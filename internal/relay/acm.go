package relay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
)

// DefaultMaxCertificates bounds how many certificates one pass will describe.
// This reader holds no certificate id (docs/DESIGN.md §7), so it finds them by
// listing the account and matching on domain client-side. The cap keeps a pass
// over an account with thousands of certificates bounded; exceeding it is logged,
// never silent.
const DefaultMaxCertificates = 50

// maxListPages bounds the account-wide listing itself. Termination already comes
// from ACM's NextToken; this is the belt to that braces, so a paging bug upstream
// cannot turn one pass of the loop into an unbounded one.
const maxListPages = 50

// ACMAPI is the slice of AWS Certificate Manager this service reads. The
// signatures copy the SDK's exactly, variadic option functions included, so
// *acm.Client satisfies it with no adapter and a test satisfies it with a struct
// literal: NO TEST IN THIS REPOSITORY MAY NEED AN AWS ACCOUNT. There is no
// RequestCertificate and no DeleteCertificate — this service reads, and
// api-platform owns the certificate's lifecycle.
type ACMAPI interface {
	ListCertificates(ctx context.Context, params *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error)
	DescribeCertificate(ctx context.Context, params *acm.DescribeCertificateInput, optFns ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
}

// ACM reads record 5 — the AWS DNS validation CNAME — out of ACM. A value type so
// its zero value is inert and no caller is tempted to park a typed nil pointer in
// the CertificateAuthority interface; a deployment with no certificate authority
// passes a nil interface instead, which ValidationRecords in relay.go treats as a
// wait rather than an error.
type ACM struct {
	// API is the ACM client. Nil means the reader is not configured, which is
	// reported as "no records yet", exactly like a nil adapter.
	API ACMAPI

	// MaxCertificates overrides DefaultMaxCertificates.
	MaxCertificates int
}

var _ CertificateAuthority = ACM{}

// NewACM builds a reader from the ambient AWS configuration. region names where
// the certificates live: ACM is regional and a certificate can only be attached by
// a service in its own region, so the caller has to say. An empty region falls back
// to whatever the process's AWS configuration resolves, which is the right answer
// inside Lambda and the wrong one almost everywhere else.
func NewACM(ctx context.Context, region string) (ACM, error) {
	var opts []func(*config.LoadOptions) error
	if region = strings.TrimSpace(region); region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return ACM{}, fmt.Errorf("relay: load aws config: %w", err)
	}
	return ACM{API: acm.NewFromConfig(cfg)}, nil
}

// ValidationRecords returns the DNS validation CNAME for every certificate that
// covers one of these hosts.
//
// 🔴 AN EMPTY ANSWER WITH A NIL ERROR IS THE NORMAL EARLY STATE — a certificate is
// routinely present and recordless for the first minutes of its life; see
// CertificateAuthority in relay.go. The only thing that produces an error here is a
// failed AWS call; a record AWS should not have been able to hand back at all is
// refused a level up.
//
// Which hosts get a certificate is a derivation decision made elsewhere: lane 1
// covers account, api and apps but NOT cdn, which the CDN Worker terminates before
// it ever reaches API Gateway, and lanes 2 and 3 have no ACM record of any kind.
//
// What comes back here is a FINDING, not a plan: publishability, duplicates and
// order are settled by relay.ValidationRecords above the interface — two SANs can
// carry one ResourceRecord, and the plan digest is order-sensitive.
func (a ACM) ValidationRecords(ctx context.Context, hosts []string) ([]dnsplan.Record, error) {
	wanted := normalizeHosts(hosts)
	if a.API == nil || len(wanted) == 0 {
		return nil, nil
	}
	arns, err := a.candidates(ctx, wanted)
	if err != nil {
		return nil, err
	}
	out := make([]dnsplan.Record, 0, len(arns))
	for _, arn := range arns {
		records, err := a.describe(ctx, arn, wanted)
		if err != nil {
			return nil, err
		}
		out = append(out, records...)
	}
	return out, nil
}

// candidates lists the account and returns the ARNs of certificates that might
// cover one of these hosts. ACM offers no server-side domain filter —
// types.Filters selects on key type, key usage and who manages the certificate,
// and on nothing else — so selecting by hostname is unavoidably client-side over
// the summaries.
func (a ACM) candidates(ctx context.Context, hosts []string) ([]*string, error) {
	input := &acm.ListCertificatesInput{
		// Only these two statuses can still produce a record worth publishing. A
		// PENDING_VALIDATION certificate is waiting on exactly the record this
		// function fetches, and an ISSUED one still needs its record to STAY in the
		// zone — ACM revalidates through the same CNAME at renewal, which is why
		// docs/RECORDS.md marks it retained. FAILED, REVOKED, EXPIRED and
		// VALIDATION_TIMED_OUT are dead ends; api-platform mints a replacement.
		CertificateStatuses: []acmtypes.CertificateStatus{
			acmtypes.CertificateStatusPendingValidation,
			acmtypes.CertificateStatusIssued,
		},
		// 🔴 BOTH OF THESE FILTERS EXIST TO DEFEAT A DEFAULT THAT HIDES ROWS. ACM's
		// documented default returns only RSA_1024 and RSA_2048, and excludes
		// certificates whose key pair origin is ACME. Neither omission is an error —
		// the certificate simply is not in the list — so a future change of key
		// algorithm would make a certificate vanish from this reader with every call
		// succeeding.
		Includes: &acmtypes.Filters{KeyTypes: []acmtypes.KeyAlgorithm{
			acmtypes.KeyAlgorithmRsa1024,
			acmtypes.KeyAlgorithmRsa2048,
			acmtypes.KeyAlgorithmRsa3072,
			acmtypes.KeyAlgorithmRsa4096,
			acmtypes.KeyAlgorithmEcPrime256v1,
			acmtypes.KeyAlgorithmEcSecp384r1,
			acmtypes.KeyAlgorithmEcSecp521r1,
		}},
		CertificateKeyPairOrigins: []acmtypes.CertificateKeyPairOrigin{
			acmtypes.CertificateKeyPairOriginAwsManaged,
			acmtypes.CertificateKeyPairOriginCustomerProvided,
			acmtypes.CertificateKeyPairOriginAcme,
		},
	}
	limit := a.MaxCertificates
	if limit <= 0 {
		limit = DefaultMaxCertificates
	}
	var arns []*string
	for page := 0; page < maxListPages; page++ {
		out, err := a.API.ListCertificates(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("relay: list ACM certificates: %w", err)
		}
		if out == nil {
			return nil, fmt.Errorf("relay: list ACM certificates returned no response")
		}
		for _, summary := range out.CertificateSummaryList {
			if summary.CertificateArn == nil || !coversAnyHost(summary, hosts) {
				continue
			}
			if len(arns) >= limit {
				slog.Warn("relay: more ACM certificates match these hosts than one pass will read",
					"limit", limit, "hosts", hosts)
				return arns, nil
			}
			arns = append(arns, summary.CertificateArn)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return arns, nil
		}
		input.NextToken = out.NextToken
	}
	slog.Warn("relay: stopped paging ACM certificates at the page bound", "pages", maxListPages)
	return arns, nil
}

// coversAnyHost reports whether a listed certificate might cover one of these
// hosts. It errs toward describing one certificate too many rather than one too
// few: a list response caps SubjectAlternativeNameSummaries at the first hundred
// names and flags the truncation, and a truncated list cannot prove absence.
// Skipping one that does cover the host costs a certificate that never validates.
func coversAnyHost(summary acmtypes.CertificateSummary, hosts []string) bool {
	names := make([]string, 0, len(summary.SubjectAlternativeNameSummaries)+1)
	if summary.DomainName != nil {
		names = append(names, *summary.DomainName)
	}
	names = append(names, summary.SubjectAlternativeNameSummaries...)
	for _, name := range names {
		name = dnsplan.NormalizeName(name)
		for _, host := range hosts {
			if name == host {
				return true
			}
		}
	}
	return summary.HasAdditionalSubjectAlternativeNames != nil && *summary.HasAdditionalSubjectAlternativeNames
}

// describe reads one certificate's validation records.
func (a ACM) describe(ctx context.Context, arn *string, hosts []string) ([]dnsplan.Record, error) {
	out, err := a.API.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: arn})
	if err != nil {
		// A certificate deleted between the list and this read is a race, not a
		// fault. This reader holds no certificate id because the truth lives in AWS;
		// the cost of that is that AWS may change its mind mid-pass.
		var missing *acmtypes.ResourceNotFoundException
		if errors.As(err, &missing) {
			return nil, nil
		}
		return nil, fmt.Errorf("relay: describe ACM certificate: %w", err)
	}
	if out == nil || out.Certificate == nil {
		return nil, nil
	}
	// DomainValidationOptions exists only for AMAZON_ISSUED certificates and is
	// empty until ACM has filled it in. Both mean "come back next pass".
	records := make([]dnsplan.Record, 0, len(out.Certificate.DomainValidationOptions))
	for _, option := range out.Certificate.DomainValidationOptions {
		// EMPTY IS NORMAL on the first read, and on every read of a certificate
		// validated by email or by HTTP redirect. Nothing to report.
		if option.ResourceRecord == nil {
			continue
		}
		// The TYPE is passed through rather than asserted to be CNAME. AWS declares
		// CNAME the only type this field takes, so anything else is a contract
		// violation that relay.ValidationRecords refuses by name; hard-coding
		// "CNAME" here would instead RELABEL whatever came back.
		record := relayedRecord(string(option.ResourceRecord.Type),
			deref(option.ResourceRecord.Name), deref(option.ResourceRecord.Value))
		// The one drop this reader may make: a certificate legitimately carries names
		// this pass did not ask about, and their records belong to another host's
		// plan. Everything else, a record with no name at all included, is handed up
		// to be refused loudly. See forAnotherHost.
		if forAnotherHost(hosts, record) {
			continue
		}
		records = append(records, record)
	}
	return records, nil
}

// deref reads an SDK string pointer without pulling the aws helper package in —
// cheaper than moving the core AWS module into this repository's direct
// dependencies for aws.ToString.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
