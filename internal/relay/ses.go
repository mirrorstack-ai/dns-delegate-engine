package relay

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sesv2types "github.com/aws/aws-sdk-go-v2/service/sesv2/types"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
)

// SESAPI is the slice of AWS SES this service reads. The signature copies the
// SDK's exactly, variadic option functions included, so *sesv2.Client satisfies it
// with no adapter and a test satisfies it with a struct literal: NO TEST IN THIS
// REPOSITORY MAY NEED AN AWS ACCOUNT.
//
// 🔴 ONE METHOD, AND IT IS A READ. There is no CreateEmailIdentity and no
// PutEmailIdentityDkimAttributes, and adding one would be a design change rather
// than a convenience: minting an identity starts SES's 72-hour verification clock
// and api-platform owns that lifecycle. The IAM grant this service asks for is
// `sesv2:GetEmailIdentity` and nothing else, so the interface and the policy say
// the same thing.
type SESAPI interface {
	GetEmailIdentity(ctx context.Context, params *sesv2.GetEmailIdentityInput, optFns ...func(*sesv2.Options)) (*sesv2.GetEmailIdentityOutput, error)
}

// SES reads records 8-10 — the DKIM selectors — out of SES.
//
// A value type so its zero value is inert and no caller is tempted to park a typed
// nil pointer in the MailIdentity interface; a deployment with no mail identity
// reader passes a nil interface instead, which DkimRecords in relay.go treats as a
// wait rather than an error.
type SES struct {
	// API is the SES client. Nil means the reader is not configured, which is
	// reported as "no records yet", exactly like a nil adapter.
	API SESAPI
}

var _ MailIdentity = SES{}

// NewSES builds a reader from the ambient AWS configuration. region names where
// the sending identity lives: SES is regional and an identity verified in one
// region does not exist in another, so the caller has to say. An empty region
// falls back to whatever the process's AWS configuration resolves, which is the
// right answer inside Lambda and the wrong one almost everywhere else.
func NewSES(ctx context.Context, region string) (SES, error) {
	var opts []func(*config.LoadOptions) error
	if region = strings.TrimSpace(region); region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return SES{}, fmt.Errorf("relay: load aws config: %w", err)
	}
	return SES{API: sesv2.NewFromConfig(cfg)}, nil
}

// DkimRecords returns one CNAME per DKIM token SES holds for the anchor.
//
// 🔴 THREE EMPTY ANSWERS, ONE FAULT, AND TELLING THEM APART IS THE POINT.
//
//	NotFoundException   api-platform has never asked for an identity on this
//	                    anchor. Ordinary: a customer domain onboarded before
//	                    branded mail, or one whose registration has not reached
//	                    the pass that requests it.
//	no tokens           the identity exists and SES has not issued the selectors
//	                    yet. Seconds to minutes, exactly like ACM's validation
//	                    record.
//	tokens, not signing the customer has not published them yet. STILL RETURNED:
//	                    these records are the instruction, and withholding them
//	                    until they are already in place is a plan that can never
//	                    become true.
//	AccessDenied        a FAULT. Returned as an error naming the grant, never as
//	                    an empty answer.
//
// The first three are waits — no records, no error. The fourth is why this method
// does not simply swallow every error: relayInto downgrades a relay error to a
// WARNING and publishes what it can, so an ungranted read that returned "nothing
// here" would be indistinguishable from a customer who has not onboarded, on every
// pass, forever. That is the failure this whole change exists to fix, and it would
// have been reintroduced one level down.
func (s SES) DkimRecords(ctx context.Context, anchor string) ([]dnsplan.Record, error) {
	if s.API == nil {
		return nil, nil
	}
	anchor = dnsplan.NormalizeName(anchor)
	if anchor == "" {
		return nil, nil
	}
	out, err := s.API.GetEmailIdentity(ctx, &sesv2.GetEmailIdentityInput{EmailIdentity: &anchor})
	if err != nil {
		var notFound *sesv2types.NotFoundException
		if errors.As(err, &notFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("relay: get email identity %q (needs ses:GetEmailIdentity): %w", anchor, err)
	}
	if out == nil || out.DkimAttributes == nil {
		return nil, nil
	}
	attrs := out.DkimAttributes
	// 🔴 BYODKIM IS NOT OURS TO PUBLISH. With EXTERNAL origin the customer brought
	// their own key: what lives at `<selector>._domainkey.<anchor>` is a TXT
	// holding their public key, not a delegation to Amazon, and SES still reports
	// Tokens. Publishing a CNAME over that name would replace a working key with a
	// pointer to one AWS does not hold, and this service's never-delete rule would
	// not save it — a CNAME and a TXT cannot coexist at one owner.
	//
	// Gated on EXTERNAL rather than on `== AWS_SES`, deliberately. The origin enum
	// has a dozen regional Easy DKIM values (AWS_SES_EU_WEST_3, AWS_SES_AP_SOUTH_1,
	// …), all of which ARE Easy DKIM; an equality test against the bare AWS_SES
	// would have silently skipped every identity outside one region.
	if attrs.SigningAttributesOrigin == sesv2types.DkimSigningAttributesOriginExternal {
		return nil, nil
	}
	tokens := attrs.Tokens
	if len(tokens) == 0 {
		return nil, nil
	}
	// 🔴 THE ZONE COMES FROM SES, NOT FROM A LITERAL. SES returns the hosted zone
	// its keys are published in, and it is not the same string in every region.
	// Hardcoding `dkim.amazonses.com` happens to be right where we run today —
	// measured live — and is wrong by construction: an identity in a region that
	// answers differently would get three records pointing at a zone holding no
	// key, which resolves, looks correct, and signs nothing. The literal stays as
	// the fallback for a response that omits the field.
	zone := DkimTargetSuffix
	if hosted := strings.TrimSpace(aws.ToString(attrs.SigningHostedZone)); hosted != "" {
		zone = "." + strings.TrimPrefix(hosted, ".")
	}
	records := make([]dnsplan.Record, 0, len(tokens))
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		records = append(records, dnsplan.Record{
			Type: "CNAME",
			Name: token + DkimOwnerInfix + anchor,
			// 🔴 DNS-ONLY, ALWAYS. A proxied DKIM CNAME is flattened at
			// Cloudflare's edge, so the resolver that checks the signature finds
			// an address instead of the delegation and every signed message fails
			// — while the record looks present and correct in the dashboard.
			Value:   token + zone,
			Proxied: false,
		})
	}
	return records, nil
}
