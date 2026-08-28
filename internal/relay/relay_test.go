package relay

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
)

// 🔴 NO TEST IN THIS FILE REACHES THE NETWORK, AN AWS ACCOUNT OR A CLOUDFLARE
// ACCOUNT. ACM is a struct literal behind ACMAPI and Cloudflare is an
// httptest.Server. That is the whole reason both upstreams sit behind a seam:
// the safety properties this service claims have to be checkable by someone who
// does not work here.

func ptr[T any](v T) *T { return &v }

// fakeACM answers ACMAPI from fixtures. It records what it was asked so a test
// can assert on the request, not only on the answer.
type fakeACM struct {
	pages       []*acm.ListCertificatesOutput
	describe    map[string]*acm.DescribeCertificateOutput
	listErr     error
	describeErr error

	listCalls int
	described []string
	statuses  []acmtypes.CertificateStatus
	keyTypes  []acmtypes.KeyAlgorithm
	origins   []acmtypes.CertificateKeyPairOrigin
}

func (f *fakeACM) ListCertificates(_ context.Context, in *acm.ListCertificatesInput, _ ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	f.statuses = in.CertificateStatuses
	f.origins = in.CertificateKeyPairOrigins
	if in.Includes != nil {
		f.keyTypes = in.Includes.KeyTypes
	}
	page := f.pages[f.listCalls]
	f.listCalls++
	return page, nil
}

func (f *fakeACM) DescribeCertificate(_ context.Context, in *acm.DescribeCertificateInput, _ ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
	if f.describeErr != nil {
		return nil, f.describeErr
	}
	arn := deref(in.CertificateArn)
	f.described = append(f.described, arn)
	return f.describe[arn], nil
}

// oneCertificate wires a single-page listing of one certificate covering host,
// whose describe returns exactly these validation options.
func oneCertificate(host string, options ...acmtypes.DomainValidation) *fakeACM {
	const arn = "arn:aws:acm:eu-central-1:111122223333:certificate/aaaa"
	return &fakeACM{
		pages: []*acm.ListCertificatesOutput{{
			CertificateSummaryList: []acmtypes.CertificateSummary{{
				CertificateArn: ptr(arn),
				DomainName:     ptr(host),
			}},
		}},
		describe: map[string]*acm.DescribeCertificateOutput{
			arn: {Certificate: &acmtypes.CertificateDetail{DomainValidationOptions: options}},
		},
	}
}

func cnameOption(name, value string) acmtypes.DomainValidation {
	return acmtypes.DomainValidation{
		DomainName: ptr("account.example.com"),
		ResourceRecord: &acmtypes.ResourceRecord{
			Type: acmtypes.RecordTypeCname, Name: ptr(name), Value: ptr(value),
		},
	}
}

// 🔴 AN EMPTY ANSWER IS A WAIT, NOT A FAULT. RequestCertificate returns an ARN
// immediately and ACM fills the validation record in minutes later, so a
// certificate with no options is the ordinary first-minutes state. A reader that
// reported it as an error would fail every fresh registration, and an exemption
// keyed on the wrong empty field has shipped broken here twice already.
func TestEmptyValidationOptionsAreAWaitNotAnError(t *testing.T) {
	for name, api := range map[string]*fakeACM{
		"no options at all": oneCertificate("account.example.com"),
		"an option with no resource record": oneCertificate("account.example.com",
			acmtypes.DomainValidation{DomainName: ptr("account.example.com")}),
		"no certificate in the account": {pages: []*acm.ListCertificatesOutput{{}}},
	} {
		records, err := ACM{API: api}.ValidationRecords(context.Background(), []string{"account.example.com"})
		if err != nil {
			t.Fatalf("%s: want no error, got %v", name, err)
		}
		if len(records) != 0 {
			t.Fatalf("%s: want no records, got %v", name, records)
		}
	}
}

// A trailing dot is presentation, not identity: AWS returns the name and the
// target with the root dot and the provider stores them without it. Left in
// place, every already-published record reads as missing and is rewritten on
// every pass.
func TestACMTrimsTheTrailingDotOnNameAndValue(t *testing.T) {
	api := oneCertificate("account.example.com", cnameOption(
		"_a79865eb4cd1a6ab990a45779b4e0b96.Account.Example.com.",
		"_ff6c7f9a.acm-validations.aws.",
	))
	records, err := ACM{API: api}.ValidationRecords(context.Background(), []string{"account.example.com"})
	if err != nil {
		t.Fatalf("ValidationRecords: %v", err)
	}
	want := dnsplan.Record{
		Type:  "CNAME",
		Name:  "_a79865eb4cd1a6ab990a45779b4e0b96.account.example.com",
		Value: "_ff6c7f9a.acm-validations.aws",
	}
	if len(records) != 1 || records[0] != want {
		t.Fatalf("want %+v, got %+v", want, records)
	}
	if records[0].Proxied {
		// Cloudflare accepts proxied:true on an underscore name with no error
		// and then answers with addresses, so the CA never follows the record.
		t.Fatal("a relayed validation record must never be proxied")
	}
}

// 🔴 REFUSE WHAT THE UPSTREAM SHOULD NOT HAVE BEEN ABLE TO SAY. AWS declares
// CNAME the only type this field takes and declares name and value required, so
// each case below is a contract violation. Publishing one anyway puts a record
// nobody chose into a customer's zone; an empty name in particular normalizes to
// the empty string and lands as a write against the zone apex.
func TestACMRefusesRecordsAWSSaysItCannotReturn(t *testing.T) {
	for name, option := range map[string]acmtypes.DomainValidation{
		"a type that is not CNAME": {
			DomainName: ptr("account.example.com"),
			ResourceRecord: &acmtypes.ResourceRecord{
				Type:  acmtypes.RecordType("TXT"),
				Name:  ptr("_x.account.example.com"),
				Value: ptr("_ff6c7f9a.acm-validations.aws"),
			},
		},
		"an empty name": cnameOption("", "_ff6c7f9a.acm-validations.aws"),
		"a value outside the AWS validation zone": cnameOption(
			"_x.account.example.com", "attacker.example.net"),
		"a value that only contains the suffix as a label": cnameOption(
			"_x.account.example.com", "_ff6c7f9a.acm-validations.aws.example.net"),
	} {
		api := oneCertificate("account.example.com", option)
		records, err := ACM{API: api}.ValidationRecords(context.Background(), []string{"account.example.com"})
		if !errors.Is(err, ErrUnexpectedRecord) {
			t.Fatalf("%s: want ErrUnexpectedRecord, got %v", name, err)
		}
		if records != nil {
			t.Fatalf("%s: a refusal must publish nothing, got %v", name, records)
		}
	}
}

// 🔴 THE TARGET SUFFIX ALONE IS NOT ENOUGH. api-platform shipped a completeness
// gate that matched on ".acm-validations.aws" without checking whose host the
// record named, so a stale sibling registration's record satisfied it and was
// persisted forever. A certificate may legitimately carry names this pass did
// not ask about; they belong to another host's plan.
func TestACMSkipsValidationRecordsForHostsWeDidNotAskAbout(t *testing.T) {
	api := oneCertificate("account.example.com",
		cnameOption("_mine.account.example.com", "_a.acm-validations.aws"),
		cnameOption("_theirs.shop.example.net", "_b.acm-validations.aws"),
		cnameOption("_lookalike.notaccount.example.com", "_c.acm-validations.aws"),
	)
	records, err := ACM{API: api}.ValidationRecords(context.Background(), []string{"account.example.com"})
	if err != nil {
		t.Fatalf("ValidationRecords: %v", err)
	}
	if len(records) != 1 || records[0].Name != "_mine.account.example.com" {
		t.Fatalf("only the record bound to the asked-for host may survive, got %+v", records)
	}
}

// The plan's SHA-256 is computed over the record list IN ORDER, before the
// customer authorizes, and re-checked before the write. Two passes over one
// unchanged AWS answer must produce one order, or a customer sitting on the
// consent screen is told the plan changed with nothing having changed.
func TestACMOutputIsDedupedAndDeterministic(t *testing.T) {
	const arnA = "arn:aws:acm:eu-central-1:111122223333:certificate/aaaa"
	const arnB = "arn:aws:acm:eu-central-1:111122223333:certificate/bbbb"
	api := &fakeACM{
		pages: []*acm.ListCertificatesOutput{{
			CertificateSummaryList: []acmtypes.CertificateSummary{
				{CertificateArn: ptr(arnA), DomainName: ptr("api.example.com")},
				{CertificateArn: ptr(arnB), DomainName: ptr("account.example.com")},
			},
		}},
		describe: map[string]*acm.DescribeCertificateOutput{
			arnA: {Certificate: &acmtypes.CertificateDetail{DomainValidationOptions: []acmtypes.DomainValidation{
				cnameOption("_z.api.example.com", "_z.acm-validations.aws"),
				// The same record twice: two SANs can carry one ResourceRecord.
				cnameOption("_z.api.example.com", "_z.acm-validations.aws"),
			}}},
			arnB: {Certificate: &acmtypes.CertificateDetail{DomainValidationOptions: []acmtypes.DomainValidation{
				cnameOption("_a.account.example.com", "_a.acm-validations.aws"),
			}}},
		},
	}
	hosts := []string{"api.example.com", "account.example.com"}
	records, err := ACM{API: api}.ValidationRecords(context.Background(), hosts)
	if err != nil {
		t.Fatalf("ValidationRecords: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("want the duplicate collapsed to two records, got %+v", records)
	}
	if records[0].Name != "_a.account.example.com" || records[1].Name != "_z.api.example.com" {
		t.Fatalf("records must come back in a stable order, got %+v", records)
	}
}

// Both defaults are documented to HIDE rows rather than error: ACM lists only
// RSA_1024/RSA_2048 unless told otherwise, and excludes ACME key-pair origins.
// A certificate that vanishes from a successful call is the worst kind of green
// signal, so every value is named explicitly.
func TestACMListingDefeatsTheFiltersThatHideCertificates(t *testing.T) {
	api := oneCertificate("account.example.com")
	if _, err := (ACM{API: api}).ValidationRecords(context.Background(), []string{"account.example.com"}); err != nil {
		t.Fatalf("ValidationRecords: %v", err)
	}
	if len(api.keyTypes) < 4 {
		t.Fatalf("key types must be named explicitly, got %v", api.keyTypes)
	}
	var sawACME bool
	for _, origin := range api.origins {
		if origin == acmtypes.CertificateKeyPairOriginAcme {
			sawACME = true
		}
	}
	if !sawACME {
		t.Fatalf("ACME key-pair origins are excluded by default and must be asked for, got %v", api.origins)
	}
	// Only a certificate that can still produce a usable record is worth
	// describing; a FAILED or REVOKED one is a dead end.
	if len(api.statuses) != 2 {
		t.Fatalf("want pending-validation and issued only, got %v", api.statuses)
	}
}

// A certificate deleted between the list and the describe is a race, not a
// fault. Holding no certificate id is what makes this service stateless; the
// price is that AWS may change its mind mid-pass.
func TestACMTreatsACertificateDeletedMidPassAsAbsent(t *testing.T) {
	api := oneCertificate("account.example.com")
	api.describeErr = &acmtypes.ResourceNotFoundException{}
	records, err := ACM{API: api}.ValidationRecords(context.Background(), []string{"account.example.com"})
	if err != nil || len(records) != 0 {
		t.Fatalf("want no records and no error, got %v / %v", records, err)
	}
}

func TestACMPagesUntilTheTokenRunsOut(t *testing.T) {
	const arn = "arn:aws:acm:eu-central-1:111122223333:certificate/aaaa"
	api := &fakeACM{
		pages: []*acm.ListCertificatesOutput{
			{NextToken: ptr("more")},
			{CertificateSummaryList: []acmtypes.CertificateSummary{{
				CertificateArn: ptr(arn), DomainName: ptr("account.example.com"),
			}}},
		},
		describe: map[string]*acm.DescribeCertificateOutput{
			arn: {Certificate: &acmtypes.CertificateDetail{DomainValidationOptions: []acmtypes.DomainValidation{
				cnameOption("_x.account.example.com", "_x.acm-validations.aws"),
			}}},
		},
	}
	records, err := ACM{API: api}.ValidationRecords(context.Background(), []string{"account.example.com"})
	if err != nil {
		t.Fatalf("ValidationRecords: %v", err)
	}
	if api.listCalls != 2 || len(records) != 1 {
		t.Fatalf("want two pages and one record, got %d pages and %+v", api.listCalls, records)
	}
}

// A list response caps the SAN summary at a hundred names and flags the
// truncation. A truncated list cannot prove absence, so the certificate is
// described rather than skipped: one extra read against a certificate that never
// validates.
func TestACMDescribesCertificatesWhoseSANListWasTruncated(t *testing.T) {
	const arn = "arn:aws:acm:eu-central-1:111122223333:certificate/aaaa"
	api := &fakeACM{
		pages: []*acm.ListCertificatesOutput{{
			CertificateSummaryList: []acmtypes.CertificateSummary{{
				CertificateArn:                       ptr(arn),
				DomainName:                           ptr("unrelated.example.net"),
				HasAdditionalSubjectAlternativeNames: ptr(true),
			}},
		}},
		describe: map[string]*acm.DescribeCertificateOutput{
			arn: {Certificate: &acmtypes.CertificateDetail{DomainValidationOptions: []acmtypes.DomainValidation{
				cnameOption("_x.account.example.com", "_x.acm-validations.aws"),
			}}},
		},
	}
	records, err := ACM{API: api}.ValidationRecords(context.Background(), []string{"account.example.com"})
	if err != nil {
		t.Fatalf("ValidationRecords: %v", err)
	}
	if len(api.described) != 1 || len(records) != 1 {
		t.Fatalf("a truncated SAN list must still be described, got %v / %+v", api.described, records)
	}
}

func edgeFor(t *testing.T, h http.HandlerFunc) Edge {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return Edge{
		ZoneID:     "mirrorstack-saas-zone",
		Token:      StaticToken("ms-zone-token"),
		Base:       srv.URL,
		HTTPClient: srv.Client(),
	}
}

// 🔴 THE ABSENT PROOF IS THE DANGEROUS ONE, AND IT MUST NOT LOOK LIKE A FAULT.
// Cloudflare mints this proof when the custom hostname is created and withholds
// it otherwise; missing it produces a 526 while the certificate reads active.
// Reporting the wait as an error would stop the pass that eventually publishes
// it, so every shape of "not yet" below is ready=false with a nil error.
func TestServingProofAbsenceIsNotReadyAndNotAnError(t *testing.T) {
	for name, body := range map[string]string{
		"no custom hostname exists yet": `{"success":true,"result":[]}`,
		"the hostname exists but carries no ownership_verification": `
			{"success":true,"result":[{"hostname":"account.example.com"}]}`,
		// 🔴 MEASURED ON A LIVE HOST: Cloudflare keeps the object present with
		// EMPTY STRINGS once the proof is no longer required. An unguarded read
		// of it publishes a nameless record — i.e. a write against the apex of
		// the customer's zone.
		"the object is present with empty strings": `
			{"success":true,"result":[{"hostname":"account.example.com",
			  "ownership_verification":{"type":"txt","name":"","value":""}}]}`,
		"a name with no value": `
			{"success":true,"result":[{"hostname":"account.example.com",
			  "ownership_verification":{"type":"txt","name":"_cf-custom-hostname.account.example.com","value":""}}]}`,
	} {
		e := edgeFor(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, body)
		})
		record, ready, err := e.ServingProof(context.Background(), "account.example.com")
		if err != nil {
			t.Fatalf("%s: want no error, got %v", name, err)
		}
		if ready {
			t.Fatalf("%s: want ready=false, got %+v", name, record)
		}
		if record != (dnsplan.Record{}) {
			t.Fatalf("%s: a not-ready proof must carry no record, got %+v", name, record)
		}
	}
}

func TestServingProofReadsTheOwnershipVerificationTXT(t *testing.T) {
	e := edgeFor(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"success":true,"result":[{"hostname":"Account.Example.com",
		  "ssl":{"status":"pending_validation"},
		  "ownership_verification":{"type":"txt",
		    "name":"_cf-custom-hostname.account.example.com",
		    "value":"ac4a9a9d-0f4a-4e5e-9a3f-2f1c1b0d9e8a"}}]}`)
	})
	record, ready, err := e.ServingProof(context.Background(), "account.example.com")
	if err != nil || !ready {
		t.Fatalf("want a ready proof, got %+v / %v / %v", record, ready, err)
	}
	want := dnsplan.Record{
		Type:  "TXT",
		Name:  "_cf-custom-hostname.account.example.com",
		Value: "ac4a9a9d-0f4a-4e5e-9a3f-2f1c1b0d9e8a",
	}
	if record != want {
		t.Fatalf("want %+v, got %+v", want, record)
	}
}

// A TXT value is data. Trimming a trailing dot from it — which is the right
// thing to do to a CNAME target — would silently corrupt a proof that happens to
// end in one, and the failure would surface as a 526 nobody could explain.
func TestServingProofDoesNotTrimATrailingDotFromATXTValue(t *testing.T) {
	e := edgeFor(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"success":true,"result":[{"hostname":"account.example.com",
		  "ownership_verification":{"type":"txt",
		    "name":"_cf-custom-hostname.account.example.com","value":"proof-value."}}]}`)
	})
	record, ready, err := e.ServingProof(context.Background(), "account.example.com")
	if err != nil || !ready {
		t.Fatalf("want a ready proof, got %v / %v", ready, err)
	}
	if record.Value != "proof-value." {
		t.Fatalf("a TXT value must survive verbatim, got %q", record.Value)
	}
}

// The hostname query parameter is a FILTER, not a lookup. Taking result[0] would
// bind this host's plan to a neighbouring hostname's proof.
func TestServingProofMatchesTheHostExactlyRatherThanTakingTheFirstResult(t *testing.T) {
	e := edgeFor(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"success":true,"result":[
		  {"hostname":"shop.account.example.com",
		   "ownership_verification":{"type":"txt","name":"_cf-custom-hostname.shop.account.example.com","value":"wrong"}},
		  {"hostname":"account.example.com",
		   "ownership_verification":{"type":"txt","name":"_cf-custom-hostname.account.example.com","value":"right"}}]}`)
	})
	record, ready, err := e.ServingProof(context.Background(), "account.example.com")
	if err != nil || !ready {
		t.Fatalf("want a ready proof, got %v / %v", ready, err)
	}
	if record.Value != "right" {
		t.Fatalf("the exact host must win, got %+v", record)
	}
}

// The proof has to name the host it was asked for. Cloudflare has no reason to
// return anything else, which is exactly why the unchecked assumption would
// survive review and then publish another registration's record.
func TestServingProofRefusesARecordThatDoesNotNameTheHost(t *testing.T) {
	for name, proof := range map[string]string{
		"a name outside the host": `{"type":"txt","name":"_cf-custom-hostname.example.net","value":"v"}`,
		"the host itself":         `{"type":"txt","name":"account.example.com","value":"v"}`,
		"a non-txt type":          `{"type":"http","name":"_cf-custom-hostname.account.example.com","value":"v"}`,
	} {
		e := edgeFor(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"success":true,"result":[{"hostname":"account.example.com",
			  "ownership_verification":`+proof+`}]}`)
		})
		record, ready, err := e.ServingProof(context.Background(), "account.example.com")
		if !errors.Is(err, ErrUnexpectedRecord) {
			t.Fatalf("%s: want ErrUnexpectedRecord, got %v", name, err)
		}
		if ready || record != (dnsplan.Record{}) {
			t.Fatalf("%s: a refusal must publish nothing, got %+v", name, record)
		}
	}
}

// 🔴 THIS READ USES MIRRORSTACK'S OWN ZONE CREDENTIAL, so the test that matters
// is that the credential rides the Authorization header and appears nowhere a
// log or a proxy access line would keep it.
func TestServingProofSendsTheZoneCredentialAsABearerAndNowhereElse(t *testing.T) {
	var auth, target string
	e := edgeFor(t, func(w http.ResponseWriter, r *http.Request) {
		auth, target = r.Header.Get("Authorization"), r.URL.String()
		_, _ = io.WriteString(w, `{"success":true,"result":[]}`)
	})
	if _, _, err := e.ServingProof(context.Background(), "account.example.com"); err != nil {
		t.Fatalf("ServingProof: %v", err)
	}
	if auth != "Bearer ms-zone-token" {
		t.Fatalf("the zone credential must ride the Authorization header, got %q", auth)
	}
	if strings.Contains(target, "ms-zone-token") {
		t.Fatalf("the credential must never appear in a URL, got %q", target)
	}
	if !strings.Contains(target, "/zones/mirrorstack-saas-zone/custom_hostnames") {
		t.Fatalf("the read must be against MirrorStack's own zone, got %q", target)
	}
}

// A missing credential is a configuration fault reported as a fault. Reported as
// not-ready it would be indistinguishable from Cloudflare being slow, forever.
func TestServingProofRefusesToRunWithoutAZoneAndACredential(t *testing.T) {
	for name, e := range map[string]Edge{
		"no zone":          {Token: StaticToken("t")},
		"no token source":  {ZoneID: "z"},
		"an empty token":   {ZoneID: "z", Token: StaticToken("  ")},
		"a failing source": {ZoneID: "z", Token: func(context.Context) (string, error) { return "", errors.New("secret unavailable") }},
	} {
		if _, ready, err := e.ServingProof(context.Background(), "account.example.com"); err == nil || ready {
			t.Fatalf("%s: want a refusal, got ready=%v err=%v", name, ready, err)
		}
	}
}

func TestServingProofRejectsAHostThatIsNotADNSName(t *testing.T) {
	e := Edge{ZoneID: "z", Token: StaticToken("t")}
	for _, host := range []string{"", "   ", strings.Repeat("a", dnsplan.MaxDNSName+1)} {
		if _, _, err := e.ServingProof(context.Background(), host); err == nil {
			t.Fatalf("want a refusal for %q", host)
		}
	}
}

func TestServingProofSurfacesACloudflareRefusal(t *testing.T) {
	e := edgeFor(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":9109,"message":"Unauthorized to access requested resource"}]}`)
	})
	_, ready, err := e.ServingProof(context.Background(), "account.example.com")
	if err == nil || ready {
		t.Fatalf("a failed read of our own zone is a fault, got ready=%v err=%v", ready, err)
	}
}

// 🔴 A NIL ADAPTER IS "NOT YET", NEVER AN ERROR. Lane 2 and lane 3 request no
// certificate at all and a deployment may not be wired for either upstream; a
// lane that was never going to have record 5 must not become a permanently
// failing one.
func TestNilAdaptersReportNotYetRatherThanFailing(t *testing.T) {
	ctx := context.Background()
	records, err := ValidationRecords(ctx, nil, []string{"account.example.com"})
	if err != nil || records != nil {
		t.Fatalf("nil CertificateAuthority: want no records and no error, got %v / %v", records, err)
	}
	record, ready, err := ServingProof(ctx, nil, "account.example.com")
	if err != nil || ready || record != (dnsplan.Record{}) {
		t.Fatalf("nil EdgeHostnames: want not-ready and no error, got %+v / %v / %v", record, ready, err)
	}
	proofs, err := ServingProofs(ctx, nil, []string{"account.example.com"})
	if err != nil || proofs != nil {
		t.Fatalf("nil EdgeHostnames: want no proofs and no error, got %v / %v", proofs, err)
	}
	// A configured-but-clientless ACM is the same answer: not-yet, not a fault.
	if records, err := (ACM{}).ValidationRecords(ctx, []string{"account.example.com"}); err != nil || records != nil {
		t.Fatalf("zero ACM: want no records and no error, got %v / %v", records, err)
	}
}

// stubEdge answers ServingProof from a fixture keyed by host.
type stubEdge struct {
	ready map[string]string
	err   error
}

func (s stubEdge) ServingProof(_ context.Context, host string) (dnsplan.Record, bool, error) {
	if s.err != nil {
		return dnsplan.Record{}, false, s.err
	}
	value, ok := s.ready[host]
	if !ok {
		return dnsplan.Record{}, false, nil
	}
	return relayedRecord("TXT", ownershipRecordPrefix+host, value), true, nil
}

// A partial answer is the normal answer: a lane-1 registration creates four
// custom hostnames and Cloudflare mints their proofs as each is created. Host
// order is preserved because the plan digest is order-sensitive.
func TestServingProofsCollectWhatIsReadyInHostOrder(t *testing.T) {
	edge := stubEdge{ready: map[string]string{
		"account.example.com": "a", "apps.example.com": "c",
	}}
	hosts := []string{"account.example.com", "api.example.com", "apps.example.com"}
	proofs, err := ServingProofs(context.Background(), edge, hosts)
	if err != nil {
		t.Fatalf("ServingProofs: %v", err)
	}
	if len(proofs) != 2 ||
		proofs[0].Name != "_cf-custom-hostname.account.example.com" ||
		proofs[1].Name != "_cf-custom-hostname.apps.example.com" {
		t.Fatalf("want the ready proofs in host order, got %+v", proofs)
	}
}

func TestServingProofsSurfaceAFailedRead(t *testing.T) {
	edge := stubEdge{err: errors.New("cloudflare unavailable")}
	if _, err := ServingProofs(context.Background(), edge, []string{"account.example.com"}); err == nil {
		t.Fatal("a failed read must not be reported as an empty set of proofs")
	}
}

// Both relayed records land at an underscore name, and Cloudflare accepts
// proxied:true on those with no error at all — then answers with addresses
// instead of following the record, so issuance or a renewal months later fails
// with every dashboard still green.
func TestRelayedRecordsAreNeverProxied(t *testing.T) {
	for _, record := range []dnsplan.Record{
		relayedRecord("CNAME", "_x.account.example.com.", "_y.acm-validations.aws."),
		relayedRecord("TXT", "_cf-custom-hostname.account.example.com", "proof"),
	} {
		if record.Proxied {
			t.Fatalf("%+v must not be proxied", record)
		}
	}
}

// Whatever this package returns still has to survive the write path unchanged:
// dnsplan refuses an unnormalized record, and anchor containment is what bounds
// a delegated credential to the subtree the customer proved.
func TestRelayedRecordsSurviveTheNormalizerAndTheAnchor(t *testing.T) {
	records := []dnsplan.Record{
		relayedRecord("CNAME", "_x.Account.Example.com.", "_y.acm-validations.aws."),
		relayedRecord("TXT", "_cf-custom-hostname.account.example.com", "proof"),
	}
	normalized, _, err := dnsplan.NormalizeRecords(records)
	if err != nil {
		t.Fatalf("NormalizeRecords: %v", err)
	}
	for i, record := range normalized {
		if record != records[i] {
			t.Fatalf("a relayed record must already be normalized: %+v became %+v", records[i], record)
		}
		if !dnsplan.Contains("example.com", record.Name) {
			t.Fatalf("%q must sit under the anchor", record.Name)
		}
	}
}
