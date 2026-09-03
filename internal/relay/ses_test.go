package relay

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sesv2types "github.com/aws/aws-sdk-go-v2/service/sesv2/types"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
)

// 🔴 NO TEST IN THIS FILE REACHES AN AWS ACCOUNT. SES is a struct literal behind
// SESAPI, for the reason ACM is one in relay_test.go: the safety properties this
// service claims about what it reads have to be checkable by someone outside this
// company.

// fakeSES answers SESAPI from a fixture and records the identity it was asked for.
type fakeSES struct {
	out   *sesv2.GetEmailIdentityOutput
	err   error
	asked []string
}

func (f *fakeSES) GetEmailIdentity(_ context.Context, in *sesv2.GetEmailIdentityInput, _ ...func(*sesv2.Options)) (*sesv2.GetEmailIdentityOutput, error) {
	if in != nil && in.EmailIdentity != nil {
		f.asked = append(f.asked, *in.EmailIdentity)
	}
	return f.out, f.err
}

func identityWithTokens(tokens ...string) *sesv2.GetEmailIdentityOutput {
	return &sesv2.GetEmailIdentityOutput{
		DkimAttributes: &sesv2types.DkimAttributes{Tokens: tokens},
	}
}

// 🔴 THE POSITIVE ASSERTION, and it is the one that matters. "No error" would
// pass against a relay that returned nothing at all, which is precisely the bug
// this whole change exists to fix; so this asserts the three records EXIST, are
// keyed on the anchor, and point at their own selector's key.
func TestSESReturnsOneRecordPerTokenKeyedOnTheAnchor(t *testing.T) {
	api := &fakeSES{out: identityWithTokens("aaa", "bbb", "ccc")}
	got, err := SES{API: api}.DkimRecords(context.Background(), "emat.tw")
	if err != nil {
		t.Fatalf("DkimRecords: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 records, got %d: %+v", len(got), got)
	}
	for i, token := range []string{"aaa", "bbb", "ccc"} {
		want := dnsplan.Record{
			Type:  "CNAME",
			Name:  token + "._domainkey.emat.tw",
			Value: token + ".dkim.amazonses.com",
		}
		if got[i] != want {
			t.Errorf("record %d = %+v, want %+v", i, got[i], want)
		}
		// A proxied DKIM CNAME is flattened at the edge and every signature fails
		// while the dashboard looks correct, so grey is asserted, not assumed.
		if got[i].Proxied {
			t.Errorf("record %d is proxied; DKIM must be DNS-only", i)
		}
	}
	if len(api.asked) != 1 || api.asked[0] != "emat.tw" {
		t.Errorf("asked SES for %v, want exactly [emat.tw]", api.asked)
	}
}

// 🔴 THE TEST THE HOST ASKED FOR: the items appear ONLY once SES has answered.
// Each of these is a legitimate empty answer and none may become an error, or a
// customer who has not onboarded would be reported as a fault forever.
func TestSESWaitsRatherThanFailingWhenThereIsNothingToPublishYet(t *testing.T) {
	notFound := &sesv2types.NotFoundException{}
	for _, tc := range []struct {
		name string
		api  *fakeSES
		why  string
	}{
		{"no identity at all", &fakeSES{err: notFound},
			"api-platform has never asked for an identity on this anchor — emat.tw in production today"},
		{"identity, no tokens yet", &fakeSES{out: identityWithTokens()},
			"SES has not issued the selectors yet; seconds to minutes, exactly like ACM"},
		{"no DKIM attributes", &fakeSES{out: &sesv2.GetEmailIdentityOutput{}},
			"an identity SES reports without a DKIM block"},
		{"reader not configured", &fakeSES{}, "nil API is a deployment without branded mail"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := SES{API: tc.api}
			if tc.name == "reader not configured" {
				s = SES{}
			}
			got, err := s.DkimRecords(context.Background(), "emat.tw")
			if err != nil {
				t.Fatalf("%s must be a WAIT, not an error (%s): %v", tc.name, tc.why, err)
			}
			if len(got) != 0 {
				t.Fatalf("%s must publish nothing, got %+v", tc.name, got)
			}
		})
	}
}

// 🔴 THE OTHER TEST THE HOST ASKED FOR: a denied read is a FAULT and it NAMES the
// grant. relayInto downgrades a relay error to a warning and publishes what it
// can, so if this returned an empty answer instead, an ungranted engine would be
// indistinguishable from a customer with no identity — on every pass, forever.
func TestSESDeniedReadIsAnErrorThatNamesTheMissingGrant(t *testing.T) {
	// 🔴 THE UPSTREAM MESSAGE MUST NOT CONTAIN THE ACTION, or this test is
	// vacuous: it would pass on the fake's own text with the wrapper deleted. It
	// also must not contain the identity, for the same reason. So the fixture is
	// deliberately mute about both, and every assertion below can only be
	// satisfied by something THIS package added.
	denied := errors.New("AccessDeniedException: User is not authorized to perform that operation")
	_, err := SES{API: &fakeSES{err: denied}}.DkimRecords(context.Background(), "emat.tw")
	if err == nil {
		t.Fatal("a denied read must be an error, not an empty answer")
	}
	// 🔴 `ses:`, NOT `sesv2:`. v1 and v2 share one IAM service prefix, so a policy
	// written `sesv2:GetEmailIdentity` grants nothing while looking correct —
	// measured: it evaluates ses:GetEmailIdentity as an implicit deny. If this log
	// line names an action that cannot be granted, it sends the next operator to
	// write exactly that policy.
	if !strings.Contains(err.Error(), "ses:GetEmailIdentity") {
		t.Errorf("the error must name the grantable action so the log says what to fix; got %q", err)
	}
	if strings.Contains(err.Error(), "sesv2:") {
		t.Errorf("the error names sesv2:, which is not an IAM action prefix; got %q", err)
	}
	if !strings.Contains(err.Error(), "emat.tw") {
		t.Errorf("the error must name the identity it was reading; got %q", err)
	}
	if !errors.Is(err, denied) {
		t.Errorf("the upstream error must stay wrapped; got %q", err)
	}
}

// A NotFoundException must not be reachable through a wrapped error either: SES
// clients wrap, and errors.As is what makes "no identity" survive that.
func TestSESTreatsAWrappedNotFoundAsAWait(t *testing.T) {
	wrapped := errWrap{inner: &sesv2types.NotFoundException{}}
	got, err := SES{API: &fakeSES{err: wrapped}}.DkimRecords(context.Background(), "emat.tw")
	if err != nil {
		t.Fatalf("a wrapped NotFound must still be a wait: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want no records, got %+v", got)
	}
}

type errWrap struct{ inner error }

func (e errWrap) Error() string { return "wrapped: " + e.inner.Error() }
func (e errWrap) Unwrap() error { return e.inner }

// fakeMail answers MailIdentity directly, so the BOUNDS above the interface can be
// tested against answers no real SES would give. That is the point of testing them
// here rather than in the adapter: an adapter cannot opt out of a rule it never
// sees, and the next upstream to be wired here will not have written these checks.
type fakeMail struct {
	records []dnsplan.Record
	err     error
}

func (f fakeMail) DkimRecords(context.Context, string) ([]dnsplan.Record, error) {
	return f.records, f.err
}

func dkim(token, anchor string) dnsplan.Record {
	return dnsplan.Record{
		Type:  "CNAME",
		Name:  token + "._domainkey." + anchor,
		Value: token + ".dkim.amazonses.com",
	}
}

func TestDkimRecordsRefusesWhatItWillNotPublish(t *testing.T) {
	const anchor = "emat.tw"
	for _, tc := range []struct {
		name   string
		record dnsplan.Record
		why    string
	}{
		{
			"a TXT instead of a CNAME",
			dnsplan.Record{Type: "TXT", Name: "aaa._domainkey." + anchor, Value: "aaa.dkim.amazonses.com"},
			"BYODKIM publishes a key as TXT; this service only relays Easy DKIM's delegation",
		},
		{
			"a name outside the anchor",
			dnsplan.Record{Type: "CNAME", Name: "aaa._domainkey.attacker.example", Value: "aaa.dkim.amazonses.com"},
			"containment is the only thing standing between a relayed name and someone else's zone",
		},
		{
			"the bare _domainkey label with no selector",
			dnsplan.Record{Type: "CNAME", Name: "_domainkey." + anchor, Value: ".dkim.amazonses.com"},
			"a selector-less name is not a record SES issues and has no key behind it",
		},
		{
			"a multi-label selector",
			dnsplan.Record{Type: "CNAME", Name: "a.b._domainkey." + anchor, Value: "a.b.dkim.amazonses.com"},
			"a token is one label; anything else is a different record wearing the shape",
		},
		{
			"a target in another zone",
			dnsplan.Record{Type: "CNAME", Name: "aaa._domainkey." + anchor, Value: "aaa.dkim.evil.example"},
			"the value is the half containment cannot bound, so the zone is asserted",
		},
		{
			// 🔴 THE ONE THAT LOOKS FINE. Contained name, right zone, right shape —
			// and it points a working selector at another identity's key, so mail
			// fails DKIM forever with nothing anywhere looking wrong.
			"halves that disagree",
			dnsplan.Record{Type: "CNAME", Name: "aaa._domainkey." + anchor, Value: "bbb.dkim.amazonses.com"},
			"SES publishes selector T's key at T.dkim.amazonses.com; a mismatch signs with nothing",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DkimRecords(context.Background(), fakeMail{records: []dnsplan.Record{tc.record}}, anchor)
			if !errors.Is(err, ErrUnexpectedRecord) {
				t.Fatalf("want ErrUnexpectedRecord (%s), got %v", tc.why, err)
			}
		})
	}
}

// The control for the table above: the shape it is bounding must PASS, or every
// case there would be vacuous.
func TestDkimRecordsAcceptsTheRealShape(t *testing.T) {
	got, err := DkimRecords(context.Background(), fakeMail{records: []dnsplan.Record{
		dkim("ccc", "emat.tw"), dkim("aaa", "emat.tw"), dkim("aaa", "emat.tw"),
	}}, "emat.tw")
	if err != nil {
		t.Fatalf("DkimRecords: %v", err)
	}
	// Deduped, and SORTED — the plan digest is taken before the customer
	// authorizes and re-checked before the write, so an unstable order would tell
	// someone on the consent screen the plan changed at random.
	if len(got) != 2 || got[0].Name != "aaa._domainkey.emat.tw" || got[1].Name != "ccc._domainkey.emat.tw" {
		t.Fatalf("want aaa then ccc, deduped; got %+v", got)
	}
}

// A nil relay and an empty anchor are deployments, not faults — same contract as
// a nil CertificateAuthority.
func TestDkimRecordsWaitsWithoutARelayOrAnAnchor(t *testing.T) {
	if got, err := DkimRecords(context.Background(), nil, "emat.tw"); err != nil || got != nil {
		t.Fatalf("nil relay must wait; got %+v %v", got, err)
	}
	if got, err := DkimRecords(context.Background(), fakeMail{records: []dnsplan.Record{dkim("a", "emat.tw")}}, "  "); err != nil || got != nil {
		t.Fatalf("empty anchor must wait; got %+v %v", got, err)
	}
}

// 🔴 THE HOSTED ZONE IS SES'S, NOT A LITERAL. An identity whose keys live in a
// regionally-named zone must produce records pointing THERE. Hardcoding the zone
// is right where we run today and wrong by construction, and the failure is
// silent: three records resolving into a zone holding no key.
func TestSESUsesTheHostedZoneSESReports(t *testing.T) {
	out := identityWithTokens("aaa")
	out.DkimAttributes.SigningHostedZone = ptrTo("dkim.eu-west-3.amazonses.com")
	got, err := SES{API: &fakeSES{out: out}}.DkimRecords(context.Background(), "emat.tw")
	if err != nil {
		t.Fatalf("DkimRecords: %v", err)
	}
	if len(got) != 1 || got[0].Value != "aaa.dkim.eu-west-3.amazonses.com" {
		t.Fatalf("want the reported zone, got %+v", got)
	}
	// And the bound above the interface must ACCEPT it — a bound that refused the
	// regional zone would turn this fix into a refusal.
	if _, err := DkimRecords(context.Background(), fakeMail{records: got}, "emat.tw"); err != nil {
		t.Fatalf("the relayed record must survive its own bounds: %v", err)
	}
}

// 🔴 BYODKIM IS NOT OURS TO PUBLISH. With EXTERNAL origin the customer's own
// public key lives as a TXT at that selector; a CNAME over it replaces a working
// key with a pointer to one AWS does not hold.
func TestSESSkipsAnIdentityTheCustomerSignsThemselves(t *testing.T) {
	out := identityWithTokens("aaa", "bbb", "ccc")
	out.DkimAttributes.SigningAttributesOrigin = sesv2types.DkimSigningAttributesOriginExternal
	got, err := SES{API: &fakeSES{out: out}}.DkimRecords(context.Background(), "emat.tw")
	if err != nil {
		t.Fatalf("BYODKIM is a skip, not a fault: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("must publish nothing over a customer-held key, got %+v", got)
	}
}

// The control for the skip above, and it is the one that would have been missed:
// the origin enum carries a dozen REGIONAL Easy DKIM values, and an equality test
// against the bare AWS_SES would silently skip every identity outside one region.
func TestSESPublishesRegionalEasyDkimOrigins(t *testing.T) {
	for _, origin := range []sesv2types.DkimSigningAttributesOrigin{
		sesv2types.DkimSigningAttributesOriginAwsSes,
		sesv2types.DkimSigningAttributesOriginAwsSesEuWest3,
		sesv2types.DkimSigningAttributesOriginAwsSesApSouth1,
		"", // an older response that omits the field
	} {
		out := identityWithTokens("aaa")
		out.DkimAttributes.SigningAttributesOrigin = origin
		got, err := SES{API: &fakeSES{out: out}}.DkimRecords(context.Background(), "emat.tw")
		if err != nil || len(got) != 1 {
			t.Errorf("origin %q is Easy DKIM and must publish; got %+v %v", origin, got, err)
		}
	}
}

func ptrTo[T any](v T) *T { return &v }
