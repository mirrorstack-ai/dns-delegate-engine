package observe

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/derive"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/proof"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/testsupport"
)

// Every name in this file is example.com, example.net or example.org. Nothing
// here needs a network, a database or a Cloudflare account, which is the
// property the Resolver interface exists to buy.
const (
	anchor       = "example.com"
	routingCNAME = "org-routing.mirrorstack.ai"
)

// ---------------------------------------------------------------------------
// A fake public DNS.
// ---------------------------------------------------------------------------

type cnameAnswer struct {
	value string
	err   error
}

type txtAnswer struct {
	values []string
	err    error
}

// fakeResolver is public DNS as a table. A name that is not in a table does not
// resolve, which is what an untouched customer zone looks like.
type fakeResolver struct {
	cname map[string]cnameAnswer
	txt   map[string]txtAnswer

	// delay is applied per lookup so a test can force completions to finish out
	// of the order they were started in.
	delay map[string]time.Duration

	mu    sync.Mutex
	calls []string
}

func (f *fakeResolver) record(kind, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, kind+" "+name)
}

func (f *fakeResolver) asked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeResolver) wait(name string) {
	if d, ok := f.delay[name]; ok && d > 0 {
		time.Sleep(d)
	}
}

func (f *fakeResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	f.record("CNAME", name)
	f.wait(name)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if answer, ok := f.cname[name]; ok {
		return answer.value, answer.err
	}
	return "", testsupport.NotFound(name)
}

func (f *fakeResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	f.record("TXT", name)
	f.wait(name)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if answer, ok := f.txt[name]; ok {
		return answer.values, answer.err
	}
	return nil, testsupport.NotFound(name)
}

// 🔴 The production resolver must satisfy the interface every test drives. It
// is the one implementation no test can exercise — covering LookupCNAME and
// LookupTXT would need a network, which this repository's tests may not have —
// so a compile-time assertion is the only thing standing between a drifted
// signature and the first production call site.
var (
	_ Resolver = NetResolver{}
	_ Resolver = &NetResolver{}
	_ Resolver = (*fakeResolver)(nil)
)

func timedOut(name string) error {
	return &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true, IsTemporary: true}
}

func servfail(name string) error {
	return &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
}

func item(recordType, name, value string, purpose derive.Purpose, source derive.Source) derive.Item {
	return derive.Item{
		Record:  dnsplan.Record{Type: recordType, Name: name, Value: value},
		Purpose: purpose,
		Source:  source,
		Explain: "why this row is here",
	}
}

func planOf(items ...derive.Item) derive.Plan {
	return derive.Plan{Lane: lane.OrgPlatformDomain, Anchor: anchor, Items: items}
}

func observe(t *testing.T, r Resolver, p derive.Plan) []Observation {
	t.Helper()
	got, err := Plan(context.Background(), r, p)
	if err != nil {
		t.Fatalf("Plan: unexpected error: %v", err)
	}
	if len(got) != len(p.Items) {
		t.Fatalf("Plan returned %d observations for %d items; a report with a hole in it is worse than no report", len(got), len(p.Items))
	}
	return got
}

// ---------------------------------------------------------------------------
// Every state, from one plan.
// ---------------------------------------------------------------------------

func TestPlanReportsEveryState(t *testing.T) {
	resolver := &fakeResolver{
		cname: map[string]cnameAnswer{
			// present
			"account.example.com": {value: routingCNAME + "."},
			// conflicting: a CNAME, but somebody else's
			"api.example.com": {value: "old-cdn.example.net."},
			// wrong type: the name resolves, but not through a CNAME, so the
			// resolver hands the queried name back
			"apps.example.com": {value: "apps.example.com."},
			// unknown: the lookup did not complete
			"cdn.example.com": {err: servfail("cdn.example.com")},
			// absent is the default: nothing is published at
			// _cf-custom-hostname.account.example.com
		},
		txt: map[string]txtAnswer{
			"_cf-custom-hostname.account.example.com": {err: testsupport.NotFound("_cf-custom-hostname.account.example.com")},
		},
	}

	plan := planOf(
		item("CNAME", "account.example.com", routingCNAME, derive.PurposeRouting, derive.SourceDerived),
		item("CNAME", "api.example.com", routingCNAME, derive.PurposeRouting, derive.SourceDerived),
		item("CNAME", "apps.example.com", routingCNAME, derive.PurposeRouting, derive.SourceDerived),
		item("CNAME", "cdn.example.com", routingCNAME, derive.PurposeRouting, derive.SourceDerived),
		item("TXT", "_cf-custom-hostname.account.example.com", "proof-value", derive.PurposeServing, derive.SourceRelayed),
	)

	want := []State{StatePresent, StateConflicting, StateWrongType, StateUnknown, StateAbsent}
	got := observe(t, resolver, plan)
	for i, observation := range got {
		if observation.State != want[i] {
			t.Errorf("item %d (%s): state = %q, want %q (explain: %s)",
				i, observation.Name, observation.State, want[i], observation.Explain)
		}
		if observation.Name != plan.Items[i].Record.Name {
			t.Errorf("item %d: observation is for %q, want %q — observations must be in item order",
				i, observation.Name, plan.Items[i].Record.Name)
		}
		if observation.Purpose != plan.Items[i].Purpose || observation.Source != plan.Items[i].Source {
			t.Errorf("item %d: purpose/source were not carried through unchanged", i)
		}
		if !strings.Contains(observation.Explain, "why this row is here") {
			t.Errorf("item %d: the derived explanation was dropped: %q", i, observation.Explain)
		}
	}
}

// ---------------------------------------------------------------------------
// TXT values add beside each other. CNAMEs do not.
// ---------------------------------------------------------------------------

func TestAMultiValueTXTWithOneMatchIsPresent(t *testing.T) {
	// A real customer's `_cf-custom-hostname` owner can hold a site
	// verification token and whatever else they have put there. None of it
	// displaces ours, so none of it is a conflict — TXT records ADD beside each
	// other, and a report that called the neighbours a problem would send
	// somebody off to delete records that were fine.
	name := "_cf-custom-hostname.account.example.com"
	resolver := &fakeResolver{txt: map[string]txtAnswer{
		name: {values: []string{"some-other-verification=abc", `"the-serving-proof"`, "v=spf1 -all"}},
	}}

	got := observe(t, resolver, planOf(
		item("TXT", name, "the-serving-proof", derive.PurposeServing, derive.SourceRelayed),
	))[0]

	if got.State != StatePresent {
		t.Fatalf("state = %q, want present (explain: %s)", got.State, got.Explain)
	}
	if len(got.Found) != 3 {
		t.Fatalf("Found = %q, want all three published values reported", got.Found)
	}
	if got.State == StateConflicting {
		t.Fatal("a neighbouring TXT value must never be reported as a conflict")
	}
	if !strings.Contains(got.Explain, "add beside each other") {
		t.Errorf("the report should say why the other values are fine: %q", got.Explain)
	}
}

func TestATXTWhoseValueIsMissingIsAbsentAndShowsWhatIsThere(t *testing.T) {
	// "I added it and nothing happened" is usually this: the value with a
	// character dropped is sitting right there in Found, next to the one that
	// was asked for. Absent, not conflicting — it only has to be added.
	name := "_cf-custom-hostname.account.example.com"
	resolver := &fakeResolver{txt: map[string]txtAnswer{
		name: {values: []string{"the-serving-proo"}},
	}}

	got := observe(t, resolver, planOf(
		item("TXT", name, "the-serving-proof", derive.PurposeServing, derive.SourceRelayed),
	))[0]

	if got.State != StateAbsent {
		t.Fatalf("state = %q, want absent", got.State)
	}
	if len(got.Found) != 1 || got.Found[0] != "the-serving-proo" {
		t.Fatalf("Found = %q, want the near-miss reported so it can be seen", got.Found)
	}
}

func TestATXTOwnerThatHoldsNoValuesIsAbsent(t *testing.T) {
	// A Resolver may report "the name resolved, and there is no TXT at it"
	// as an empty answer rather than as NXDOMAIN. It is still absence — an
	// ANSWER, unlike a failed lookup — and the report says so plainly.
	name := "_cf-custom-hostname.account.example.com"
	resolver := &fakeResolver{txt: map[string]txtAnswer{name: {values: []string{}}}}

	got := observe(t, resolver, planOf(
		item("TXT", name, "the-serving-proof", derive.PurposeServing, derive.SourceRelayed),
	))[0]
	if got.State != StateAbsent {
		t.Fatalf("state = %q, want absent", got.State)
	}
	if len(got.Found) != 0 {
		t.Fatalf("Found = %q, want nothing", got.Found)
	}
}

func TestACNAMEWithADifferentTargetIsConflictingAndFoundNamesIt(t *testing.T) {
	// A CNAME owner holds exactly one value, so ours cannot be added beside
	// what is there. The customer has to change something, and cannot decide
	// what without being told what is in the way — so the observation must NAME
	// the target it found, not merely report a conflict.
	resolver := &fakeResolver{cname: map[string]cnameAnswer{
		"account.example.com": {value: "old-cdn.example.net."},
	}}

	got := observe(t, resolver, planOf(
		item("CNAME", "account.example.com", routingCNAME, derive.PurposeRouting, derive.SourceDerived),
	))[0]

	if got.State != StateConflicting {
		t.Fatalf("state = %q, want conflicting (a different target is not absence)", got.State)
	}
	if len(got.Found) != 1 || got.Found[0] != "old-cdn.example.net" {
		t.Fatalf("Found = %q, want the conflicting target named (and the root dot folded off)", got.Found)
	}
	if !strings.Contains(got.Explain, "old-cdn.example.net") {
		t.Errorf("the explanation must name what is in the way: %q", got.Explain)
	}
}

func TestACNAMEValueIsComparedWithoutTheRootDot(t *testing.T) {
	// A resolver answer carries the root dot where a provider record does not.
	// dnsplan.NormalizeName exists for exactly this, and forgetting it here
	// would report every correctly published routing record as conflicting.
	resolver := &fakeResolver{cname: map[string]cnameAnswer{
		"account.example.com": {value: "ORG-Routing.MirrorStack.ai."},
	}}
	got := observe(t, resolver, planOf(
		item("CNAME", "account.example.com", routingCNAME, derive.PurposeRouting, derive.SourceDerived),
	))[0]
	if got.State != StatePresent {
		t.Fatalf("state = %q, want present; DNS is case-insensitive and the root dot is presentation", got.State)
	}
}

func TestACNAMEThatResolvesWithoutOneIsWrongType(t *testing.T) {
	// The Resolver contract: a name that resolves but holds no CNAME answers
	// with itself. In practice that means address records are published there —
	// most often because the record was left proxied on Cloudflare, where the
	// CNAME is in the zone but public DNS serves addresses instead.
	resolver := &fakeResolver{cname: map[string]cnameAnswer{
		"account.example.com": {value: "account.example.com."},
	}}
	got := observe(t, resolver, planOf(
		item("CNAME", "account.example.com", routingCNAME, derive.PurposeRouting, derive.SourceDerived),
	))[0]

	if got.State != StateWrongType {
		t.Fatalf("state = %q, want wrong_type", got.State)
	}
	if !strings.Contains(got.Explain, "proxied") {
		t.Errorf("the explanation should name the reason a customer usually hits this: %q", got.Explain)
	}
}

// ---------------------------------------------------------------------------
// 🔴 The one that matters most.
// ---------------------------------------------------------------------------

func TestATimeoutIsUnknownAndNeverAbsent(t *testing.T) {
	// 🔴 THIS IS THE IMPORTANT TEST IN THIS FILE.
	//
	// Absent and unknown look similar in a report and mean opposite things to
	// the loop that reads it. Absent is an ANSWER from public DNS: the record
	// is not there, and on the ownership proof that eventually means the domain
	// is no longer proven and a live credential should be released. Unknown is
	// our failure to get an answer at all.
	//
	// If a timeout collapsed into absent, a resolver blip on our side — or a
	// customer's nameserver having a bad minute — would be indistinguishable
	// from that customer deliberately withdrawing their proof, and this service
	// would act on the difference. Every wrong guess this package could make
	// points that way, which is why isNotFound recognises exactly one error and
	// treats everything else as unknown.
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"timeout", timedOut("account.example.com")},
		{"servfail", servfail("account.example.com")},
		{"transport", errors.New("connection reset by peer")},
		{"cancelled", context.Canceled},
		{"deadline", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &fakeResolver{cname: map[string]cnameAnswer{
				"account.example.com": {err: tc.err},
			}}
			got := observe(t, resolver, planOf(
				item("CNAME", "account.example.com", routingCNAME, derive.PurposeRouting, derive.SourceDerived),
			))[0]

			if got.State == StateAbsent {
				t.Fatalf("a failed lookup was reported as absent; %v is not evidence the customer removed anything", tc.err)
			}
			if got.State != StateUnknown {
				t.Fatalf("state = %q, want unknown", got.State)
			}
			if !strings.Contains(got.Explain, "not evidence") {
				t.Errorf("the report must say the record is not known to be missing: %q", got.Explain)
			}
		})
	}
}

func TestAResolverThatAnswersNothingIsUnknownNotAbsent(t *testing.T) {
	// An empty value with no error is a resolver telling us nothing. Reading it
	// as absence would be inventing an answer, so it fails toward unknown.
	resolver := &fakeResolver{cname: map[string]cnameAnswer{
		"account.example.com": {value: ""},
	}}
	got := observe(t, resolver, planOf(
		item("CNAME", "account.example.com", routingCNAME, derive.PurposeRouting, derive.SourceDerived),
	))[0]
	if got.State != StateUnknown {
		t.Fatalf("state = %q, want unknown", got.State)
	}
}

func TestNXDOMAINIsAbsentAndNotAnError(t *testing.T) {
	// The ordinary early state of every registration: nothing published yet.
	// It must reach the caller as a report, never as a fault.
	resolver := &fakeResolver{}
	got := observe(t, resolver, planOf(
		item("CNAME", "account.example.com", routingCNAME, derive.PurposeRouting, derive.SourceDerived),
	))[0]
	if got.State != StateAbsent {
		t.Fatalf("state = %q, want absent", got.State)
	}
	if len(got.Found) != 0 {
		t.Fatalf("Found = %q, want nothing", got.Found)
	}
}

func TestPlanOnAFinishedContextIsUnknownNotAbsent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resolver := &fakeResolver{cname: map[string]cnameAnswer{
		"account.example.com": {value: routingCNAME},
		"api.example.com":     {value: routingCNAME},
	}}
	got, err := Plan(ctx, resolver, planOf(
		item("CNAME", "account.example.com", routingCNAME, derive.PurposeRouting, derive.SourceDerived),
		item("CNAME", "api.example.com", routingCNAME, derive.PurposeRouting, derive.SourceDerived),
	))
	if err != nil {
		t.Fatalf("a cancelled context is reported per record, not as a refusal: %v", err)
	}
	for i, observation := range got {
		if observation.State != StateUnknown {
			t.Errorf("item %d: state = %q, want unknown", i, observation.State)
		}
	}
}

func TestPlanDoesNotWaitForASlotOnAFinishedContext(t *testing.T) {
	// With every concurrency slot held by a name that is still in flight, the
	// items behind them must take the context's answer rather than queue for a
	// lookup that cannot succeed. Otherwise one slow name at the head of a plan
	// decides how long a cancelled report takes to come back.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resolver := &fakeResolver{cname: map[string]cnameAnswer{}, delay: map[string]time.Duration{}}
	items := make([]derive.Item, 0, 3*maxInFlight)
	for i := 0; i < 3*maxInFlight; i++ {
		name := string(rune('a'+i)) + ".example.com"
		resolver.cname[name] = cnameAnswer{value: routingCNAME}
		resolver.delay[name] = 20 * time.Millisecond
		items = append(items, item("CNAME", name, routingCNAME, derive.PurposeRouting, derive.SourceDerived))
	}

	got, err := Plan(ctx, resolver, planOf(items...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, observation := range got {
		if observation.State != StateUnknown {
			t.Fatalf("item %d: state = %q, want unknown", i, observation.State)
		}
	}
}

// ---------------------------------------------------------------------------
// What Plan refuses outright.
// ---------------------------------------------------------------------------

func TestPlanRefusesARecordOutsideTheAnchor(t *testing.T) {
	// The report goes in front of a customer as "the records this service
	// manages in your zone". A line in it naming something outside the proven
	// parent is a lie we would be asking them to act on, and it is a derivation
	// bug either way — so the whole plan is refused, exactly as the write path
	// refuses it.
	for _, name := range []string{
		"account.example.net",
		"evilexample.com",
		"example.com.attacker.example.net",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Plan(context.Background(), &fakeResolver{}, planOf(
				item("CNAME", name, routingCNAME, derive.PurposeRouting, derive.SourceDerived),
			))
			if !errors.Is(err, dnsplan.ErrAnchorEscape) {
				t.Fatalf("err = %v, want dnsplan.ErrAnchorEscape", err)
			}
			// It wraps ErrPlanInvalid, so a caller matching only the boundary
			// error still refuses.
			if !errors.Is(err, dnsplan.ErrPlanInvalid) {
				t.Fatalf("the containment refusal must still match the boundary error")
			}
		})
	}
}

func TestPlanAcceptsTheAnchorItselfAndAWildcardUnderIt(t *testing.T) {
	// Lane 3's anchor IS the hostname, and lane 2's whole plan is one wildcard.
	// Both must pass containment or two of the three lanes cannot be described.
	for _, name := range []string{"example.com", "*.example.com"} {
		t.Run(name, func(t *testing.T) {
			if _, err := Plan(context.Background(), &fakeResolver{}, planOf(
				item("CNAME", name, routingCNAME, derive.PurposeRouting, derive.SourceDerived),
			)); err != nil {
				t.Fatalf("Plan refused %q under anchor %q: %v", name, anchor, err)
			}
		})
	}
}

func TestPlanRefusesATypeThisServiceDoesNotPublish(t *testing.T) {
	// The README promises CNAME and TXT and nothing else. Observing an A record
	// would quietly widen what this repository claims to touch.
	for _, recordType := range []string{"A", "AAAA", "MX", "NS", "CAA", ""} {
		t.Run("type_"+recordType, func(t *testing.T) {
			_, err := Plan(context.Background(), &fakeResolver{}, planOf(
				item(recordType, "account.example.com", "192.0.2.1", derive.PurposeRouting, derive.SourceDerived),
			))
			if !errors.Is(err, ErrObserve) {
				t.Fatalf("err = %v, want ErrObserve", err)
			}
		})
	}
}

func TestPlanRefusesAMalformedRequest(t *testing.T) {
	good := planOf(item("CNAME", "account.example.com", routingCNAME, derive.PurposeRouting, derive.SourceDerived))

	t.Run("no resolver", func(t *testing.T) {
		if _, err := Plan(context.Background(), nil, good); !errors.Is(err, ErrObserve) {
			t.Fatalf("err = %v, want ErrObserve", err)
		}
	})
	t.Run("no anchor", func(t *testing.T) {
		p := good
		p.Anchor = ""
		if _, err := Plan(context.Background(), &fakeResolver{}, p); !errors.Is(err, ErrObserve) {
			t.Fatalf("err = %v, want ErrObserve", err)
		}
	})
	t.Run("over long anchor", func(t *testing.T) {
		p := good
		p.Anchor = strings.Repeat("a", dnsplan.MaxDNSName) + ".example.com"
		if _, err := Plan(context.Background(), &fakeResolver{}, p); !errors.Is(err, ErrObserve) {
			t.Fatalf("err = %v, want ErrObserve", err)
		}
	})
	t.Run("more items than a plan may hold", func(t *testing.T) {
		items := make([]derive.Item, 0, dnsplan.MaxRecords+1)
		for i := 0; i <= dnsplan.MaxRecords; i++ {
			items = append(items, item("TXT", "_probe.example.com", "value", derive.PurposeServing, derive.SourceRelayed))
		}
		if _, err := Plan(context.Background(), &fakeResolver{}, planOf(items...)); !errors.Is(err, ErrObserve) {
			t.Fatalf("err = %v, want ErrObserve; an unbounded plan is an unbounded fan-out at a customer's nameservers", err)
		}
	})
	t.Run("an item that does not name a record", func(t *testing.T) {
		for _, name := range []string{"", "   ", "."} {
			_, err := Plan(context.Background(), &fakeResolver{}, planOf(
				item("CNAME", name, routingCNAME, derive.PurposeRouting, derive.SourceDerived),
			))
			if !errors.Is(err, ErrObserve) {
				t.Fatalf("name %q: err = %v, want ErrObserve", name, err)
			}
		}
	})
	t.Run("empty plan is an empty report", func(t *testing.T) {
		got, err := Plan(context.Background(), &fakeResolver{}, planOf())
		if err != nil || len(got) != 0 {
			t.Fatalf("got %d observations, err %v; an empty plan is not a defect", len(got), err)
		}
	})
}

// ---------------------------------------------------------------------------
// What Plan declines to judge, and what it declines to ask.
// ---------------------------------------------------------------------------

func TestPlanDefersTheOwnershipProofToVerify(t *testing.T) {
	// 🔴 The keyset accepts one value per key. The plan item carries only the
	// value a customer would be asked for TODAY, so a proof published under a
	// key that has since rotated is valid and would not match it. Judging it
	// here would make describe() contradict verify() on the one record every
	// other record hangs from.
	name := proof.Prefix + anchor
	resolver := &fakeResolver{txt: map[string]txtAnswer{
		name: {values: []string{"msv1-something-from-an-older-key"}},
	}}

	got := observe(t, resolver, planOf(
		item("TXT", name, "msv1-todays-value", derive.PurposeOwnership, derive.SourceCustomer),
	))[0]

	if got.State != StateUnknown {
		t.Fatalf("state = %q, want unknown: this report is not entitled to an opinion here", got.State)
	}
	if asked := resolver.asked(); len(asked) != 0 {
		t.Fatalf("Plan issued %v; a query whose answer it may not judge is a query worth not making", asked)
	}
	if !strings.Contains(got.Explain, "verify()") {
		t.Errorf("the report must point at what does decide this record: %q", got.Explain)
	}
}

func TestPlanTreatsAnUnknownValueAsPendingWithoutAskingDNS(t *testing.T) {
	// The relayed records exist in a plan before AWS or Cloudflare have
	// produced what goes in them. Nothing has been asked of the customer yet,
	// so reporting absent would be wrong in the direction that costs a support
	// reply — and there is nothing to look for.
	resolver := &fakeResolver{}
	got := observe(t, resolver, planOf(
		item("TXT", "_cf-custom-hostname.account.example.com", "", derive.PurposeServing, derive.SourceRelayed),
	))[0]

	if got.State != StateUnknown {
		t.Fatalf("state = %q, want unknown", got.State)
	}
	if asked := resolver.asked(); len(asked) != 0 {
		t.Fatalf("Plan asked %v about a record nobody has been asked to publish", asked)
	}
}

func TestPlanIssuesOneLookupPerNameAndType(t *testing.T) {
	// Two values at one TXT owner are judged against the SAME answer. Two
	// separate lookups could disagree for no reason but timing, and a report
	// that contradicts itself is the thing this package exists to prevent.
	name := "_cf-custom-hostname.account.example.com"
	resolver := &fakeResolver{txt: map[string]txtAnswer{
		name: {values: []string{"first-value"}},
	}}

	got := observe(t, resolver, planOf(
		item("TXT", name, "first-value", derive.PurposeServing, derive.SourceRelayed),
		item("TXT", name, "second-value", derive.PurposeServing, derive.SourceRelayed),
	))

	if asked := resolver.asked(); len(asked) != 1 {
		t.Fatalf("resolver was asked %v, want exactly one lookup for one owner and type", asked)
	}
	if got[0].State != StatePresent || got[1].State != StateAbsent {
		t.Fatalf("states = %q/%q, want present/absent from one shared answer", got[0].State, got[1].State)
	}
	if len(got[1].Found) != 1 || got[1].Found[0] != "first-value" {
		t.Fatalf("both items must report the same observed set; got %q", got[1].Found)
	}
	// The same values, not the same slice: a caller trimming one observation
	// must not be reordering another it never touched.
	got[0].Found[0] = "mutated"
	if got[1].Found[0] != "first-value" {
		t.Fatal("two observations in one lookup group share a Found slice")
	}
}

func TestPlanPreservesItemOrderWhenLookupsFinishOutOfOrder(t *testing.T) {
	// Concurrency is an implementation detail of the report, never of its
	// shape. The first item's answer belongs at index zero even when it is the
	// last one to arrive.
	names := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com", "f.example.com"}
	resolver := &fakeResolver{
		cname: map[string]cnameAnswer{},
		delay: map[string]time.Duration{},
	}
	items := make([]derive.Item, 0, len(names))
	for i, name := range names {
		resolver.cname[name] = cnameAnswer{value: routingCNAME}
		// Earlier items finish last.
		resolver.delay[name] = time.Duration(len(names)-i) * time.Millisecond
		items = append(items, item("CNAME", name, routingCNAME, derive.PurposeRouting, derive.SourceDerived))
	}

	got := observe(t, resolver, planOf(items...))
	for i, observation := range got {
		if observation.Name != names[i] {
			t.Fatalf("observation %d is for %q, want %q", i, observation.Name, names[i])
		}
		if observation.State != StatePresent {
			t.Fatalf("observation %d: state = %q, want present", i, observation.State)
		}
	}
}

func TestPlanAsksAboutTheNormalizedName(t *testing.T) {
	// A Resolver implementation is handed the name in one spelling only. The
	// root dot belongs to the wire, and NetResolver adds it; every other
	// implementation, including a test fake, sees the normalized form.
	resolver := &fakeResolver{cname: map[string]cnameAnswer{
		"account.example.com": {value: routingCNAME},
	}}
	observe(t, resolver, planOf(
		item("CNAME", "ACCOUNT.Example.COM.", routingCNAME, derive.PurposeRouting, derive.SourceDerived),
	))
	if asked := resolver.asked(); len(asked) != 1 || asked[0] != "CNAME account.example.com" {
		t.Fatalf("resolver was asked %v, want the normalized name", asked)
	}
}

// ---------------------------------------------------------------------------
// Proof: the gate.
// ---------------------------------------------------------------------------

const proofIdentity = "11111111-2222-3333-4444-555555555555"

func acceptSet(t *testing.T, p proof.Prover) (accepted []string, active string) {
	t.Helper()
	accepted, err := p.Accepted(lane.OrgPlatformDomain, proofIdentity, anchor)
	if err != nil {
		t.Fatal(err)
	}
	active, err = p.Expected(lane.OrgPlatformDomain, proofIdentity, anchor)
	if err != nil {
		t.Fatal(err)
	}
	return accepted, active
}

func TestProofIsTrueWhenTheActiveValueIsPublished(t *testing.T) {
	prover := proof.Prover{Sealer: testsupport.Sealer(t, "current")}
	accepted, active := acceptSet(t, prover)
	name := proof.Name(anchor)

	resolver := &fakeResolver{txt: map[string]txtAnswer{name: {values: []string{active}}}}
	ok, obs, err := Proof(context.Background(), resolver, name, accepted)
	if err != nil || !ok || obs.State != StatePresent {
		t.Fatalf("ok=%v state=%q err=%v, want true/present/nil", ok, obs.State, err)
	}
}

func TestProofIsTrueForARotatedOutAcceptedValue(t *testing.T) {
	// 🔴 KEY ROTATION MUST NOT BREAK A PUBLISHED PROOF.
	//
	// A customer publishes the ownership TXT once and has no reason ever to
	// look at it again. If rotating the MAC key invalidated it, every domain in
	// the estate would go unproven at the same moment and this service would
	// start releasing live credentials over a key change of ours.
	prover := proof.Prover{Sealer: testsupport.Sealer(t, "current", "previous")}
	accepted, active := acceptSet(t, prover)
	if len(accepted) != 2 {
		t.Fatalf("accept set has %d values, want one per key", len(accepted))
	}

	retired := ""
	for _, value := range accepted {
		if value != active {
			retired = value
		}
	}
	if retired == "" {
		t.Fatal("could not find a non-active accepted value")
	}

	name := proof.Name(anchor)
	resolver := &fakeResolver{txt: map[string]txtAnswer{name: {values: []string{retired}}}}
	ok, obs, err := Proof(context.Background(), resolver, name, accepted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok || obs.State != StatePresent {
		t.Fatalf("a proof published under a rotated-out key was rejected: ok=%v state=%q", ok, obs.State)
	}
}

func TestProofIsFalseWhenNoAcceptedValueIsPublished(t *testing.T) {
	prover := proof.Prover{Sealer: testsupport.Sealer(t, "current")}
	accepted, active := acceptSet(t, prover)
	name := proof.Name(anchor)

	// A value for a DIFFERENT anchor, which is exactly what a caller aiming
	// this service at somebody else's domain would have to hand.
	other, err := prover.Expected(lane.OrgPlatformDomain, proofIdentity, "example.net")
	if err != nil {
		t.Fatal(err)
	}
	if other == active {
		t.Fatal("two anchors produced the same proof value")
	}

	resolver := &fakeResolver{txt: map[string]txtAnswer{
		name: {values: []string{"unrelated=token", other, "v=spf1 -all"}},
	}}
	ok, obs, err := Proof(context.Background(), resolver, name, accepted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("a value minted for another anchor satisfied the proof")
	}
	if obs.State != StateAbsent {
		t.Fatalf("state = %q, want absent", obs.State)
	}
	if len(obs.Found) != 3 {
		t.Fatalf("Found = %q, want everything published at the name reported back", obs.Found)
	}
}

func TestProofFoldsPresentationButNotMeaning(t *testing.T) {
	// Several DNS control panels upper-case or quote what is pasted into them.
	// Refusing a proof over presentation would be refusing a customer who did
	// exactly what they were asked.
	prover := proof.Prover{Sealer: testsupport.Sealer(t, "current")}
	accepted, active := acceptSet(t, prover)
	name := proof.Name(anchor)

	for _, published := range []string{
		active,
		strings.ToUpper(active),
		`"` + active + `"`,
		"  " + active + "  ",
		`" ` + strings.ToUpper(active) + ` "`,
	} {
		resolver := &fakeResolver{txt: map[string]txtAnswer{name: {values: []string{published}}}}
		ok, _, err := Proof(context.Background(), resolver, name, accepted)
		if err != nil || !ok {
			t.Fatalf("published %q: ok=%v err=%v, want accepted", published, ok, err)
		}
	}

	// A dropped character is a different value, not different presentation.
	truncated := active[:len(active)-1]
	resolver := &fakeResolver{txt: map[string]txtAnswer{name: {values: []string{truncated}}}}
	if ok, _, _ := Proof(context.Background(), resolver, name, accepted); ok {
		t.Fatal("a truncated value satisfied the proof")
	}
}

func TestProofAbsentIsNotAnError(t *testing.T) {
	// The ordinary state of a registration the customer has not acted on yet.
	// An error here would make the loop treat waiting as a fault and back off
	// from a customer who is simply still typing.
	prover := proof.Prover{Sealer: testsupport.Sealer(t, "current")}
	accepted, _ := acceptSet(t, prover)
	name := proof.Name(anchor)

	ok, obs, err := Proof(context.Background(), &fakeResolver{}, name, accepted)
	if err != nil {
		t.Fatalf("NXDOMAIN was returned as an error: %v", err)
	}
	if ok || obs.State != StateAbsent {
		t.Fatalf("ok=%v state=%q, want false/absent", ok, obs.State)
	}

	// The other shape of the same answer: the name resolves, and holds no TXT.
	// Still an ANSWER, so still absent rather than unknown, and still not a
	// fault.
	empty := &fakeResolver{txt: map[string]txtAnswer{name: {values: []string{}}}}
	ok, obs, err = Proof(context.Background(), empty, name, accepted)
	if err != nil {
		t.Fatalf("an empty TXT owner was returned as an error: %v", err)
	}
	if ok || obs.State != StateAbsent {
		t.Fatalf("ok=%v state=%q, want false/absent", ok, obs.State)
	}
	if len(obs.Found) != 0 {
		t.Fatalf("Found = %q, want nothing", obs.Found)
	}
}

func TestProofUnknownReturnsTheErrorAndIsNeverAbsent(t *testing.T) {
	// 🔴 A failed lookup must not reach the caller as a clean negative. Absent
	// eventually releases a customer's credential; unknown must not be able to.
	prover := proof.Prover{Sealer: testsupport.Sealer(t, "current")}
	accepted, _ := acceptSet(t, prover)
	name := proof.Name(anchor)

	for _, lookupErr := range []error{servfail(name), timedOut(name), context.DeadlineExceeded} {
		resolver := &fakeResolver{txt: map[string]txtAnswer{name: {err: lookupErr}}}
		ok, obs, err := Proof(context.Background(), resolver, name, accepted)
		if ok {
			t.Fatalf("%v: proof passed on a failed lookup", lookupErr)
		}
		if obs.State == StateAbsent {
			t.Fatalf("%v: a failed lookup was reported as absent", lookupErr)
		}
		if obs.State != StateUnknown {
			t.Fatalf("%v: state = %q, want unknown", lookupErr, obs.State)
		}
		if err == nil {
			t.Fatalf("%v: the error was swallowed; the caller cannot tell this from a clean negative", lookupErr)
		}
	}
}

func TestProofRefusesAMalformedRequest(t *testing.T) {
	prover := proof.Prover{Sealer: testsupport.Sealer(t, "current")}
	accepted, _ := acceptSet(t, prover)
	name := proof.Name(anchor)

	t.Run("no resolver", func(t *testing.T) {
		if _, _, err := Proof(context.Background(), nil, name, accepted); !errors.Is(err, ErrObserve) {
			t.Fatalf("err = %v, want ErrObserve", err)
		}
	})
	t.Run("no name", func(t *testing.T) {
		if _, _, err := Proof(context.Background(), &fakeResolver{}, "", accepted); !errors.Is(err, ErrObserve) {
			t.Fatalf("err = %v, want ErrObserve", err)
		}
	})
	t.Run("empty accept set", func(t *testing.T) {
		// 🔴 An empty accept set means the keyset produced nothing — a defect on
		// our side. Returning a clean false would be indistinguishable from a
		// customer who has not published yet, and the caller would eventually
		// release a live credential over our own fault.
		for _, accepted := range [][]string{nil, {}, {""}, {"", ""}} {
			ok, _, err := Proof(context.Background(), &fakeResolver{}, name, accepted)
			if ok {
				t.Fatal("an empty accept set passed the proof")
			}
			if !errors.Is(err, ErrObserve) {
				t.Fatalf("accepted=%q: err = %v, want ErrObserve", accepted, err)
			}
		}
	})
	t.Run("an empty accepted entry matches nothing at all", func(t *testing.T) {
		// Neither an empty published value nor a real one may be satisfied by a
		// blank slot in the accept set — a keyset that produced one entry of
		// nothing must not become a proof that anything satisfies.
		for _, published := range [][]string{
			{"", `""`, "   "},
			{"a-real-but-wrong-value"},
			{"", "a-real-but-wrong-value"},
		} {
			resolver := &fakeResolver{txt: map[string]txtAnswer{name: {values: published}}}
			if ok, _, _ := Proof(context.Background(), resolver, name, append([]string{""}, accepted...)); ok {
				t.Fatalf("published %q satisfied the proof through an empty accepted entry", published)
			}
		}
	})
}

func TestProofDoesNotEchoTheAcceptSetBack(t *testing.T) {
	// The accept set holds one value per key and carries no marker for which is
	// active, so there is nothing here that could be shown to a customer
	// without picking arbitrarily. Want stays empty; proof.Prover.Expected is
	// what a console renders.
	prover := proof.Prover{Sealer: testsupport.Sealer(t, "current", "previous")}
	accepted, active := acceptSet(t, prover)
	name := proof.Name(anchor)
	resolver := &fakeResolver{txt: map[string]txtAnswer{name: {values: []string{active}}}}

	_, obs, err := Proof(context.Background(), resolver, name, accepted)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Want != "" {
		t.Fatalf("Want = %q, want empty", obs.Want)
	}
}

// ---------------------------------------------------------------------------
// The duplicated matcher, pinned to the canonical one.
// ---------------------------------------------------------------------------

func TestProofMatchingAgreesWithTheProofPackage(t *testing.T) {
	// foldProofValue and matchesAccepted are a second copy of a rule that
	// belongs to internal/proof. The duplication exists because Proof is handed
	// an accept set and never an identity, which is what keeps this package
	// unable to decide what counts as a valid proof — but a second copy of a
	// security rule is a place for the two to drift, and the looser one would
	// be the one that mattered. So the two are driven over one table and have
	// to agree on every row.
	prover := proof.Prover{Sealer: testsupport.Sealer(t, "current", "previous")}
	accepted, active := acceptSet(t, prover)

	rows := [][]string{
		nil,
		{},
		{active},
		{strings.ToUpper(active)},
		{`"` + active + `"`},
		{"  " + active},
		{active + "  "},
		{`" ` + strings.ToUpper(active) + ` "`},
		{accepted[0]},
		{accepted[1]},
		{accepted[0], accepted[1]},
		{"", active},
		{"unrelated", active, "v=spf1 -all"},
		{"unrelated"},
		{""},
		{`""`},
		{"   "},
		{active[:len(active)-1]},
		{active + "x"},
		{strings.Replace(active, "msv1-", "msv2-", 1)},
	}

	for i, observed := range rows {
		want, err := prover.Matches(lane.OrgPlatformDomain, proofIdentity, anchor, observed)
		if err != nil {
			t.Fatalf("row %d: %v", i, err)
		}
		// Exactly the path Proof takes: normalize the observed values, then
		// match them against the accept set.
		got := matchesAccepted(normalizeTXTValues(observed), accepted)
		if got != want {
			t.Errorf("row %d %q: observe says %v, proof.Prover.Matches says %v — the two matchers have drifted",
				i, observed, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Small pieces.
// ---------------------------------------------------------------------------

func TestRootedMakesANameAbsolute(t *testing.T) {
	// A name without the root dot is tried against /etc/resolv.conf's search
	// list as well as on its own, so an absent customer record could be
	// answered by whatever `<name>.<our-search-domain>` resolves to.
	for input, want := range map[string]string{
		"example.com":  "example.com.",
		"example.com.": "example.com.",
		"":             "",
	} {
		if got := rooted(input); got != want {
			t.Errorf("rooted(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNetResolverHoldsNothing(t *testing.T) {
	// No network is touched here: this asserts the shape of the production
	// resolver, which is the part that has to be checkable by reading.
	var n NetResolver
	if n.timeout() != defaultTimeout {
		t.Errorf("zero NetResolver timeout = %v, want %v", n.timeout(), defaultTimeout)
	}
	if (NetResolver{Timeout: -time.Second}).timeout() != defaultTimeout {
		t.Error("a negative timeout must not become an immediate deadline")
	}
	if (NetResolver{Timeout: time.Second}).timeout() != time.Second {
		t.Error("a configured timeout must be honoured")
	}

	first, second := n.resolver(), n.resolver()
	if first == second {
		t.Error("resolver() returned a shared instance; a per-lookup one is how 'holds no answers' stays visible")
	}
	if !first.PreferGo {
		t.Error("PreferGo must be set: the cgo path answers a CNAME from an address lookup and reports a correctly published validation record as missing")
	}
}

func TestNormalizeTXTStripsPresentationAndKeepsMeaning(t *testing.T) {
	for input, want := range map[string]string{
		`"value"`:     "value",
		`  "value"  `: "value",
		`value`:       "value",
		// ONE matched pair, dnsprovider.TrimTXTQuotes: an unbalanced or doubled
		// quote is data, and eating it would make two different values compare
		// equal here while the write path still told them apart.
		`""value""`: `"value"`,
		`"`:         `"`,
		``:          "",
		// Case is meaning for a general TXT value: a difference in case is a
		// real difference to whoever is checking it upstream.
		`"MixedCase"`: "MixedCase",
	} {
		if got := normalizeTXT(input); got != want {
			t.Errorf("normalizeTXT(%q) = %q, want %q", input, got, want)
		}
	}
	if normalizeTXTValues(nil) != nil {
		t.Error("no values must stay no values, not an empty slice")
	}
}

func TestExplainKeepsBothHalves(t *testing.T) {
	// Why the record exists and why adding it has not worked are different
	// questions, and there is one field in a report for a human to read.
	if got := explain("why it is here", "what we saw"); got != "why it is here — what we saw" {
		t.Errorf("explain() = %q", got)
	}
	if got := explain("", "what we saw"); got != "what we saw" {
		t.Errorf("explain() with no item text = %q", got)
	}
	if got := explain("why it is here", ""); got != "why it is here" {
		t.Errorf("explain() with no diagnosis = %q", got)
	}
}

func TestIsNotFoundRecognisesExactlyOneError(t *testing.T) {
	// 🔴 Every mistake this function could make points the same way: toward
	// telling a caller a record is gone when it may not be.
	if !isNotFound(testsupport.NotFound("example.com")) {
		t.Error("NXDOMAIN must be recognised")
	}
	for _, err := range []error{
		timedOut("example.com"),
		servfail("example.com"),
		errors.New("no such host"), // the same words, not the same fact
		context.Canceled,
		&net.DNSError{Err: "no such host", IsTemporary: true},
	} {
		if isNotFound(err) {
			t.Errorf("%v was read as absence", err)
		}
	}
}
