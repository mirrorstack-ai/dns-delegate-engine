package observe

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Every vantage point in this file is a fake. Nothing here needs a network, a
// database or a Cloudflare account, which is the property Resolver exists to
// buy — and it is the only way a quorum rule can be checked at all, since a
// disagreement between real resolvers cannot be arranged on purpose.

const proofName = "_mirrorstack-challenge.example.com"

var accepted = []string{"proof-under-the-active-key"}

// serving is a vantage point that publishes values at proofName.
func serving(values ...string) *fakeResolver {
	return &fakeResolver{txt: map[string]txtAnswer{proofName: {values: values}}}
}

// missing is a vantage point at which nothing resolves — an untouched zone.
func missing() *fakeResolver { return &fakeResolver{} }

// failing is a vantage point that could not be asked.
func failing(err error) *fakeResolver {
	return &fakeResolver{txt: map[string]txtAnswer{proofName: {err: err}}}
}

// read runs the ownership proof through r, the way Verify does.
func read(t *testing.T, r Resolver) (bool, Observation, error) {
	t.Helper()
	return Proof(context.Background(), r, proofName, accepted)
}

// ---------------------------------------------------------------------------
// The threshold.
// ---------------------------------------------------------------------------

func TestTheThresholdDecidesWhetherAProofIsPresent(t *testing.T) {
	truthful := func() Resolver { return serving(accepted[0]) }

	for _, tc := range []struct {
		name      string
		vantages  []Resolver
		threshold int
		want      State
		ok        bool
	}{
		{"two of three agree, two required", []Resolver{truthful(), truthful(), missing()}, 2, StatePresent, true},
		{"two of three agree, three required", []Resolver{truthful(), truthful(), missing()}, 3, StateUnknown, false},
		{"three of three agree, three required", []Resolver{truthful(), truthful(), truthful()}, 3, StatePresent, true},
		{"one of three agrees, two required", []Resolver{truthful(), missing(), missing()}, 2, StateAbsent, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, obs, _ := read(t, Quorum{Resolvers: tc.vantages, Threshold: tc.threshold})
			if obs.State != tc.want || ok != tc.ok {
				t.Fatalf("state %q ok %v; want %q ok %v", obs.State, ok, tc.want, tc.ok)
			}
		})
	}
}

// 🔴 The attack this whole type exists for: one vantage point that lies.
func TestOneLiarOutOfThreeCannotProduceAPresentProof(t *testing.T) {
	q := Quorum{
		Resolvers: []Resolver{serving(accepted[0]), missing(), missing()},
		Threshold: 2,
	}
	ok, obs, err := read(t, q)
	if ok {
		t.Fatal("a single lying vantage point forged an ownership proof")
	}
	if obs.State != StateAbsent {
		t.Fatalf("state %q; the other two agreed nothing is published, which is absent", obs.State)
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// The liar cannot smuggle a value in beside real ones either: agreement is per
// VALUE, so what the majority serves survives and what one server invented does
// not.
func TestAValueOnlyOneVantagePointServesIsDropped(t *testing.T) {
	q := Quorum{
		Resolvers: []Resolver{
			serving("v=spf1 -all", "forged"),
			serving("v=spf1 -all"),
			serving("v=spf1 -all"),
		},
		Threshold: 2,
	}
	values, agreement, err := q.AttestedTXT(context.Background(), proofName)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(values) != 1 || values[0] != "v=spf1 -all" {
		t.Fatalf("values %q; only the value two vantage points served may survive", values)
	}
	if agreement.Agreed != 3 || agreement.Asked != 3 || agreement.Threshold != 2 {
		t.Fatalf("agreement %+v; want 3 of 3 asked, threshold 2", agreement)
	}
}

// One server repeating a value is still one vantage point.
func TestARepeatedValueDoesNotReachTheThresholdByItself(t *testing.T) {
	q := Quorum{
		Resolvers: []Resolver{serving(accepted[0], accepted[0], accepted[0]), missing()},
		Threshold: 2,
	}
	if ok, _, _ := read(t, q); ok {
		t.Fatal("one vantage point reached a quorum of two by repeating itself")
	}
}

// ---------------------------------------------------------------------------
// The three outcomes are not two.
// ---------------------------------------------------------------------------

// 🔴 A split is a failure to get an answer, so it must be unknown. Absent would
// be read as the customer withdrawing their proof.
func TestASplitIsUnknownAndNeverAbsent(t *testing.T) {
	q := Quorum{
		Resolvers: []Resolver{serving("one"), serving("another"), failing(servfail(proofName))},
		Threshold: 2,
	}
	ok, obs, err := read(t, q)
	if ok || obs.State != StateUnknown {
		t.Fatalf("state %q ok %v; a split must be unknown", obs.State, ok)
	}
	if obs.State == StateAbsent {
		t.Fatal("a split was read as a withdrawal")
	}
	if !errors.Is(err, ErrNoQuorum) {
		t.Fatalf("error %v; want ErrNoQuorum so the caller can tell a split from a lookup that never ran", err)
	}
	if isNotFound(err) {
		t.Fatal("ErrNoQuorum reported IsNotFound, which this package reads as absence")
	}
}

func TestTotalFailureIsUnknown(t *testing.T) {
	q := Quorum{
		Resolvers: []Resolver{
			failing(servfail(proofName)),
			failing(timedOut(proofName)),
			failing(errors.New("connection refused")),
		},
		Threshold: 2,
	}
	ok, obs, err := read(t, q)
	if ok || obs.State != StateUnknown {
		t.Fatalf("state %q ok %v; want unknown", obs.State, ok)
	}
	if err == nil {
		t.Fatal("a total failure returned no error, so a caller cannot tell it from a clean negative")
	}
	if isNotFound(err) {
		t.Fatal("three dead vantage points were reported as absence")
	}
}

// 🔴 The customer's stop control (README, "two controls"): when the vantage
// points agree the proof is gone, it is gone.
func TestAgreementOnAbsenceIsStillAbsence(t *testing.T) {
	q := Quorum{Resolvers: []Resolver{missing(), missing(), missing()}, Threshold: 2}
	ok, obs, err := read(t, q)
	if ok {
		t.Fatal("a withdrawn proof read as published")
	}
	if obs.State != StateAbsent {
		t.Fatalf("state %q; deleting the TXT must stop the registration, and only absent does that", obs.State)
	}
	if err != nil {
		t.Fatalf("unexpected error: %v; an unpublished proof is the ordinary early state, not a fault", err)
	}
}

// Absence is reached over one dissenting vantage point, but not over two
// silent ones.
func TestAbsenceNeedsTheThresholdToo(t *testing.T) {
	q := Quorum{
		Resolvers: []Resolver{missing(), failing(servfail(proofName)), failing(servfail(proofName))},
		Threshold: 2,
	}
	_, obs, _ := read(t, q)
	if obs.State != StateUnknown {
		t.Fatalf("state %q; one vantage point saying nothing is there is not a quorum", obs.State)
	}
}

// ---------------------------------------------------------------------------
// Fail closed on our own mistakes.
// ---------------------------------------------------------------------------

func TestAMisconfiguredQuorumVerifiesNothing(t *testing.T) {
	truthful := serving(accepted[0])
	for _, tc := range []struct {
		name string
		q    Quorum
	}{
		{"threshold zero", Quorum{Resolvers: []Resolver{truthful, truthful}, Threshold: 0}},
		{"threshold negative", Quorum{Resolvers: []Resolver{truthful, truthful}, Threshold: -1}},
		{"threshold above the vantage points", Quorum{Resolvers: []Resolver{truthful}, Threshold: 2}},
		{"no vantage points at all", Quorum{Threshold: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, obs, err := read(t, tc.q)
			if ok || obs.State != StateUnknown {
				t.Fatalf("state %q ok %v; a quorum that cannot be met must verify nothing", obs.State, ok)
			}
			if !errors.Is(err, ErrNoQuorum) {
				t.Fatalf("error %v; want ErrNoQuorum", err)
			}
		})
	}
}

// A CNAME owner holds one value, so two winning targets is a split.
func TestTwoAgreedCNAMETargetsAreASplit(t *testing.T) {
	const name = "www.example.com"
	at := func(target string) *fakeResolver {
		return &fakeResolver{cname: map[string]cnameAnswer{name: {value: target}}}
	}
	q := Quorum{
		Resolvers: []Resolver{at("a.example.net"), at("a.example.net"), at("b.example.net"), at("b.example.net")},
		Threshold: 2,
	}
	if _, err := q.LookupCNAME(context.Background(), name); !errors.Is(err, ErrNoQuorum) {
		t.Fatalf("error %v; want ErrNoQuorum", err)
	}
}

// DNS names are case-insensitive, so vantage points spelling a target
// differently are agreeing.
func TestCNAMETargetsAgreeAcrossCase(t *testing.T) {
	const name = "www.example.com"
	at := func(target string) *fakeResolver {
		return &fakeResolver{cname: map[string]cnameAnswer{name: {value: target}}}
	}
	q := Quorum{Resolvers: []Resolver{at("Edge.example.net."), at("edge.example.net.")}, Threshold: 2}
	got, err := q.LookupCNAME(context.Background(), name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.EqualFold(got, "edge.example.net.") {
		t.Fatalf("target %q; want edge.example.net.", got)
	}
}

// ---------------------------------------------------------------------------
// Reporting what was used.
// ---------------------------------------------------------------------------

func TestAPlainResolverReportsOneVantagePoint(t *testing.T) {
	if got := PolicyOf(serving(accepted[0])); got != (Policy{Vantages: 1, Threshold: 1}) {
		t.Fatalf("policy %+v; a plain resolver is one vantage point believed on its own", got)
	}
	_, obs, err := read(t, serving(accepted[0]))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if obs.Agreement != (Agreement{Asked: 1, Agreed: 1, Threshold: 1}) {
		t.Fatalf("agreement %+v; want 1 of 1", obs.Agreement)
	}
}

func TestAQuorumPublishesItsOwnPolicy(t *testing.T) {
	q := Quorum{
		Resolvers: []Resolver{serving(accepted[0]), serving(accepted[0]), Authoritative{}},
		Threshold: 2,
	}
	want := Policy{Vantages: 3, Threshold: 2, Authoritative: true}
	if got := q.Policy(); got != want {
		t.Fatalf("policy %+v; want %+v", got, want)
	}
}

func TestAFailedReadingRestsOnNothing(t *testing.T) {
	_, obs, _ := read(t, failing(servfail(proofName)))
	if obs.Agreement.Agreed != 0 || obs.Agreement.Asked != 1 {
		t.Fatalf("agreement %+v; a lookup that did not complete rests on no vantage point", obs.Agreement)
	}
}

func TestMajorityIsMoreThanHalf(t *testing.T) {
	for vantages, want := range map[int]int{1: 1, 2: 2, 3: 2, 4: 3, 5: 3} {
		if got := Majority(vantages); got != want {
			t.Fatalf("Majority(%d) = %d; want %d", vantages, got, want)
		}
	}
}

// The two composable resolvers must satisfy the interface every test drives.
var (
	_ Resolver   = Quorum{}
	_ Attesting  = Quorum{}
	_ Policied   = Quorum{}
	_ Resolver   = Authoritative{}
	_ Policied   = Authoritative{}
	_ Delegation = NetDelegation{}
)
