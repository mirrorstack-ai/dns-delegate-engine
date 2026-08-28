package observe

import (
	"context"
	"testing"
	"time"
)

// Every vantage point here is a fake. The probe's whole job is to measure real
// egress, and these tests hold it to reporting what it measured — including the
// one answer it must never act on.

const probeName = "connect.example.com"

// answering is a vantage point that resolves the probe name.
func answering() *fakeResolver {
	return &fakeResolver{cname: map[string]cnameAnswer{probeName: {value: probeName}}}
}

// unreachable is a vantage point this deployment has no egress to.
func unreachable() *fakeResolver {
	return &fakeResolver{cname: map[string]cnameAnswer{probeName: {err: timedOut(probeName)}}}
}

func sweepOf(t *testing.T, r Resolver) Reach {
	t.Helper()
	return (&Probe{Resolver: r, Name: probeName}).Reach(context.Background())
}

func TestTheProbeReportsWhichVantagePointsAnswered(t *testing.T) {
	got := sweepOf(t, Quorum{
		Resolvers: []Resolver{NetResolver{Server: "192.0.2.1:53"}, answering(), unreachable()},
		Threshold: 2,
	})

	if len(got.Vantages) != 3 || got.Threshold != 2 {
		t.Fatalf("reach %+v; want one row per configured vantage point and the declared threshold", got)
	}
	if got.Vantages[0].Vantage != "192.0.2.1:53" {
		t.Fatalf("vantage %q; an operator has to be told which one to fix", got.Vantages[0].Vantage)
	}
	if !got.Vantages[1].Reachable {
		t.Fatal("a vantage point that answered must be reported reachable")
	}
	if got.Vantages[2].Reachable || got.Vantages[2].Explain == "" {
		t.Fatalf("vantage %+v; one that did not answer must say so, and why", got.Vantages[2])
	}
	if got.CheckedAt.IsZero() {
		t.Fatal("a sweep that ran must be distinguishable from one that never did")
	}
}

// 🔴 The rule this whole branch exists to protect. An unreachable vantage point
// is REPORTED; it is never dropped so the survivors can meet a smaller
// threshold, because that would silently verify at 1 of 3 a customer who read
// "2 of 3" before authorizing.
func TestAnUnreachableVantagePointIsNeverDroppedFromTheQuorum(t *testing.T) {
	quorum := Quorum{
		Resolvers: []Resolver{serving(accepted[0]), serving(accepted[0]), unreachable()},
		Threshold: 3,
	}
	got := sweepOf(t, quorum)

	if got.Threshold != 3 || len(got.Vantages) != 3 {
		t.Fatalf("reach %+v; the published rule must survive the measurement unchanged", got)
	}
	if !got.Degraded() {
		t.Fatalf("2 reachable of a threshold of 3 is a broken deployment: %+v", got)
	}

	// And the quorum itself is unmoved: it still needs all three, so the proof
	// two of them serve does not become present.
	ok, obs, _ := read(t, quorum)
	if ok || obs.State != StateUnknown {
		t.Fatalf("state %q ok %v; the probe must not have lowered what the quorum requires", obs.State, ok)
	}
}

func TestAReachableSetThatMeetsTheThresholdIsNotDegraded(t *testing.T) {
	got := sweepOf(t, Quorum{
		Resolvers: []Resolver{answering(), answering(), unreachable()},
		Threshold: 2,
	})
	if got.Reachable() != 2 || got.Degraded() {
		t.Fatalf("reach %+v; 2 reachable against a threshold of 2 is a working deployment", got)
	}
}

// An unmeasured deployment is not a broken one: nothing was asked, so nothing
// may be concluded. It is the state of every deployment before a probe is wired.
func TestAnUnmeasuredReachIsNotDegraded(t *testing.T) {
	for _, tc := range []struct {
		name  string
		probe *Probe
	}{
		{"no resolver", &Probe{Name: probeName}},
		{"no probe name", &Probe{Resolver: unreachable()}},
		{"no probe at all", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.probe.Reach(context.Background())
			if !got.CheckedAt.IsZero() || got.Degraded() {
				t.Fatalf("reach %+v; an unasked question has no answer", got)
			}
		})
	}
}

// The probe is cheap because it is cached, and it re-measures because an
// operator who fixes egress must see the answer change without a redeploy.
func TestTheProbeReMeasuresOnlyAfterItsTTL(t *testing.T) {
	vantage := unreachable()
	now := time.Unix(0, 0)
	probe := &Probe{
		Resolver: vantage,
		Name:     probeName,
		TTL:      time.Minute,
		Now:      func() time.Time { return now },
	}

	probe.Reach(context.Background())
	probe.Reach(context.Background())
	if len(vantage.asked()) != 1 {
		t.Fatalf("%d lookups; a second caller inside the TTL must reuse the reading", len(vantage.asked()))
	}

	now = now.Add(2 * time.Minute)
	vantage.cname[probeName] = cnameAnswer{value: probeName}
	if got := probe.Reach(context.Background()); !got.Vantages[0].Reachable {
		t.Fatal("past the TTL the probe must re-measure, or a fixed deployment never recovers")
	}
}

// 🔴 Nothing in a lookup path may consult a Probe: a reachability reading that
// could reach a verification is a gate, and a gate here weakens the policy. The
// proof is that a quorum resolves normally through vantage points a probe has
// never touched.
func TestALookupNeverConsultsAProbe(t *testing.T) {
	vantages := []*fakeResolver{serving(accepted[0]), serving(accepted[0])}
	quorum := Quorum{Resolvers: []Resolver{vantages[0], vantages[1]}, Threshold: 2}

	if ok, _, _ := read(t, quorum); !ok {
		t.Fatal("the proof two of two vantage points serve must verify")
	}
	for i, v := range vantages {
		for _, call := range v.asked() {
			if call != "TXT "+proofName {
				t.Fatalf("vantage %d made %q; a verification must ask for the proof and nothing else", i, call)
			}
		}
	}
}
