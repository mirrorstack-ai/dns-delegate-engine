package intent

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/observe"
)

// A customer decides whether to authorize BEFORE any of this runs, so the
// vantage-point rule has to be readable from Capabilities and every reading has
// to say what it rests on. These tests hold both to the resolver the service was
// actually wired with.

func emptyResolver() *fakeResolver {
	return &fakeResolver{txt: map[string][]string{}, cname: map[string]string{}, fail: map[string]error{}}
}

func servingProof(name, value string) *fakeResolver {
	r := emptyResolver()
	r.txt[name] = []string{value}
	return r
}

func TestCapabilitiesPublishesTheDeploymentsVantagePointRule(t *testing.T) {
	h := newHarness(t)

	if got := h.svc.Capabilities(t.Context()).Resolution; got != (ResolutionCapability{Vantages: 1, Threshold: 1}) {
		t.Fatalf("resolution %+v; a single resolver must say so rather than imply more", got)
	}

	h.svc.Resolver = observe.Quorum{
		Resolvers: []observe.Resolver{emptyResolver(), emptyResolver(), observe.Authoritative{}},
		Threshold: 2,
	}
	want := ResolutionCapability{Vantages: 3, Threshold: 2, Authoritative: true}
	if got := h.svc.Capabilities(t.Context()).Resolution; got != want {
		t.Fatalf("resolution %+v; want %+v", got, want)
	}
}

// 🔴 The field is always false, and a test pins it so nobody can turn it on
// without adding the validation it claims.
func TestCapabilitiesNeverClaimsDNSSEC(t *testing.T) {
	h := newHarness(t)
	h.svc.Resolver = observe.Quorum{
		Resolvers: []observe.Resolver{emptyResolver(), observe.Authoritative{}},
		Threshold: 2,
	}
	if h.svc.Capabilities(t.Context()).Resolution.DNSSEC {
		t.Fatal("this repository validates no signature anywhere, so the API must not say it does")
	}
}

func TestVerifyReportsHowManyVantagePointsAgreed(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)

	verified, err := h.svc.Verify(t.Context(), VerifyRequest{Registration: out.Registration})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Proof.Agreement == nil || *verified.Proof.Agreement != (AgreementView{Asked: 1, Agreed: 1, Threshold: 1}) {
		t.Fatalf("agreement %+v; one resolver believed on its own is what the default is worth", verified.Proof.Agreement)
	}

	h.svc.Resolver = observe.Quorum{
		Resolvers: []observe.Resolver{
			servingProof(out.Proof.Name, out.Proof.Value),
			servingProof(out.Proof.Name, out.Proof.Value),
			emptyResolver(),
		},
		Threshold: 2,
	}
	verified, err = h.svc.Verify(t.Context(), VerifyRequest{Registration: out.Registration})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verified.Verified {
		t.Fatal("two of three vantage points agreed the proof is published; that is a quorum")
	}
	if verified.Proof.Agreement == nil || *verified.Proof.Agreement != (AgreementView{Asked: 3, Agreed: 2, Threshold: 2}) {
		t.Fatalf("agreement %+v; want 2 of 3", verified.Proof.Agreement)
	}
}

// 🔴 A quorum that did not form is Unresolved, never "you have not published
// it": the two have opposite remedies, and only one of them is the customer's.
func TestASplitQuorumMakesVerifyUnresolvedRatherThanUnverified(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)

	liar := servingProof(out.Proof.Name, "a value nobody asked for")
	h.svc.Resolver = observe.Quorum{
		Resolvers: []observe.Resolver{servingProof(out.Proof.Name, out.Proof.Value), liar, emptyResolver()},
		Threshold: 2,
	}
	verified, err := h.svc.Verify(t.Context(), VerifyRequest{Registration: out.Registration})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Verified {
		t.Fatal("a split quorum verified a proof")
	}
	if !verified.Unresolved {
		t.Fatal("a split was reported as the customer not having published, which sends them to edit a correct record")
	}
	if verified.Proof.State != string(observe.StateUnknown) {
		t.Fatalf("state %q; want unknown", verified.Proof.State)
	}
}

// The customer's stop control has to survive the quorum: when the vantage
// points agree the TXT is gone, Verify says absent and the pass stops.
func TestAQuorumAgreeingTheProofIsGoneStillStops(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)

	h.svc.Resolver = observe.Quorum{
		Resolvers: []observe.Resolver{emptyResolver(), emptyResolver(), servingProof(out.Proof.Name, out.Proof.Value)},
		Threshold: 2,
	}
	verified, err := h.svc.Verify(t.Context(), VerifyRequest{Registration: out.Registration})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Verified || verified.Unresolved {
		t.Fatalf("verified %v unresolved %v; two of three agreed nothing is there", verified.Verified, verified.Unresolved)
	}
	if verified.Proof.State != string(observe.StateAbsent) {
		t.Fatalf("state %q; only absent stops a registration", verified.Proof.State)
	}
}

// Describe's derived rows carry the same count, so a customer reads one number
// for the whole report rather than trusting the proof row alone.
func TestDescribeRowsCarryTheirVantagePointCount(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)

	described, err := h.svc.Describe(t.Context(), DescribeRequest{Registration: out.Registration})
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	looked := 0
	for _, row := range described.Records {
		if row.State == "" {
			continue
		}
		looked++
		if row.Agreement == nil {
			t.Fatalf("row %s %s has a state but no vantage-point count", row.Type, row.Name)
		}
	}
	if looked == 0 {
		t.Fatal("no row in the report was looked up at all")
	}
}

// ─── reachability ───────────────────────────────────────────────────────────

// A deployment cannot check its own egress from a configuration file, so the
// service measures it and publishes what it found. These tests hold the
// published answer to the measurement — and hold the measurement out of every
// path that decides anything.

// stubReach is a measurement a test dictates, counting the calls so a publish
// path can be proven not to make any.
type stubReach struct {
	reach observe.Reach
	calls int
}

func (s *stubReach) Reach(context.Context) observe.Reach {
	s.calls++
	return s.reach
}

func measured(threshold int, reachable ...bool) *stubReach {
	out := observe.Reach{Threshold: threshold, CheckedAt: time.Unix(1_700_000_000, 0)}
	for i, ok := range reachable {
		v := observe.Reachability{Vantage: fmt.Sprintf("192.0.2.%d:53", i+1), Reachable: ok}
		if !ok {
			v.Explain = "no answer"
		}
		out.Vantages = append(out.Vantages, v)
	}
	return &stubReach{reach: out}
}

func TestCapabilitiesPublishesWhichVantagePointsAnswered(t *testing.T) {
	h := newHarness(t)
	h.svc.Resolver = observe.Quorum{
		Resolvers: []observe.Resolver{emptyResolver(), emptyResolver(), emptyResolver()},
		Threshold: 2,
	}
	h.svc.Reach = measured(2, true, true, false)

	got := h.svc.Capabilities(t.Context()).Resolution
	if got.Reachability == nil {
		t.Fatal("a measured deployment must publish what it measured")
	}
	if got.Reachability.Reachable != 2 || got.Reachability.Degraded {
		t.Fatalf("reachability %+v; 2 of 3 against a threshold of 2 is a working deployment", got.Reachability)
	}
	if got.Reachability.CheckedAt == "" {
		t.Fatal("a reading nobody can date is a reading nobody can act on")
	}
	if len(got.Reachability.Points) != 3 {
		t.Fatalf("%d points; every configured vantage point must be named", len(got.Reachability.Points))
	}
	if got.Reachability.Points[2].Reachable || got.Reachability.Points[2].Explain == "" {
		t.Fatalf("point %+v; the one to fix must be identifiable and say why", got.Reachability.Points[2])
	}
}

// 🔴 An unreachable vantage point is reported, and the rule it belongs to is
// republished UNCHANGED. Nothing may quietly re-cut a customer's "2 of 3" into
// a "1 of 1" because one leg went dark.
func TestAnUnreachableVantagePointNeverShrinksThePublishedRule(t *testing.T) {
	h := newHarness(t)
	h.svc.Resolver = observe.Quorum{
		Resolvers: []observe.Resolver{emptyResolver(), emptyResolver(), emptyResolver()},
		Threshold: 2,
	}
	h.svc.Reach = measured(2, true, false, false)

	got := h.svc.Capabilities(t.Context()).Resolution
	if got.Vantages != 3 || got.Threshold != 2 {
		t.Fatalf("resolution %+v; the rule a customer authorized against must not move", got)
	}
	if !got.Reachability.Degraded {
		t.Fatalf("reachability %+v; 1 reachable under a threshold of 2 is a broken deployment", got.Reachability)
	}
}

// Unmeasured is not unreachable: a deployment with no probe wired says nothing
// rather than something alarming.
func TestCapabilitiesReportsAnUnmeasuredDeploymentAsUnmeasured(t *testing.T) {
	h := newHarness(t)
	if got := h.svc.Capabilities(t.Context()).Resolution; got.Reachability != nil {
		t.Fatalf("reachability %+v; nothing was asked, so nothing may be reported", got.Reachability)
	}
}

// 🔴 The probe is an egress measurement, not a step in a registration. Nothing
// a customer waits on may pay for it, and — the reason that matters — nothing
// that decides whether to write may read it.
func TestThePublishPathNeverProbesReachability(t *testing.T) {
	h := newHarness(t)
	reach := measured(1, false)
	h.svc.Reach = reach

	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)
	state := h.authorize(t, out)
	pass, err := h.svc.Complete(t.Context(), CompleteRequest{
		State: state, Code: "auth-code", CodeVerifier: "verifier", ExpectDigest: out.Digest,
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if pass.Result != ResultPublished {
		t.Fatalf("a deployment whose probe found nothing must still publish for a proof it can read: %#v", pass)
	}
	if _, err := h.svc.Verify(t.Context(), VerifyRequest{Registration: out.Registration}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if reach.calls != 0 {
		t.Fatalf("%d probe calls on the register→authorize→publish→verify path; the probe belongs to Capabilities alone", reach.calls)
	}
}
