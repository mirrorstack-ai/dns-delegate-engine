package intent

import (
	"testing"

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
