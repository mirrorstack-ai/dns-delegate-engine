package intent

import (
	"strings"
	"testing"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
)

// 🔴 THE PATH NOTHING EXERCISED, AND THE ONE THAT BROKE.
//
// derive marked routing rows under exempt MirrorStack suffixes proxied;
// consent.Page refused every proxied row; the dispatcher maps that refusal to a
// 404. Each package's own tests passed — the contradiction only exists BETWEEN
// them, so it took a real Registration plan handed to the real ConsentPage to
// see it, and no test did that. Reported on core-v2#1022, after the exact-SHA
// Publish and CI both went green.
//
// This is that test: register the lane whose consent page exists, on an anchor
// inside our own zone, and render it.
func TestAnExemptAnchorsRegistrationRendersItsConsentPage(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgAppDomain, testOrg, appParent)

	page, err := h.svc.ConsentPage(t.Context(), out.Registration)
	if err != nil {
		t.Fatalf("the consent page must render for a plan this service derives: %v", err)
	}
	if !strings.Contains(page, appParent) {
		t.Errorf("the page must name the anchor it describes")
	}

	// 🔴 AND THE DISCLOSURE MUST MATCH THE PLAN, not merely render beside it.
	// The proof is ours to publish now, so a page still calling it a stop
	// control would be a false security claim — which is the second half of
	// what core-v2#1022 found.
	for _, gone := range []string{
		"MirrorStack cannot publish that record",
		"Delete it and every write",
	} {
		if strings.Contains(page, gone) {
			t.Errorf("the page still claims the ownership row is a stop control: %q", gone)
		}
	}
	// Matched on a fragment that survives the template's line wrapping — the
	// sentence itself spans a newline in the markup, so asserting the whole of
	// it would fail on formatting rather than on meaning.
	if !strings.Contains(page, "MirrorStack publishes that record for you") {
		t.Error("the page must say plainly that MirrorStack publishes the ownership marker")
	}
	if !strings.Contains(page, "it is not a") || !strings.Contains(page, "proof") {
		t.Error("the page must say the marker is not a proof")
	}
}

// 🔴 THE CUSTOMER-ZONE REGRESSION. Proxied is allowed in OUR zones and nowhere
// else, and both wrong answers are silent in production: a customer row
// published orange is flattened at their edge and fails at a renewal months
// later, with every dashboard on both sides green.
//
// Asserted through a real Registration rather than against the predicate, so a
// future change that widens the exemption or loses the anchor on the way to
// derivation is caught here too.
func TestACustomerZonesRoutingStaysDNSOnlyAndSaysSo(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgAppDomain, testOrg, "shop.example.com")

	for _, r := range out.Records {
		if r.Purpose == "routing" && r.Proxied {
			t.Fatalf("a customer-zone routing row must never be proxied: %+v", r)
		}
	}
	page, err := h.svc.ConsentPage(t.Context(), out.Registration)
	if err != nil {
		t.Fatalf("ConsentPage: %v", err)
	}
	if strings.Contains(page, "Proxied (Cloudflare terminates it)") {
		t.Error("a customer-zone plan must not disclose any proxied row, because it has none")
	}
	if !strings.Contains(page, "DNS only") {
		t.Error("the page must still state the proxy status it does have")
	}
}
