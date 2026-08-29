package lane_test

import (
	"strings"
	"testing"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
)

// The reserved-suffix rule is the reason this repository is worth reading, so
// the escape from it is pinned property by property rather than by example.

var reserved = []string{"mirrorstack.ai", "mirrorstack.app"}

func TestAnExemptedHostIsAdmitted(t *testing.T) {
	got, err := lane.ValidateDomainExempt(
		"platform.mirrorstack.app", reserved, []string{"platform.mirrorstack.app"})
	if err != nil {
		t.Fatalf("exempted host refused: %v", err)
	}
	if got != "platform.mirrorstack.app" {
		t.Errorf("got %q", got)
	}
}

// 🔴 PROPERTY 1 — THE ONE THAT MATTERS MOST.
//
// An exemption names ONE host. If it were matched as a suffix, exempting
// `platform.mirrorstack.app` would silently admit every name beneath it, which
// is the reserved rule inverted rather than narrowed.
func TestAnExemptionDoesNotAdmitTheSubtreeBeneathIt(t *testing.T) {
	for _, name := range []string{
		"api.platform.mirrorstack.app",
		"deep.nested.platform.mirrorstack.app",
	} {
		if _, err := lane.ValidateDomainExempt(name, reserved, []string{"platform.mirrorstack.app"}); err == nil {
			t.Errorf("%q was admitted by an exemption for its parent", name)
		}
	}
}

// 🔴 PROPERTY 2. Exempting a reserved suffix itself readmits its whole subtree.
// It fails CLOSED — every domain is refused, not just this one — because a
// misconfiguration that quietly permits everything is the worst outcome here.
func TestExemptingAReservedSuffixItselfRefusesEveryDomain(t *testing.T) {
	for _, name := range []string{"customer-owned.example", "platform.mirrorstack.app"} {
		_, err := lane.ValidateDomainExempt(name, reserved, []string{"mirrorstack.app"})
		if err == nil {
			t.Fatalf("%q admitted while an exemption named a reserved suffix", name)
		}
		if !strings.Contains(err.Error(), "reserved suffix") {
			t.Errorf("error should name the cause, got %v", err)
		}
	}
}

// 🔴 PROPERTY 3. An entry outside every reserved suffix permits nothing and
// reads like it does — which is how a real exemption gets added later without
// anyone noticing the list was already decorative.
func TestAnExemptionThatPermitsNothingIsRefused(t *testing.T) {
	if _, err := lane.ValidateDomainExempt(
		"customer-owned.example", reserved, []string{"unrelated.example"}); err == nil {
		t.Error("a no-op exemption entry was accepted")
	}
}

// A name that is not reserved at all needs no exemption and must not depend on
// the list being right.
func TestAnUnreservedNameIsUnaffected(t *testing.T) {
	if _, err := lane.ValidateDomainExempt("customer-owned.example", reserved, nil); err != nil {
		t.Fatalf("an ordinary domain was refused: %v", err)
	}
}

// With no entries this is ValidateDomain exactly — the production configuration.
func TestTheEmptyListReservesEverything(t *testing.T) {
	for _, name := range []string{"studio.mirrorstack.ai", "platform.mirrorstack.app", "mirrorstack.ai"} {
		if _, err := lane.ValidateDomainExempt(name, reserved, nil); err == nil {
			t.Errorf("%q admitted with no exemptions configured", name)
		}
	}
}

// Structural validation is not bypassed by an exemption: a malformed name must
// never be admitted just because somebody listed it.
func TestAnExemptionCannotAdmitAMalformedName(t *testing.T) {
	for _, name := range []string{"", "..mirrorstack.ai", "mirrorstack", "-bad.mirrorstack.ai"} {
		if _, err := lane.ValidateDomainExempt(name, reserved, []string{name}); err == nil {
			t.Errorf("malformed %q was admitted by listing it", name)
		}
	}
}

// Matching is on the NORMALIZED name, so a trailing dot or shouting case in
// either the entry or the input cannot be used to slip past the exact match —
// nor to defeat a legitimate entry.
func TestMatchingIsNormalized(t *testing.T) {
	if _, err := lane.ValidateDomainExempt(
		"Platform.MirrorStack.App.", reserved, []string{"platform.mirrorstack.app"}); err != nil {
		t.Errorf("a normalized-equal name was refused: %v", err)
	}
	if _, err := lane.ValidateDomainExempt(
		"platform.mirrorstack.app", reserved, []string{"PLATFORM.mirrorstack.APP."}); err != nil {
		t.Errorf("a normalized-equal entry did not match: %v", err)
	}
}
