package intent

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/consent"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/sealed"
)

// 🔴 THE WILDCARD LANE IS AUTHORIZABLE, AND ONLY BY ACKNOWLEDGING THE PAGE THIS
// SERVICE SERVED. Every step is taken through the service's own two entry
// points: nothing here mints a consent.Token directly, because a test that did
// would prove the lane can be authorized by whoever holds the keyset rather than
// by whoever was served the page.
func TestLaneTwoIsAuthorizedByAcknowledgingThePageThatWasServed(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgAppDomain, testOrg, appParent)
	h.publishProof(t, out)

	if _, err := h.svc.Authorize(t.Context(), AuthorizeRequest{
		Registration: out.Registration, CodeChallenge: "chal",
	}); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("want ErrConsentRequired with no acknowledgement, got %v", err)
	}

	page, err := h.svc.ConsentPage(t.Context(), out.Registration)
	if err != nil {
		t.Fatalf("ConsentPage: %v", err)
	}
	token, err := h.svc.AcknowledgeConsent(t.Context(), out.Registration, challengeFrom(t, page))
	if err != nil {
		t.Fatalf("AcknowledgeConsent: %v", err)
	}
	authorized, err := h.svc.Authorize(t.Context(), AuthorizeRequest{
		Registration: out.Registration, CodeChallenge: "chal", ConsentToken: token,
	})
	if err != nil {
		t.Fatalf("Authorize with an acknowledged page: %v", err)
	}
	state, err := sealed.OpenAuthState(h.sealer, authorized.State)
	if err != nil || !state.ConsentAck {
		t.Fatalf("the acknowledgement must be sealed INTO the state: %#v %v", state, err)
	}
}

// 🔴 SERVING IS NOT AGREEING. The page carries a challenge and never an
// acknowledgement, so holding the page is not holding the customer's agreement —
// which is the whole reason ConsentPage and AcknowledgeConsent are two calls.
func TestTheServedPageCarriesAChallengeAndNoAcknowledgement(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgAppDomain, testOrg, appParent)

	page, err := h.svc.ConsentPage(t.Context(), out.Registration)
	if err != nil {
		t.Fatalf("ConsentPage: %v", err)
	}
	challenge := challengeFrom(t, page)
	reference := h.open(t, out.Registration).ConsentNonce
	if consent.Verify(h.sealer, reference, appParent, challenge) {
		t.Fatal("🔴 the value printed on the page verifies as an acknowledgement")
	}
	// And the page names no acknowledgement anywhere else in its bytes either.
	if strings.Contains(page, "msack1-") {
		t.Fatal("🔴 rendering the consent page minted an acknowledgement")
	}
}

// 🔴 AN ACKNOWLEDGEMENT IS SPECIFIC TO THE REGISTRATION ITS PAGE WAS SERVED FOR.
// The same domain connected twice is two consents: the second registration mints
// its own reference, so a challenge from the first redeems for nothing there and
// the token from the first authorizes nothing there.
func TestAChallengeAndItsTokenAreBothSpecificToOneRegistration(t *testing.T) {
	h := newHarness(t)
	first := h.register(t, lane.OrgAppDomain, testOrg, appParent)
	second := h.register(t, lane.OrgAppDomain, testOrg, appParent)
	h.publishProof(t, second)

	page, err := h.svc.ConsentPage(t.Context(), first.Registration)
	if err != nil {
		t.Fatalf("ConsentPage: %v", err)
	}
	challenge := challengeFrom(t, page)

	if _, err := h.svc.AcknowledgeConsent(t.Context(), second.Registration, challenge); !errors.Is(err, consent.ErrConsent) {
		t.Fatalf("one registration's challenge must not redeem for another, got %v", err)
	}
	token, err := h.svc.AcknowledgeConsent(t.Context(), first.Registration, challenge)
	if err != nil {
		t.Fatalf("AcknowledgeConsent: %v", err)
	}
	if _, err := h.svc.Authorize(t.Context(), AuthorizeRequest{
		Registration: second.Registration, CodeChallenge: "chal", ConsentToken: token,
	}); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("one registration's acknowledgement must not authorize another, got %v", err)
	}
}

// 🔴 A PAGE SERVED FOR ONE ANCHOR CANNOT ACKNOWLEDGE ANOTHER. The challenge is a
// MAC over the anchor and the disclosure's bytes, and the anchor comes out of the
// sealed registration on both halves — so there is no request in which the two
// could be made to disagree.
func TestAPageServedForOneAnchorCannotAcknowledgeAnother(t *testing.T) {
	h := newHarness(t)
	here := h.register(t, lane.OrgAppDomain, testOrg, appParent)
	elsewhere := h.register(t, lane.OrgAppDomain, testOrg, "example.org")

	page, err := h.svc.ConsentPage(t.Context(), here.Registration)
	if err != nil {
		t.Fatalf("ConsentPage: %v", err)
	}
	if _, err := h.svc.AcknowledgeConsent(
		t.Context(), elsewhere.Registration, challengeFrom(t, page),
	); !errors.Is(err, consent.ErrConsent) {
		t.Fatalf("a challenge from example.net's page must not acknowledge example.org, got %v", err)
	}
}

// 🔴 A DISCLOSURE THAT CHANGED IS A DISCLOSURE NOBODY READ. The challenge binds
// the page's bytes, so a routing target that moved between the render and the
// agreement refuses rather than collecting consent to a screen that is no longer
// what this service would write.
func TestAnAcknowledgementRefusesADisclosureThatChangedUnderIt(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgAppDomain, testOrg, appParent)

	page, err := h.svc.ConsentPage(t.Context(), out.Registration)
	if err != nil {
		t.Fatalf("ConsentPage: %v", err)
	}
	challenge := challengeFrom(t, page)
	h.svc.Derive.AppRoutingTarget = "somewhere-else.mirrorstack.app"

	if _, err := h.svc.AcknowledgeConsent(t.Context(), out.Registration, challenge); !errors.Is(err, consent.ErrConsent) {
		t.Fatalf("the wildcard now points somewhere else: want a refusal, got %v", err)
	}
}

// The lanes that publish a closed, listable set have no page here and nothing to
// acknowledge — asked for one, both halves refuse as a bad REQUEST rather than
// as a malformed plan.
func TestNeitherHalfServesTheLanesWithNoConsentPage(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		lane     lane.Lane
		identity string
		domain   string
	}{
		{lane.OrgPlatformDomain, testOrg, platformDomain},
		{lane.AppDomain, testApp, appHostname},
	} {
		out := h.register(t, tc.lane, tc.identity, tc.domain)
		if _, err := h.svc.ConsentPage(t.Context(), out.Registration); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s has no consent page: got %v", tc.lane, err)
		}
		if _, err := h.svc.AcknowledgeConsent(t.Context(), out.Registration, "mschal1-anything"); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s has nothing to acknowledge: got %v", tc.lane, err)
		}
	}
}

// challengeValue reads the one hidden input the served page carries. Parsing the
// page rather than recomputing the value is the point: what a test redeems is
// what a browser would post back.
var challengeValue = regexp.MustCompile(`name="challenge" value="([^"]+)"`)

func challengeFrom(t *testing.T, page string) string {
	t.Helper()
	match := challengeValue.FindStringSubmatch(page)
	if len(match) != 2 {
		t.Fatal("the served page carries no challenge, so nobody could acknowledge it")
	}
	return match[1]
}
