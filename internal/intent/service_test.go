package intent

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/consent"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/derive"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsprovider"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/observe"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/proof"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/reconcile"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/sealed"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/cfoauth"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/grantcrypto"
)

// Fixture domains are example.com / .net / .org only, per CLAUDE.md: a real
// customer's name must never appear in this repository, including in a test.
const (
	testOrg = "11111111-2222-4333-8444-555555555555"
	testApp = "3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f607"

	platformDomain = "example.com" // lane 1
	appParent      = "example.net" // lane 2
	appHostname    = "example.org" // lane 3

	testDCVUUID = "6126b8722afa32ca"
)

// ─── the tests the rules demand ─────────────────────────────────────────────

// 🔴 A REGISTRATION TOUCHES NO CREDENTIAL AND WRITES NOTHING. It is the entire
// reason the manual path is a supported answer rather than a fallback: a
// customer who never authorizes still gets the derived list, and no credential
// of theirs exists anywhere in MirrorStack.
func TestRegisteringTouchesNoCredentialAndWritesNothing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		lane   lane.Lane
		call   func(*Service) (RegisteredResponse, error)
		anchor string
		hosts  int
	}{
		{"platform", lane.OrgPlatformDomain, func(s *Service) (RegisteredResponse, error) {
			return s.AddOrgPlatformDomain(t.Context(), AddOrgPlatformDomainRequest{OrgID: testOrg, Domain: platformDomain})
		}, platformDomain, 4},
		{"org app domain", lane.OrgAppDomain, func(s *Service) (RegisteredResponse, error) {
			return s.AddOrgAppDomain(t.Context(), AddOrgAppDomainRequest{OrgID: testOrg, Domain: appParent})
		}, appParent, 1},
		{"app domain", lane.AppDomain, func(s *Service) (RegisteredResponse, error) {
			return s.AddAppDomain(t.Context(), AddAppDomainRequest{AppID: testApp, Hostname: appHostname})
		}, appHostname, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			out, err := tc.call(h.svc)
			if err != nil {
				t.Fatalf("register: %v", err)
			}
			if h.provider.writes != 0 || h.oauth.tokenCalls != 0 || h.oauth.revokeCalls != 0 {
				t.Fatalf("a registration wrote or exchanged something: %#v %#v", h.provider, h.oauth)
			}
			if out.Registration == "" || out.KeyID == "" || out.Digest == "" {
				t.Fatalf("a registration must come back sealed, keyed and digested: %#v", out)
			}
			if out.Lane != string(tc.lane) || out.Anchor != tc.anchor || len(out.Hosts) != tc.hosts {
				t.Fatalf("lane/anchor/hosts: %#v", out)
			}
			if out.Proof.Source != string(derive.SourceCustomer) ||
				out.Proof.Name != proof.Prefix+tc.anchor || out.Proof.Value == "" {
				t.Fatalf("the proof must be the CUSTOMER's, at the anchor, with a value: %#v", out.Proof)
			}
			// The sealed registration opens, and carries exactly the three facts
			// every later call is derived from.
			reg := h.open(t, out.Registration)
			if reg.Lane != tc.lane || reg.Anchor != tc.anchor {
				t.Fatalf("sealed registration: %#v", reg)
			}
		})
	}
}

// 🔴 THE ONE THAT MATTERS MOST. A regression here silently restores the exact
// defect this rebuild exists to fix: an ownership proof this service publishes
// itself proves nothing, because the gate on proceeding is a public lookup of
// that same record.
func TestTheOwnershipRecordIsNeverInWhatIsPublished(t *testing.T) {
	h := newHarness(t)
	for _, lane := range []struct {
		anchor string
		plan   func() (RegisteredResponse, error)
	}{
		{platformDomain, func() (RegisteredResponse, error) {
			return h.svc.AddOrgPlatformDomain(t.Context(), AddOrgPlatformDomainRequest{OrgID: testOrg, Domain: platformDomain})
		}},
		{appParent, func() (RegisteredResponse, error) {
			return h.svc.AddOrgAppDomain(t.Context(), AddOrgAppDomainRequest{OrgID: testOrg, Domain: appParent})
		}},
		{appHostname, func() (RegisteredResponse, error) {
			return h.svc.AddAppDomain(t.Context(), AddAppDomainRequest{AppID: testApp, Hostname: appHostname})
		}},
	} {
		out, err := lane.plan()
		if err != nil {
			t.Fatalf("register %s: %v", lane.anchor, err)
		}
		reg := h.open(t, out.Registration)
		plan, err := h.svc.derivedPlan(t.Context(), reg)
		if err != nil {
			t.Fatalf("derive %s: %v", lane.anchor, err)
		}
		records, err := publishable(plan)
		if err != nil {
			t.Fatalf("publishable %s: %v", lane.anchor, err)
		}
		if len(records) == 0 {
			t.Fatalf("%s derived nothing publishable", lane.anchor)
		}
		for _, record := range records {
			if record.Name == proof.Prefix+lane.anchor {
				t.Fatalf("%s: the ownership proof is in the publishable set: %#v", lane.anchor, record)
			}
		}
	}
}

// And the guard has to hold when the derivation itself is the thing that
// drifted. A record the customer owes, appearing under a source that would let
// this service write it, must refuse the WHOLE plan rather than being filtered
// out quietly — a filtered plan publishes on and nobody learns the derivation
// is wrong.
func TestAPlanThatWouldPublishTheCustomersRecordIsRefused(t *testing.T) {
	owed := dnsplan.Record{Type: "TXT", Name: proof.Prefix + platformDomain, Value: "msv1-theirs"}
	plan := derive.Plan{
		Lane: lane.OrgPlatformDomain, Anchor: platformDomain,
		Items: []derive.Item{
			{Record: owed, Purpose: derive.PurposeOwnership, Source: derive.SourceCustomer},
			// The drift: the same owner and type, now marked as ours to write.
			{Record: dnsplan.Record{Type: "TXT", Name: owed.Name, Value: "msv1-ours"},
				Purpose: derive.PurposeOwnership, Source: derive.SourceDerived},
		},
	}
	if _, err := publishable(plan); !errors.Is(err, dnsplan.ErrPlanInvalid) {
		t.Fatalf("want a plan refusal, got %v", err)
	}
}

// 🔴 Authorize refuses unless verify passes RIGHT NOW. Not "was verified once".
// Without a live check the anchor's proof is a fact about the past, and deleting
// the TXT — the customer's first stop control — would not bound the authority
// about to be granted.
func TestAuthorizeRefusesUntilTheProofResolvesRightNow(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)

	_, err := h.svc.Authorize(t.Context(), AuthorizeRequest{Registration: out.Registration, CodeChallenge: "chal"})
	if !errors.Is(err, ErrNotProven) {
		t.Fatalf("want ErrNotProven, got %v", err)
	}

	h.publishProof(t, out)
	authorized, err := h.svc.Authorize(t.Context(), AuthorizeRequest{Registration: out.Registration, CodeChallenge: "chal"})
	if err != nil {
		t.Fatalf("Authorize after the proof landed: %v", err)
	}
	if authorized.State == "" || !strings.Contains(authorized.AuthorizationURL, "code_challenge=chal") {
		t.Fatalf("consent URL: %#v", authorized)
	}

	// And it stops again the moment the proof goes. A registration is not
	// permanently authorizable because it was authorizable once.
	h.resolver.remove(proof.Prefix + platformDomain)
	if _, err := h.svc.Authorize(t.Context(), AuthorizeRequest{Registration: out.Registration, CodeChallenge: "chal"}); !errors.Is(err, ErrNotProven) {
		t.Fatalf("want ErrNotProven after the proof was withdrawn, got %v", err)
	}
}

// 🔴 Authorize MINTS the state. The legacy grant.Authorize took one as a request
// field, which is a string a caller can also mint for a registration it is not
// holding.
func TestAuthorizeMintsAStateCarryingTheSealedFacts(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.AppDomain, testApp, appHostname)
	h.publishProof(t, out)

	authorized, err := h.svc.Authorize(t.Context(), AuthorizeRequest{Registration: out.Registration, CodeChallenge: "chal"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	state, err := sealed.OpenAuthState(h.sealer, authorized.State)
	if err != nil {
		t.Fatalf("the minted state must open here: %v", err)
	}
	if state.Lane != lane.AppDomain || state.Identity != testApp || state.Anchor != appHostname || state.Nonce == "" {
		t.Fatalf("the state must carry the lane, the identity, the anchor and a nonce: %#v", state)
	}
	// Two authorizations of one registration are two different values.
	second, err := h.svc.Authorize(t.Context(), AuthorizeRequest{Registration: out.Registration, CodeChallenge: "chal"})
	if err != nil || second.State == authorized.State {
		t.Fatalf("each authorization must mint a distinct state: %v", err)
	}
}

// 🔴 The wildcard lane needs this service's own consent page. `*.example.net` is
// the one grant whose scope a customer cannot enumerate for themselves.
func TestAuthorizeRefusesTheWildcardLaneWithoutAnAcknowledgedConsentPage(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgAppDomain, testOrg, appParent)
	h.publishProof(t, out)

	if !consent.Required(lane.OrgAppDomain) {
		t.Fatal("this test is meaningless if the wildcard lane does not require consent")
	}
	if _, err := h.svc.Authorize(t.Context(), AuthorizeRequest{
		Registration: out.Registration, CodeChallenge: "chal",
	}); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("want ErrConsentRequired with no token, got %v", err)
	}

	// The reference the acknowledgement is a MAC over is the REGISTRATION's,
	// minted when the domain was registered. There is no request field for it.
	reference := h.open(t, out.Registration).ConsentNonce
	if reference == "" {
		t.Fatal("a wildcard registration must carry the reference its consent page is printed with")
	}

	// A token for a DIFFERENT anchor is not a token for this one.
	elsewhere, err := consent.Token(h.sealer, reference, platformDomain)
	if err != nil {
		t.Fatalf("consent.Token: %v", err)
	}
	if _, err := h.svc.Authorize(t.Context(), AuthorizeRequest{
		Registration: out.Registration, CodeChallenge: "chal", ConsentToken: elsewhere,
	}); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("a consent token for another anchor must not authorize this one, got %v", err)
	}

	// 🔴 AND A TOKEN OVER A REFERENCE THIS SERVICE NEVER SEALED INTO THIS
	// REGISTRATION IS REFUSED, however well formed it is and whatever key minted
	// it. This is the whole of the control: the caller supplies one half of the
	// MAC and never both, so an acknowledgement cannot be a signature on a
	// statement the caller wrote for itself.
	invented, err := sealed.NewNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	forged, err := consent.Token(h.sealer, invented, appParent)
	if err != nil {
		t.Fatalf("consent.Token: %v", err)
	}
	if _, err := h.svc.Authorize(t.Context(), AuthorizeRequest{
		Registration: out.Registration, CodeChallenge: "chal", ConsentToken: forged,
	}); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("a token over a reference nobody issued for this registration must not authorize it, got %v", err)
	}

	token, err := consent.Token(h.sealer, reference, appParent)
	if err != nil {
		t.Fatalf("consent.Token: %v", err)
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
	// The other two lanes keep the console's screen and owe no acknowledgement.
	for _, l := range []lane.Lane{lane.OrgPlatformDomain, lane.AppDomain} {
		if consent.Required(l) {
			t.Fatalf("%s must not require this service's consent page", l)
		}
	}
}

// 🔴 AN ACKNOWLEDGEMENT IS SCOPED TO ONE REGISTRATION, AND THAT IS BOTH HALVES
// OF THE CLAIM consent.Token MAKES.
//
// It does not carry to a second registration of the same domain: re-registering
// mints a new reference, so the earlier agreement — given about an earlier
// derivation, possibly by an earlier person — authorizes nothing. And within one
// registration it IS replayable, because a service that stores nothing cannot
// count. The second half is asserted here rather than left implied: consent.Token
// says the limit out loud, and a documented limit nobody exercises is a sentence,
// not a property.
func TestAnAcknowledgementIsScopedToOneRegistrationAndNotToOneAttempt(t *testing.T) {
	h := newHarness(t)
	first := h.register(t, lane.OrgAppDomain, testOrg, appParent)
	h.publishProof(t, first)

	firstReference := h.open(t, first.Registration).ConsentNonce
	ack, err := consent.Token(h.sealer, firstReference, appParent)
	if err != nil {
		t.Fatalf("consent.Token: %v", err)
	}
	if _, err := h.svc.Authorize(t.Context(), AuthorizeRequest{
		Registration: first.Registration, CodeChallenge: "chal", ConsentToken: ack,
	}); err != nil {
		t.Fatalf("the acknowledgement must authorize its own registration: %v", err)
	}

	// The same domain connected a second time is a second consent.
	second := h.register(t, lane.OrgAppDomain, testOrg, appParent)
	if reference := h.open(t, second.Registration).ConsentNonce; reference == firstReference {
		t.Fatal("each registration must mint its own reference, or one screen agrees for all of them")
	}
	if _, err := h.svc.Authorize(t.Context(), AuthorizeRequest{
		Registration: second.Registration, CodeChallenge: "chal", ConsentToken: ack,
	}); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("an acknowledgement of one registration must not authorize another, got %v", err)
	}

	// The limit that remains, exercised so it cannot quietly stop being true.
	if _, err := h.svc.Authorize(t.Context(), AuthorizeRequest{
		Registration: first.Registration, CodeChallenge: "chal", ConsentToken: ack,
	}); err != nil {
		t.Fatalf("consent.Token documents the acknowledgement as replayable within its registration: %v", err)
	}
}

// The consent page is printed with the registration's own reference, and there
// is no way to ask for another one — a page rendered with a reference Authorize
// will not check collects an agreement that can never be verified.
func TestTheConsentPageIsPrintedWithTheSealedReference(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgAppDomain, testOrg, appParent)

	page, err := h.svc.ConsentPage(t.Context(), out.Registration)
	if err != nil {
		t.Fatalf("ConsentPage: %v", err)
	}
	reference := h.open(t, out.Registration).ConsentNonce
	if !strings.Contains(page, reference) {
		t.Fatal("the page must print the reference the acknowledgement is bound to")
	}
	// Rendering it twice is the same page: the reference is a property of the
	// registration, not of the request that asked for it.
	again, err := h.svc.ConsentPage(t.Context(), out.Registration)
	if err != nil || again != page {
		t.Fatalf("two renders of one registration must be the same page: %v", err)
	}

	// A registration sealed by a build without this control has no reference,
	// and is refused rather than served a page nobody could act on. The proof is
	// published first so the refusal below is reached at the consent gate rather
	// than at the ownership one.
	h.publishProof(t, out)
	stale, _, err := sealed.SealRegistration(h.sealer, sealed.Registration{
		Lane: lane.OrgAppDomain, Identity: testOrg, Anchor: appParent, IssuedAt: nowUnix(),
	})
	if err != nil {
		t.Fatalf("SealRegistration: %v", err)
	}
	if _, err := h.svc.ConsentPage(t.Context(), stale); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("want ErrInvalidRequest for a registration with no reference, got %v", err)
	}
	if _, err := h.svc.Authorize(t.Context(), AuthorizeRequest{
		Registration: stale, CodeChallenge: "chal", ConsentToken: "msack1-anything",
	}); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("a registration with no reference must fail closed at Authorize too, got %v", err)
	}
}

// 🔴 An integrity check the caller can switch off by omitting a field is a claim
// rather than a control. README.md admits the legacy weakness in as many words;
// this is the fix.
func TestCompleteRefusesAnEmptyExpectDigest(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)
	state := h.authorize(t, out)

	_, err := h.svc.Complete(t.Context(), CompleteRequest{
		State: state, Code: "auth-code", CodeVerifier: "verifier", ExpectDigest: "",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("want ErrInvalidRequest for an empty digest, got %v", err)
	}
	if h.oauth.tokenCalls != 0 || h.provider.writes != 0 {
		t.Fatal("a refusal before the exchange must consume and write nothing")
	}
	// Whitespace is not a digest either.
	if _, err := h.svc.Complete(t.Context(), CompleteRequest{
		State: state, Code: "auth-code", CodeVerifier: "verifier", ExpectDigest: "   ",
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("want ErrInvalidRequest for a blank digest, got %v", err)
	}
}

// A state names its own anchor, so pairing it with another domain's reviewed
// digest is refused — and refused BEFORE the authorization code is spent.
func TestCompleteRefusesAStateSealedForADifferentAnchor(t *testing.T) {
	h := newHarness(t)
	first := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	second := h.register(t, lane.OrgPlatformDomain, testOrg, appParent)
	h.publishProof(t, first)
	h.publishProof(t, second)

	// The state is example.net's; the digest is example.com's.
	state := h.authorize(t, second)
	_, err := h.svc.Complete(t.Context(), CompleteRequest{
		State: state, Code: "auth-code", CodeVerifier: "verifier", ExpectDigest: first.Digest,
	})
	// 🔴 AND IT IS ErrPlanChanged, NOT ErrPlanInvalid. plan_invalid's contract is
	// "the plan is wrong and retrying cannot help", which is the wrong sentence
	// for a well-formed plan whose digest simply no longer reproduces — a routing
	// target or a DCV identifier moved under a consent screen rendered minutes
	// ago. The remedy is to re-render and authorize again, and a caller shown
	// "this is a bug" may abandon the domain permanently instead.
	if !errors.Is(err, dnsplan.ErrPlanChanged) {
		t.Fatalf("want ErrPlanChanged for a digest that no longer reproduces, got %v", err)
	}
	if errors.Is(err, dnsplan.ErrPlanInvalid) {
		t.Fatal("a stale reviewed digest must not be reported as a malformed plan")
	}
	if h.oauth.tokenCalls != 0 || h.provider.writes != 0 {
		t.Fatal("nothing may be exchanged or written for a plan that does not reproduce the reviewed digest")
	}

	// Its own digest goes through, which is what makes the refusal above mean
	// something rather than being a broken code path.
	ok, err := h.svc.Complete(t.Context(), CompleteRequest{
		State: state, Code: "auth-code", CodeVerifier: "verifier", ExpectDigest: second.Digest,
	})
	if err != nil || ok.Result != ResultPublished {
		t.Fatalf("the reviewed plan must publish: %v %#v", err, ok)
	}
}

// A state this deployment did not seal is not a state.
func TestCompleteRefusesAStateFromAnotherKeyset(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)

	stranger := newSealer(t, "other")
	state, err := sealed.SealAuthState(stranger, sealed.AuthState{
		Lane: lane.OrgPlatformDomain, Identity: testOrg, Anchor: platformDomain,
		Nonce: "00112233445566778899aabbccddeeff", IssuedAt: nowUnix(),
	})
	if err != nil {
		t.Fatalf("SealAuthState: %v", err)
	}
	if _, err := h.svc.Complete(t.Context(), CompleteRequest{
		State: state, Code: "auth-code", CodeVerifier: "verifier", ExpectDigest: out.Digest,
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("want ErrInvalidRequest, got %v", err)
	}
	if h.oauth.tokenCalls != 0 {
		t.Fatal("nothing may be exchanged for an unopenable state")
	}
}

// The happy path, end to end, with the credential held and the ownership proof
// conspicuously absent from what reached the provider.
func TestCompletePublishesTheDerivedSetAndHoldsTheGrant(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)
	state := h.authorize(t, out)

	pass, err := h.svc.Complete(t.Context(), CompleteRequest{
		State: state, Code: "auth-code", CodeVerifier: "verifier", ExpectDigest: out.Digest,
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if pass.Result != ResultPublished || pass.Failure != nil {
		t.Fatalf("want a clean publish: %#v", pass)
	}
	if pass.SealedToken == "" || pass.KeyID == "" || pass.Revoked {
		t.Fatalf("the grant must come back held: %#v", pass)
	}
	if pass.GrantSeconds != 86400 {
		t.Fatalf("lane 1 holds for 24 hours, got %d seconds", pass.GrantSeconds)
	}
	// Four routing CNAMEs and four DCV pointers; no ownership TXT.
	if len(pass.Published) != 8 {
		t.Fatalf("want 8 published identities, got %d: %v", len(pass.Published), pass.Published)
	}
	for _, name := range h.provider.created {
		if strings.HasPrefix(name, proof.Prefix) {
			t.Fatalf("the ownership proof reached the provider: %q", name)
		}
	}
	// The sealed grant opens only under this registration.
	reg := h.open(t, out.Registration)
	if _, err := h.sealer.Open(pass.SealedToken, GrantAAD(reg)); err != nil {
		t.Fatalf("the held grant must open for its own registration: %v", err)
	}
}

// 🔴 THE CUSTOMER'S STOP CONTROL. Delete the proof and every write stops within
// one pass, with nothing needing to reach MirrorStack — not even their provider.
func TestAdvanceWritesNothingWhenTheProofHasBeenDeleted(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)
	reg := h.open(t, out.Registration)
	held := h.seal(t, "refresh-1", reg)

	// It advances while the proof stands.
	first, err := h.svc.Advance(t.Context(), AdvanceRequest{Registration: out.Registration, SealedToken: held})
	if err != nil || first.Result != ResultPublished {
		t.Fatalf("want a published pass while the proof stands: %v %#v", err, first)
	}
	writesBefore, refreshesBefore := h.provider.writes, h.oauth.refreshCalls

	h.resolver.remove(proof.Prefix + platformDomain)
	stopped, err := h.svc.Advance(t.Context(), AdvanceRequest{Registration: out.Registration, SealedToken: first.SealedToken})
	if err != nil {
		t.Fatalf("a withdrawn proof is an outcome, not an RPC error: %v", err)
	}
	if stopped.Result != ResultStopped {
		t.Fatalf("want %q, got %#v", ResultStopped, stopped)
	}
	if h.provider.writes != writesBefore {
		t.Fatalf("a withdrawn proof must write NOTHING: %d writes", h.provider.writes-writesBefore)
	}
	if h.oauth.refreshCalls != refreshesBefore {
		t.Fatal("a withdrawn proof must not even open the grant, let alone reach the provider")
	}
	if stopped.Failure == nil || stopped.Failure.Code != FailureProofWithdrawn {
		t.Fatalf("the reason must be named: %#v", stopped.Failure)
	}
	if stopped.Revoked {
		t.Fatal("stopping is not revoking — the customer may be fixing a typo, and the grant is theirs to end")
	}
	// The records are still reported, so the customer can see what would be
	// written if they republish.
	if len(stopped.Records) == 0 {
		t.Fatal("a stopped pass must still describe the plan")
	}
}

// 🔴 THE CUSTOMER'S STOP CONTROL, IN EXECUTABLE FORM.
//
// checkProof fails for four reasons and only one of them is an answer about the
// world. These tests pin the three that are NOT: a pass that was never in a
// position to look must refuse rather than publish. Before proofBeforeWriting
// existed, all four folded into a warning string and the pass wrote anyway —
// so a deployment with a nil Resolver published into a customer's zone having
// never read their proof, and deleting it changed nothing, forever.
func TestAPassThatCouldNotLookRefusesRatherThanWriting(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cripple func(*harness)
		want    error
	}{
		{
			name: "no resolver wired",
			// The Resolver field's own comment promises a nil is reported rather
			// than quietly replaced. Describe and Orphans honoured that; the two
			// paths that write did not.
			cripple: func(h *harness) { h.svc.Resolver = nil },
			want:    ErrUnavailable,
		},
		{
			name: "the keyset went away mid-pass",
			// Not a contrivance: the loaders are per-request and re-read their
			// secret on a TTL, so a retired key or a secret store that starts
			// refusing looks exactly like this from inside one call. Without a
			// keyset there is no accept set, so there is nothing to compare a
			// published proof against.
			cripple: func(h *harness) {
				h.svc.Keys = &vanishingKeys{sealer: h.sealer, gone: true}
			},
			want: ErrUnavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
			h.publishProof(t, out)
			reg := h.open(t, out.Registration)
			held := h.seal(t, "refresh-1", reg)
			tc.cripple(h)

			got, err := h.svc.Advance(t.Context(),
				AdvanceRequest{Registration: out.Registration, SealedToken: held})
			if err == nil {
				t.Fatalf("a pass that could not read the proof must REFUSE, got %#v", got)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if h.provider.writes != 0 {
				t.Fatalf("nothing may reach the customer's zone: %d writes", h.provider.writes)
			}
			// A warning inside a published response is exactly what this test
			// exists to forbid: it is invisible to anyone reading the result.
			if got.Result == ResultPublished {
				t.Fatal("refusing must not be spelled as publishing-with-a-warning")
			}
		})
	}
}

// The other half of the asymmetry, and it matters just as much: a resolver that
// timed out is a fault of ours or of the network, not the customer withdrawing
// consent. Stopping on it would let a nameserver blip take a working domain
// down, and the loop would eventually release a live credential over it.
func TestAResolverFailureStillWarnsAndStillPublishes(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)
	reg := h.open(t, out.Registration)
	held := h.seal(t, "refresh-1", reg)

	h.resolver.failWith(proof.Prefix+platformDomain, errors.New("SERVFAIL"))

	got, err := h.svc.Advance(t.Context(),
		AdvanceRequest{Registration: out.Registration, SealedToken: held})
	if err != nil {
		t.Fatalf("a resolver fault is not a refusal: %v", err)
	}
	if got.Result != ResultPublished {
		t.Fatalf("want the pass to proceed on the anchor proven at authorize time, got %#v", got)
	}
	if h.provider.writes == 0 {
		t.Fatal("a resolver blip must not stop a pass that is otherwise fine")
	}
	if len(got.Warnings) == 0 {
		t.Fatal("it must still be visible that the proof could not be read")
	}
}

// lookupFailed is the classifier the rule above turns on. Pinning it directly
// covers the one case the harness cannot reach: an accept set that came back
// empty, which observe refuses so that it cannot be mistaken for a customer who
// has not published yet.
func TestLookupFailedNamesOnlyAnswersAboutTheWorld(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"a resolver that did not answer", errors.New("SERVFAIL"), true},
		{"no keyset or no resolver", fmt.Errorf("%w: nothing wired", ErrUnavailable), false},
		{"an anchor too deep to carry a proof", fmt.Errorf("%w: too deep", ErrInvalidRequest), false},
		{"an empty accept set", fmt.Errorf("%w: no accepted values", observe.ErrObserve), false},
		{"no error at all", nil, false},
	} {
		if got := lookupFailed(tc.err); got != tc.want {
			t.Errorf("%s: lookupFailed(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

// 🔴 THE 2026-08-24 BUG. The provider rotates the refresh token on every use, so
// once the refresh returns, the caller's stored token is already dead. A publish
// failure after that point must still hand back the replacement.
func TestAdvanceReturnsTheRotatedTokenEvenWhenThePublishFails(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)
	reg := h.open(t, out.Registration)
	held := h.seal(t, "refresh-1", reg)

	h.provider.failErr = errors.New("cloudflare 500")
	h.oauth.nextRefresh = "refresh-2"

	pass, err := h.svc.Advance(t.Context(), AdvanceRequest{Registration: out.Registration, SealedToken: held})
	if err != nil {
		t.Fatalf("a post-rotation failure must NOT be an RPC error: %v", err)
	}
	if pass.Result != ResultDeferred || pass.Failure == nil || !pass.Failure.Retry {
		t.Fatalf("a provider blip must defer and be retryable: %#v", pass)
	}
	if !pass.Rotated || pass.SealedToken == "" {
		t.Fatalf("the ROTATED token must come back so the caller can persist it: %#v", pass)
	}
	got, err := h.sealer.Open(pass.SealedToken, GrantAAD(reg))
	if err != nil || got != "refresh-2" {
		t.Fatalf("the returned seal must carry the NEW refresh token, got %q (%v)", got, err)
	}
	if pass.Revoked {
		t.Fatal("a held grant must not be revoked over a retryable failure")
	}
}

// Losing a credential never becomes a stuck domain: it becomes a list of records
// and an instruction.
func TestAdvanceDegradesToManualWithNoGrant(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)

	pass, err := h.svc.Advance(t.Context(), AdvanceRequest{Registration: out.Registration})
	if err != nil {
		t.Fatalf("the manual path is not an error: %v", err)
	}
	if pass.Result != ResultManual || pass.Failure == nil || pass.Failure.Code != FailureNoGrant {
		t.Fatalf("want a manual outcome naming the missing grant: %#v", pass)
	}
	if h.provider.writes != 0 || h.oauth.refreshCalls != 0 {
		t.Fatal("the manual path writes nothing and touches no provider")
	}
	if len(pass.Records) == 0 || pass.Digest == "" {
		t.Fatal("the manual path must carry the exact records to add by hand")
	}
	// A grant this deployment cannot open is dead rather than absent, and the
	// caller has to be able to tell them apart.
	dead, err := h.svc.Advance(t.Context(), AdvanceRequest{
		Registration: out.Registration,
		SealedToken:  h.seal(t, "refresh-1", h.open(t, h.register(t, lane.OrgPlatformDomain, testOrg, appParent).Registration)),
	})
	if err != nil {
		t.Fatalf("an unopenable grant is an outcome: %v", err)
	}
	if dead.Result != ResultManual || dead.Failure == nil || dead.Failure.Code != FailureTokenUnreadable {
		t.Fatalf("a grant sealed for another registration must not open here: %#v", dead)
	}
}

// 🔴 A transient provider failure is NOT the manual path. Telling a customer to
// type seven records into their DNS panel over a five-second blip is the wrong
// answer to the right question.
func TestAdvanceDefersRatherThanGoingManualOnATransientRefreshFailure(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)
	held := h.seal(t, "refresh-1", h.open(t, out.Registration))

	h.oauth.tokenStatus, h.oauth.tokenBody = http.StatusInternalServerError, `{"error":"server_error"}`
	pass, err := h.svc.Advance(t.Context(), AdvanceRequest{Registration: out.Registration, SealedToken: held})
	if err != nil {
		t.Fatalf("a refresh failure is an outcome: %v", err)
	}
	if pass.Result != ResultDeferred || pass.Failure == nil || !pass.Failure.Retry {
		t.Fatalf("an unreachable provider must defer: %#v", pass)
	}

	// A provider that REJECTS the token is a different answer: the grant is dead
	// and the customer is back on the manual path.
	h.oauth.tokenStatus, h.oauth.tokenBody = http.StatusBadRequest, `{"error":"invalid_grant"}`
	dead, err := h.svc.Advance(t.Context(), AdvanceRequest{Registration: out.Registration, SealedToken: held})
	if err != nil {
		t.Fatalf("a rejected grant is an outcome: %v", err)
	}
	if dead.Result != ResultManual || dead.Failure == nil || dead.Failure.Code != FailureInvalidGrant || dead.Failure.Retry {
		t.Fatalf("a rejected refresh token is a dead grant, not a retry: %#v", dead)
	}
}

// 🔴 BindApp's second outcome is not a failure, and the private half neither
// chooses it nor can ask for the first.
func TestBindAppReturnsManualWithTheRecordsWhenNoGrantIsHeld(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgAppDomain, testOrg, appParent)
	h.publishProof(t, out)

	pass, err := h.svc.BindAppToOrgAppDomain(t.Context(), BindAppRequest{
		Registration: out.Registration, Slug: "blog",
	})
	if err != nil {
		t.Fatalf("the manual path is not an error: %v", err)
	}
	if pass.Result != ResultManual || pass.Failure == nil || pass.Failure.Code != FailureNoGrant {
		t.Fatalf("want manual with a reason: %#v", pass)
	}
	if h.provider.writes != 0 {
		t.Fatal("nothing is written on the manual path")
	}
	wantName := "_acme-challenge.blog." + appParent
	wantValue := "blog." + appParent + "." + testDCVUUID + ".dcv.cloudflare.com"
	found := false
	for _, record := range pass.Records {
		if record.Name == wantName {
			found = true
			if record.Value != wantValue {
				t.Fatalf("the DCV pointer must carry the hostname prefix: %q", record.Value)
			}
			if record.Explain == "" {
				t.Fatal("a record somebody is asked to add by hand must say what it is for")
			}
		}
	}
	if !found {
		t.Fatalf("the manual answer must carry the exact record to add: %#v", pass.Records)
	}
}

func TestBindAppPublishesWhenTheGrantIsLive(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgAppDomain, testOrg, appParent)
	h.publishProof(t, out)
	reg := h.open(t, out.Registration)

	pass, err := h.svc.BindAppToOrgAppDomain(t.Context(), BindAppRequest{
		Registration: out.Registration, Slug: "blog", SealedToken: h.seal(t, "refresh-1", reg),
	})
	if err != nil {
		t.Fatalf("BindApp: %v", err)
	}
	if pass.Result != ResultPublished || len(pass.Published) != 1 {
		t.Fatalf("want one published record: %#v", pass)
	}
	// 0 is STANDING, and it is the one lane that gets it: the records this
	// parent exists to write belong to apps that do not exist yet.
	if pass.GrantSeconds != 0 {
		t.Fatalf("the org app domain lane is standing: %d", pass.GrantSeconds)
	}
	if h.provider.created[0] != "_acme-challenge.blog."+appParent {
		t.Fatalf("wrote the wrong record: %v", h.provider.created)
	}
}

// A slug selects WHICH name under a parent already proven. There is no parent to
// select a name under on the other two lanes, so accepting one would be
// inventing authority the design does not grant.
func TestBindAppRefusesEveryOtherLane(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		l        lane.Lane
		identity string
		domain   string
	}{
		{lane.OrgPlatformDomain, testOrg, platformDomain},
		{lane.AppDomain, testApp, appHostname},
	} {
		out := h.register(t, tc.l, tc.identity, tc.domain)
		if _, err := h.svc.BindAppToOrgAppDomain(t.Context(), BindAppRequest{
			Registration: out.Registration, Slug: "blog",
		}); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("%s must refuse a bind, got %v", tc.l, err)
		}
	}
	// And the slug itself cannot spell a name whose meaning it did not choose.
	out := h.register(t, lane.OrgAppDomain, testOrg, appParent)
	for _, slug := range []string{"_acme-challenge", "a.b", "*", ""} {
		if _, err := h.svc.BindAppToOrgAppDomain(t.Context(), BindAppRequest{
			Registration: out.Registration, Slug: slug,
		}); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("slug %q must be refused, got %v", slug, err)
		}
	}
}

// 🔴 Orphans is A REPORT, NEVER A MUTATION, on both of its paths.
func TestOrphansWritesNothing(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)
	reg := h.open(t, out.Registration)

	// With a grant: the customer's own zone is read, and only read.
	report, err := h.svc.Orphans(t.Context(), OrphansRequest{
		Registration: out.Registration, SealedToken: h.seal(t, "refresh-1", reg),
	})
	if err != nil {
		t.Fatalf("Orphans: %v", err)
	}
	if h.provider.writes != 0 {
		t.Fatalf("Orphans wrote %d records", h.provider.writes)
	}
	if h.provider.reads == 0 || report.ReadThrough != "provider" {
		t.Fatalf("want a provider-backed report: reads=%d %#v", h.provider.reads, report)
	}
	if !report.Incomplete {
		t.Fatal("a stateless service cannot enumerate what it wrote under an older derivation, and must say so")
	}
	if report.SealedToken == "" {
		t.Fatal("reading with the grant rotates it, so the replacement must come back")
	}

	// Without one it falls back to public DNS rather than failing, so the report
	// still works for a customer who never authorized or has already revoked.
	public, err := h.svc.Orphans(t.Context(), OrphansRequest{Registration: out.Registration})
	if err != nil {
		t.Fatalf("Orphans without a grant: %v", err)
	}
	if public.ReadThrough != "public-dns" || len(public.Records) == 0 {
		t.Fatalf("want a public-DNS report: %#v", public)
	}
	if h.provider.writes != 0 {
		t.Fatal("no path through Orphans writes")
	}
}

// 🔴 Describe must not judge the ownership proof from the derived item. The item
// carries the value under TODAY's active key; verification accepts one value per
// key. A proof published before a rotation is valid and would be reported absent
// — telling a customer whose domain is working to fix a record that is fine.
func TestDescribeReportsAProofPublishedUnderARotatedKey(t *testing.T) {
	h := newHarnessWithKeys(t, "k1", "k2")
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)

	prover := proof.Prover{Sealer: h.sealer}
	accepted, err := prover.Accepted(lane.OrgPlatformDomain, testOrg, platformDomain)
	if err != nil {
		t.Fatalf("Accepted: %v", err)
	}
	older := ""
	for _, value := range accepted {
		if value != out.Proof.Value {
			older = value
		}
	}
	if older == "" {
		t.Fatal("this test needs a keyset with more than one key")
	}
	// The customer published under the OTHER key and has no reason to revisit it.
	h.resolver.txt[proof.Prefix+platformDomain] = []string{older}

	described, err := h.svc.Describe(t.Context(), DescribeRequest{Registration: out.Registration})
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if !described.Verified || described.Proof.State != string(observe.StatePresent) {
		t.Fatalf("a proof under a rotated key is still a proof: %#v", described.Proof)
	}
	if h.provider.writes != 0 || h.oauth.tokenCalls != 0 {
		t.Fatal("Describe writes nothing and touches no credential")
	}
	// Every other row is still judged, and judged as absent — the fixture
	// publishes none of them.
	for _, record := range described.Records {
		if record.Purpose == string(derive.PurposeOwnership) {
			continue
		}
		if record.State != string(observe.StateAbsent) {
			t.Fatalf("unpublished record %q reported %q", record.Name, record.State)
		}
	}
	if len(described.Records) != len(out.Records) {
		t.Fatalf("describe must report every derived record: %d vs %d", len(described.Records), len(out.Records))
	}
}

// Release revokes refresh token first: revoking it kills the whole grant, where
// revoking only the access token leaves a credential that can mint another.
func TestReleaseRevokesRefreshTokenFirst(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	reg := h.open(t, out.Registration)

	released, err := h.svc.Release(t.Context(), ReleaseRequest{
		Registration: out.Registration, SealedToken: h.seal(t, "refresh-1", reg), Reason: "domain removed",
	})
	if err != nil || !released.Revoked || released.Unreadable {
		t.Fatalf("Release: %v %#v", err, released)
	}
	if len(h.oauth.revokedHints) == 0 || h.oauth.revokedHints[0] != "refresh_token" {
		t.Fatalf("the refresh token must be revoked first: %v", h.oauth.revokedHints)
	}
}

// 🔴 An envelope that cannot be opened is reported as such and never guessed at.
func TestReleaseReportsAnUnreadableEnvelopeRatherThanGuessing(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	elsewhere := h.register(t, lane.OrgPlatformDomain, testOrg, appParent)

	released, err := h.svc.Release(t.Context(), ReleaseRequest{
		Registration: out.Registration,
		SealedToken:  h.seal(t, "refresh-1", h.open(t, elsewhere.Registration)),
	})
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if !released.Unreadable || released.Revoked {
		t.Fatalf("want unreadable and nothing sent: %#v", released)
	}
	if h.oauth.revokeCalls != 0 {
		t.Fatal("a credential we cannot prove is this row's must not be sent to the provider")
	}
}

// 🔴 A ciphertext must not move between registrations, and the LANE is part of
// what binds it — one org can connect one domain on two lanes, and those are two
// consents, two proofs and two grants.
func TestGrantAADBindsToTheWholeRegistration(t *testing.T) {
	sealer := newSealer(t, "k1")
	base := sealed.Registration{Lane: lane.OrgPlatformDomain, Identity: testOrg, Anchor: platformDomain}
	aad := GrantAAD(base)
	if aad != "ms-dns-grant/v1\x00org_platform_domain\x00"+testOrg+"\x00"+platformDomain {
		t.Fatalf("AAD drift: %q", aad)
	}
	envelope, _, err := sealer.Seal("refresh-1", aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	for _, other := range []sealed.Registration{
		{Lane: lane.OrgAppDomain, Identity: testOrg, Anchor: platformDomain},
		{Lane: lane.OrgPlatformDomain, Identity: testApp, Anchor: platformDomain},
		{Lane: lane.OrgPlatformDomain, Identity: testOrg, Anchor: appParent},
	} {
		if _, err := sealer.Open(envelope, GrantAAD(other)); err == nil {
			t.Fatalf("a grant opened under a different registration: %#v", other)
		}
	}
	if got, err := sealer.Open(envelope, aad); err != nil || got != "refresh-1" {
		t.Fatalf("its own registration must open it: %q %v", got, err)
	}
}

// Capabilities publishes what this deployment would put in a zone, and the clock
// it would do it on, before anything is asked of anyone.
func TestCapabilitiesPublishesTheTargetsAndTheClock(t *testing.T) {
	h := newHarness(t)
	caps := h.svc.Capabilities(t.Context())
	if !caps.Available || !caps.CanHold || caps.Provider != "stub" {
		t.Fatalf("capabilities: %#v", caps)
	}
	if caps.OrgRoutingTarget == "" || caps.AppRoutingTarget == "" || caps.DCVDelegationUUID == "" {
		t.Fatal("a customer must be able to read the values we will ask them to accept")
	}
	if caps.ConfigError != "" {
		t.Fatalf("the fixture config is meant to be valid: %s", caps.ConfigError)
	}
	if caps.IntervalSeconds <= 0 || caps.MinIntervalSeconds <= 0 {
		t.Fatalf("the loop's clock must be published: %#v", caps)
	}
	if len(caps.Lanes) != 3 {
		t.Fatalf("all three lanes are described together, deliberately: %#v", caps.Lanes)
	}
	for _, l := range caps.Lanes {
		if l.Lane == string(lane.OrgAppDomain) && !l.ConsentPage {
			t.Fatal("the wildcard lane serves this service's own consent page and must say so")
		}
	}
}

// Verify recomputes the value it looks for; a caller cannot supply one.
func TestVerifyRecomputesTheValueItLooksFor(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.AppDomain, testApp, appHostname)

	absent, err := h.svc.Verify(t.Context(), VerifyRequest{Registration: out.Registration})
	if err != nil {
		t.Fatalf("an unpublished proof is a state, not an error: %v", err)
	}
	if absent.Verified || absent.Expected != out.Proof.Value || absent.Name != proof.Prefix+appHostname {
		t.Fatalf("verify: %#v", absent)
	}

	h.publishProof(t, out)
	present, err := h.svc.Verify(t.Context(), VerifyRequest{Registration: out.Registration})
	if err != nil || !present.Verified || present.Proof.State != string(observe.StatePresent) {
		t.Fatalf("want a verified proof: %v %#v", err, present)
	}
}

// A deployment with no keyset cannot compute a proof, seal a registration or
// open one — and says so rather than deriving a plan whose ownership row is a
// constant shared by every customer.
func TestADeploymentWithNoKeysetRefusesEveryEntryPoint(t *testing.T) {
	h := newHarness(t)
	h.svc.Keys = stubKeys{}
	if _, err := h.svc.AddOrgPlatformDomain(t.Context(), AddOrgPlatformDomainRequest{
		OrgID: testOrg, Domain: platformDomain,
	}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	if _, err := h.svc.Advance(t.Context(), AdvanceRequest{Registration: "anything"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

// 🔴 RELAYED RECORDS DO NOT MOVE THE DIGEST, AND THAT IS WHY THE DIGEST IS
// COMPUTED OVER THE DERIVED SET ALONE.
//
// AWS populates a validation record minutes after it returns an ARN and
// Cloudflare mints a serving proof when a custom hostname is created, so both
// appear AFTER the customer reviewed the plan. If they were inside the digest,
// every customer mid-connect would be told the plan had changed — for records
// nobody could have shown them.
func TestRelayedRecordsArePublishedWithoutMovingTheReviewedDigest(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)
	state := h.authorize(t, out)

	acm := dnsplan.Record{Type: "CNAME", Name: "_abc123.api." + platformDomain, Value: "xyz.acm-validations.aws"}
	ca := &fakeCA{records: []dnsplan.Record{acm}}
	edge := &fakeEdge{proofs: map[string]dnsplan.Record{
		// Partial is the NORMAL answer: a lane-1 registration creates four custom
		// hostnames and on any given pass some exist and some do not.
		"account." + platformDomain: {Type: "TXT", Name: "_cf-custom-hostname.account." + platformDomain, Value: "proof-a"},
		"api." + platformDomain:     {Type: "TXT", Name: "_cf-custom-hostname.api." + platformDomain, Value: "proof-b"},
	}}
	h.svc.Certificates, h.svc.Edge = ca, edge

	pass, err := h.svc.Complete(t.Context(), CompleteRequest{
		State: state, Code: "auth-code", CodeVerifier: "verifier", ExpectDigest: out.Digest,
	})
	if err != nil {
		t.Fatalf("the digest taken before the relays answered must still validate: %v", err)
	}
	if pass.Result != ResultPublished || pass.Digest != out.Digest {
		t.Fatalf("the reviewable digest must not move: %#v", pass)
	}
	// 8 derived + 1 ACM + 2 serving proofs.
	if len(pass.Published) != 11 {
		t.Fatalf("want 11 published identities, got %d: %v", len(pass.Published), pass.Published)
	}

	// 🔴 cdn is never asked of the certificate authority: the CDN worker
	// terminates TLS for that hostname, so no AWS certificate covers it.
	if len(ca.asked) != 1 || strings.Join(ca.asked[0], ",") !=
		"account."+platformDomain+",api."+platformDomain+",apps."+platformDomain {
		t.Fatalf("the certificate authority was asked about the wrong hosts: %v", ca.asked)
	}
	if len(edge.asked) != 4 {
		t.Fatalf("every host owes a serving proof: %v", edge.asked)
	}

	// Each relayed row is attributed: relayed, with the right purpose, and
	// grouped under the hostname it SERVES rather than its own name.
	seen := map[string]RecordView{}
	for _, record := range pass.Records {
		seen[record.Name] = record
	}
	if got := seen[acm.Name]; got.Source != string(derive.SourceRelayed) ||
		got.Purpose != string(derive.PurposeCertACM) || got.Host != "api."+platformDomain {
		t.Fatalf("the ACM row is misattributed: %#v", got)
	}
	if got := seen["_cf-custom-hostname.api."+platformDomain]; got.Source != string(derive.SourceRelayed) ||
		got.Purpose != string(derive.PurposeServing) || got.Host != "api."+platformDomain {
		t.Fatalf("the serving row is misattributed: %#v", got)
	}
}

// 🔴 A relay failure is a WARNING, not a refusal. Record 6 is derived here and is
// what gets the CLOUDFLARE EDGE certificate issued, so the lane still gets TLS
// at the edge when the relay is unreadable — lane 1's AWS certificate is a
// second one, and it stays unvalidated until record 5 is relayed. Blocking
// record 6 on an ACM permission problem on our side would leave a customer's
// domain unrouted for a reason that has nothing to do with them.
func TestARelayFailureWarnsAndStillPublishesWhatIsDerived(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)
	h.svc.Certificates = &fakeCA{err: errors.New("access denied")}
	h.svc.Edge = &fakeEdge{err: errors.New("cloudflare 502")}

	pass, err := h.svc.Advance(t.Context(), AdvanceRequest{
		Registration: out.Registration, SealedToken: h.seal(t, "refresh-1", h.open(t, out.Registration)),
	})
	if err != nil {
		t.Fatalf("an unreadable upstream must not fail the pass: %v", err)
	}
	if pass.Result != ResultPublished || len(pass.Published) != 8 {
		t.Fatalf("the derived records must still publish: %#v", pass)
	}
	if len(pass.Warnings) != 2 {
		t.Fatalf("both upstream failures must be reported rather than swallowed: %v", pass.Warnings)
	}
}

// The wildcard is not a custom hostname on this account, so nothing is asked of
// the edge for the parent itself — the proofs are minted per app, at deploy time.
func TestTheWildcardParentAsksTheEdgeNothingAndABoundAppAsksForItself(t *testing.T) {
	h := newHarness(t)
	edge := &fakeEdge{proofs: map[string]dnsplan.Record{}}
	h.svc.Edge = edge
	out := h.register(t, lane.OrgAppDomain, testOrg, appParent)
	h.publishProof(t, out)

	if _, err := h.svc.Advance(t.Context(), AdvanceRequest{Registration: out.Registration}); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	if len(edge.asked) != 0 {
		t.Fatalf("a wildcard is not a custom hostname and must not be asked about: %v", edge.asked)
	}
	if _, err := h.svc.BindAppToOrgAppDomain(t.Context(), BindAppRequest{
		Registration: out.Registration, Slug: "blog",
	}); err != nil {
		t.Fatalf("BindApp: %v", err)
	}
	if len(edge.asked) != 1 || edge.asked[0] != "blog."+appParent {
		t.Fatalf("a bound app owes its own serving proof: %v", edge.asked)
	}
}

// A state minted without the consent page must not complete either. The
// acknowledgement is sealed INTO the state precisely so a later check can rely
// on it, and a state written by a build without the gate would otherwise sail
// straight past Authorize's refusal.
func TestCompleteRefusesAWildcardStateThatWasNeverAcknowledged(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgAppDomain, testOrg, appParent)
	h.publishProof(t, out)

	state, err := sealed.SealAuthState(h.sealer, sealed.AuthState{
		Lane: lane.OrgAppDomain, Identity: testOrg, Anchor: appParent,
		Nonce: "00112233445566778899aabbccddeeff", IssuedAt: nowUnix(), ConsentAck: false,
	})
	if err != nil {
		t.Fatalf("SealAuthState: %v", err)
	}
	if _, err := h.svc.Complete(t.Context(), CompleteRequest{
		State: state, Code: "auth-code", CodeVerifier: "verifier", ExpectDigest: out.Digest,
	}); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("want ErrConsentRequired, got %v", err)
	}
	if h.oauth.tokenCalls != 0 {
		t.Fatal("nothing may be exchanged for an unacknowledged wildcard")
	}
}

// An expired state is distinguished from a corrupt one, because it is the only
// refusal that is NORMAL: a customer who left the consent screen open over lunch
// should be told to start again, not shown the same message as a tampered value.
func TestAnExpiredStateIsReportedAsExpired(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)

	state, err := sealed.SealAuthState(h.sealer, sealed.AuthState{
		Lane: lane.OrgPlatformDomain, Identity: testOrg, Anchor: platformDomain,
		Nonce:    "00112233445566778899aabbccddeeff",
		IssuedAt: nowUnix() - int64(2*sealed.AuthStateTTL/time.Second),
	})
	if err != nil {
		t.Fatalf("SealAuthState: %v", err)
	}
	_, err = h.svc.Complete(t.Context(), CompleteRequest{
		State: state, Code: "auth-code", CodeVerifier: "verifier", ExpectDigest: out.Digest,
	})
	if !errors.Is(err, sealed.ErrExpired) {
		t.Fatalf("want sealed.ErrExpired, got %v", err)
	}
}

// 🔴 A refusal is split by AUDIENCE. A domain that cannot be connected is the
// caller's problem; a deployment whose routing configuration is incomplete is an
// operator's. Reporting the second as an invalid request sends somebody to
// re-read a request that was fine.
func TestARefusalIsSplitByAudience(t *testing.T) {
	h := newHarness(t)
	// A MirrorStack name has no customer at the other end.
	if _, err := h.svc.AddOrgPlatformDomain(t.Context(), AddOrgPlatformDomainRequest{
		OrgID: testOrg, Domain: "tenant.mirrorstack.ai",
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("want ErrInvalidRequest for a reserved domain, got %v", err)
	}
	// An id that is not a canonical UUID is the caller's too.
	if _, err := h.svc.AddOrgPlatformDomain(t.Context(), AddOrgPlatformDomainRequest{
		OrgID: "not-a-uuid", Domain: platformDomain,
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("want ErrInvalidRequest for a malformed id, got %v", err)
	}
	// A deployment with no delegation identifier can derive no certificate
	// pointer, and that is not the caller's fault.
	h.svc.Derive.DCVDelegationUUID = ""
	if _, err := h.svc.AddOrgPlatformDomain(t.Context(), AddOrgPlatformDomainRequest{
		OrgID: testOrg, Domain: platformDomain,
	}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable for an incomplete deployment, got %v", err)
	}
	if caps := h.svc.Capabilities(t.Context()); caps.ConfigError == "" {
		t.Fatal("a misconfigured deployment must look different from an unconfigured one")
	}
}

// Orphans reads the customer's own zone and reports each name's state in
// internal/observe's vocabulary, so one report can be read against the other.
func TestOrphansReportsWhatIsActuallyInTheZone(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)
	reg := h.open(t, out.Registration)
	h.provider.live = map[string][]dnsprovider.LiveRecord{
		"account." + platformDomain: {{ID: "1", Type: "CNAME", Name: "account." + platformDomain, Value: "connect.mirrorstack.ai"}},
		"api." + platformDomain:     {{ID: "2", Type: "CNAME", Name: "api." + platformDomain, Value: "somewhere.else.example"}},
	}

	report, err := h.svc.Orphans(t.Context(), OrphansRequest{
		Registration: out.Registration, SealedToken: h.seal(t, "refresh-1", reg),
	})
	if err != nil {
		t.Fatalf("Orphans: %v", err)
	}
	states := map[string]string{}
	for _, record := range report.Records {
		states[record.Name] = record.State
	}
	if states["account."+platformDomain] != string(observe.StatePresent) {
		t.Fatalf("a record still in the zone is present: %v", states)
	}
	// A CNAME is exclusive at its owner, so somebody else's answer there is a
	// conflict rather than an absence.
	if states["api."+platformDomain] != string(observe.StateConflicting) {
		t.Fatalf("a foreign CNAME at a planned name is conflicting: %v", states)
	}
	if states["apps."+platformDomain] != string(observe.StateAbsent) {
		t.Fatalf("a record that has gone is absent: %v", states)
	}
	if h.provider.writes != 0 {
		t.Fatal("Orphans does not write")
	}
}

// The two guards on the write set are unreachable through the public API — the
// merged plan always contains the reviewed one — so they are exercised directly.
// They are retained for dnsplan.Digest's reason: a guard that can only fire after
// a future edit is the one worth keeping.
func TestTheWriteSetGuardsFailClosed(t *testing.T) {
	reg := sealed.Registration{Lane: lane.AppDomain, Identity: testApp, Anchor: appHostname}
	routing := derive.Item{
		Record: dnsplan.Record{Type: "CNAME", Name: appHostname, Value: "connect.mirrorstack.app"},
		Source: derive.SourceDerived, Purpose: derive.PurposeRouting,
	}
	review, err := reviewSnapshot(reg.Lane, reg.Identity, derive.Plan{
		Lane: reg.Lane, Anchor: appHostname, Items: []derive.Item{routing},
	})
	if err != nil {
		t.Fatalf("reviewSnapshot: %v", err)
	}
	// A write set that no longer covers the reviewed plan is a plan the customer
	// did not see.
	_, _, err = writeSnapshot(reg, review, derive.Plan{
		Lane: reg.Lane, Anchor: appHostname, Items: []derive.Item{{
			Record: dnsplan.Record{Type: "CNAME", Name: appHostname, Value: "somewhere.else.example"},
			Source: derive.SourceDerived, Purpose: derive.PurposeRouting,
		}},
	})
	if !errors.Is(err, dnsplan.ErrPlanChanged) {
		t.Fatalf("want ErrPlanChanged, got %v", err)
	}
	// A plan with nothing publishable in it yet is a WAIT, not a fault.
	_, failure, err := writeSnapshot(reg, review, derive.Plan{Lane: reg.Lane, Anchor: appHostname})
	if err != nil || failure == nil || failure.Code != FailurePlanPreparing || !failure.Retry {
		t.Fatalf("want a retryable preparing failure, got %#v %v", failure, err)
	}
}

// 🔴 UNKNOWN MEANS RETRY. Defaulting to "dead" releases a working customer
// credential over a transient blip, and a released grant cannot be recovered
// without sending the customer back through consent.
func TestUnknownPublishFailuresAreRetryable(t *testing.T) {
	if f := publishFailure(errors.New("something nobody has seen before")); !f.Retry || f.Code != FailureProvider {
		t.Fatalf("an unrecognised failure must be a retryable provider failure: %#v", f)
	}
	for name, err := range map[string]error{
		"containment": fmt.Errorf("%w: x", dnsplan.ErrAnchorEscape),
		"conflict":    fmt.Errorf("%w: x", reconcile.ErrConflictingPlan),
		"name in use": fmt.Errorf("%w: x", reconcile.ErrNameInUse),
	} {
		if f := publishFailure(err); f.Retry {
			t.Fatalf("%s is not retryable — the same plan cannot start passing: %#v", name, f)
		}
	}
	if f := publishFailure(fmt.Errorf("%w: x", dnsplan.ErrPlanPreparing)); !f.Retry ||
		f.Code != FailurePlanPreparing {
		t.Fatalf("a preparing plan is a wait: %#v", f)
	}
}

// 🔴 THE ASYMMETRY, AND IT IS THE POINT OF checkProof.
//
// GRANTING authority requires a positive answer: a lookup that did not complete
// is not a proof, and retrying an authorization thirty seconds later costs
// nothing. CONTINUING to exercise authority stops only on a NEGATIVE answer: a
// registration is stopped on an answer, never on a failure to get one. Folding
// the two together in either direction is a real outage — one way a nameserver
// blip becomes a customer saying no and the loop eventually releases a live
// credential; the other way a customer saying no is ignored while our resolver
// is unwell.
func TestALookupThatDidNotCompleteIsNeitherProvenNorWithdrawn(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)
	held := h.seal(t, "refresh-1", h.open(t, out.Registration))

	// The proof IS published; our resolver simply cannot answer right now.
	h.resolver.fail[proof.Prefix+platformDomain] = &net.DNSError{
		Err: "server misbehaving", Name: proof.Prefix + platformDomain, IsTemporary: true,
	}

	pass, err := h.svc.Advance(t.Context(), AdvanceRequest{Registration: out.Registration, SealedToken: held})
	if err != nil {
		t.Fatalf("a pass is not failed by a resolver blip: %v", err)
	}
	if pass.Result != ResultPublished {
		t.Fatalf("an unknown answer must not be read as a withdrawal: %#v", pass)
	}
	if len(pass.Warnings) == 0 {
		t.Fatal("the pass proceeded on an unread proof and must say so")
	}

	// Authorize goes the other way, and the error must not be ErrNotProven: a
	// console that showed "publish this record" to a customer who already had
	// would be the wrong screen for the wrong reason.
	_, err = h.svc.Authorize(t.Context(), AuthorizeRequest{
		Registration: out.Registration, CodeChallenge: "chal",
	})
	if err == nil {
		t.Fatal("authorization must not be granted on an answer we did not get")
	}
	if errors.Is(err, ErrNotProven) {
		t.Fatalf("a failed lookup is not an absent proof: %v", err)
	}
}

// 🔴 ZERO MEANS STANDING, SO AN UNRECOGNISED LANE MUST NEVER REPORT ZERO. It
// reports a negative, which a caller adds to `now` to get an expiry in the PAST
// — holding a grant that is already dead. Clamping it here would throw away the
// one answer lane.GrantLifetime deliberately made impossible to get wrong.
func TestGrantSecondsNeverFailsOpenOnAnUnknownLane(t *testing.T) {
	if got := grantSeconds(lane.OrgAppDomain); got != 0 {
		t.Fatalf("the standing lane is 0 seconds, got %d", got)
	}
	for _, l := range []lane.Lane{lane.OrgPlatformDomain, lane.AppDomain} {
		if got := grantSeconds(l); got != 86400 {
			t.Fatalf("%s holds for 24 hours, got %d", l, got)
		}
	}
	if got := grantSeconds(lane.Lane("a_lane_this_build_does_not_know")); got >= 0 {
		t.Fatalf("an unrecognised lane must not report a usable lifetime, got %d", got)
	}
}

// zoneReader is what makes "a report, never a mutation" a property of the type.
// Widening it is the visible act this test exists to force.
func TestTheOrphansProviderViewCannotWrite(t *testing.T) {
	typ := reflect.TypeOf((*zoneReader)(nil)).Elem()
	allowed := map[string]bool{"FindZone": true, "ListRecordsAt": true, "SameValue": true}
	for i := 0; i < typ.NumMethod(); i++ {
		if !allowed[typ.Method(i).Name] {
			t.Fatalf("zoneReader.%s is not a read: Orphans must not be able to reach a mutation",
				typ.Method(i).Name)
		}
	}
	if typ.NumMethod() != len(allowed) {
		t.Fatalf("zoneReader has %d methods, want %d", typ.NumMethod(), len(allowed))
	}
}

// 🔴 THE 2026-08-24 FAILURE, IN THE FUNCTION THAT ONLY READS. Reading the zone
// through the customer's grant REFRESHES it, so the caller's stored token is
// dead the moment Orphans touches the provider. If the replacement cannot be
// sealed there is nothing to hand back, and a report that returned rotated:true
// with an empty sealedToken and no failure would leave a live grant at
// Cloudflare that nothing in MirrorStack could ever release.
func TestOrphansRevokesARotatedGrantItCannotHold(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)
	held := h.seal(t, "refresh-1", h.open(t, out.Registration))

	keys := &vanishingKeys{sealer: h.sealer}
	h.svc.Keys = keys
	h.oauth.nextRefresh = "refresh-2"
	// The keyset disappears while the refresh is in flight: everything before it
	// opened normally, and the rotated token then cannot be sealed.
	h.oauth.onToken = func() { keys.gone = true }

	report, err := h.svc.Orphans(t.Context(), OrphansRequest{
		Registration: out.Registration, SealedToken: held,
	})
	if err != nil {
		t.Fatalf("a grant that cannot be held is an outcome, not an RPC error: %v", err)
	}
	if !report.Rotated || report.SealedToken != "" {
		t.Fatalf("the grant rotated and could not be sealed: %#v", report)
	}
	if report.Failure == nil || report.Failure.Code != FailureResealFailed || report.Failure.Retry {
		t.Fatalf("the caller must be told the grant is gone and why: %#v", report.Failure)
	}
	if !report.Revoked {
		t.Fatal("a grant nobody can record must not be left alive at the provider")
	}
	if len(h.oauth.revokedHints) == 0 || h.oauth.revokedHints[0] != "refresh_token" {
		t.Fatalf("the refresh token must be revoked first: %v", h.oauth.revokedHints)
	}
	// The report itself still answers, from public DNS, and still writes nothing.
	if report.ReadThrough != "public-dns" || len(report.Records) == 0 {
		t.Fatalf("the report must degrade to public DNS rather than disappear: %#v", report)
	}
	if h.provider.writes != 0 {
		t.Fatal("no path through Orphans writes")
	}
}

// 🔴 A FAILED LOOKUP IS A FACT ABOUT THE WORLD, NOT A FAULT IN THE REQUEST.
// observe.Proof populates the observation on the error path precisely so a
// caller can render what was seen; returning an RPC error throws it away at the
// transport and answers the customer's question with "internal".
func TestVerifyReportsAFailedLookupInsteadOfDiscardingTheObservation(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.AppDomain, testApp, appHostname)
	h.publishProof(t, out)

	// The proof IS published; our resolver simply cannot answer right now.
	h.resolver.fail[proof.Prefix+appHostname] = &net.DNSError{
		Err: "server misbehaving", Name: proof.Prefix + appHostname, IsTemporary: true,
	}

	got, err := h.svc.Verify(t.Context(), VerifyRequest{Registration: out.Registration})
	if err != nil {
		t.Fatalf("a resolver failure is an answer about the world: %v", err)
	}
	if got.Verified {
		t.Fatal("nothing may report a proof as present on an answer that never arrived")
	}
	if !got.Unresolved {
		t.Fatal("verified=false must be distinguishable from \"we could not look\"")
	}
	if got.Proof.State != string(observe.StateUnknown) {
		t.Fatalf("an unread proof is unknown, never absent: %#v", got.Proof)
	}
	if got.Name == "" || got.Expected == "" || got.Proof.Explain == "" {
		t.Fatalf("the name, the value to publish and what was seen must survive: %#v", got)
	}

	// A deployment that could not look at all is still an RPC error: a report
	// about a customer's zone from a service in no position to look is not one.
	h.svc.Resolver = nil
	if _, err := h.svc.Verify(t.Context(), VerifyRequest{Registration: out.Registration}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable when this deployment has no resolver, got %v", err)
	}
}

// ─── harness ────────────────────────────────────────────────────────────────

type harness struct {
	svc      *Service
	sealer   *grantcrypto.Sealer
	resolver *fakeResolver
	provider *recordingProvider
	oauth    *oauthServer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWithKeys(t, "k1")
}

func newHarnessWithKeys(t *testing.T, ids ...string) *harness {
	t.Helper()
	sealer := newSealer(t, ids...)
	resolver := &fakeResolver{
		txt: map[string][]string{}, cname: map[string]string{}, fail: map[string]error{},
	}
	provider := &recordingProvider{}
	oauth := &oauthServer{}
	svc := &Service{
		Keys:      stubKeys{sealer: sealer},
		Publisher: reconcile.Publisher{Provider: provider},
		Resolver:  resolver,
		Derive: derive.Config{
			OrgRoutingTarget:  "connect.mirrorstack.ai",
			AppRoutingTarget:  "connect.mirrorstack.app",
			DCVDelegationUUID: testDCVUUID,
			ReservedSuffixes:  []string{"mirrorstack.ai", "mirrorstack.app"},
		},
	}
	svc.OAuth, svc.HTTPClient = oauth.start(t)
	return &harness{svc: svc, sealer: sealer, resolver: resolver, provider: provider, oauth: oauth}
}

func (h *harness) register(t *testing.T, l lane.Lane, identity, domain string) RegisteredResponse {
	t.Helper()
	var out RegisteredResponse
	var err error
	switch l {
	case lane.OrgPlatformDomain:
		out, err = h.svc.AddOrgPlatformDomain(t.Context(), AddOrgPlatformDomainRequest{OrgID: identity, Domain: domain})
	case lane.OrgAppDomain:
		out, err = h.svc.AddOrgAppDomain(t.Context(), AddOrgAppDomainRequest{OrgID: identity, Domain: domain})
	case lane.AppDomain:
		out, err = h.svc.AddAppDomain(t.Context(), AddAppDomainRequest{AppID: identity, Hostname: domain})
	}
	if err != nil {
		t.Fatalf("register %s %s: %v", l, domain, err)
	}
	return out
}

// publishProof puts the value the customer was told to publish into the fake
// zone. It uses the RESPONSE's value rather than recomputing one, so a test
// cannot pass by agreeing with itself about a derivation.
func (h *harness) publishProof(t *testing.T, out RegisteredResponse) {
	t.Helper()
	h.resolver.txt[out.Proof.Name] = []string{out.Proof.Value}
}

func (h *harness) open(t *testing.T, envelope string) sealed.Registration {
	t.Helper()
	reg, err := sealed.OpenRegistration(h.sealer, envelope)
	if err != nil {
		t.Fatalf("OpenRegistration: %v", err)
	}
	return reg
}

func (h *harness) seal(t *testing.T, refresh string, reg sealed.Registration) string {
	t.Helper()
	envelope, _, err := h.sealer.Seal(refresh, GrantAAD(reg))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return envelope
}

func (h *harness) authorize(t *testing.T, out RegisteredResponse) string {
	t.Helper()
	authorized, err := h.svc.Authorize(t.Context(), AuthorizeRequest{
		Registration: out.Registration, CodeChallenge: "chal",
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	return authorized.State
}

// newSealer derives key material from the key ID rather than from its position,
// so a rotation fixture that reorders ids still holds identical bytes — the same
// property grantcrypto's own tests rely on, and the reason
// TestDescribeReportsAProofPublishedUnderARotatedKey means anything.
func newSealer(t *testing.T, ids ...string) *grantcrypto.Sealer {
	t.Helper()
	if len(ids) == 0 {
		t.Fatal("a keyset needs at least one key")
	}
	entries := make([]string, 0, len(ids))
	for _, id := range ids {
		raw := make([]byte, grantcrypto.KeySize)
		for i := range raw {
			raw[i] = id[i%len(id)] ^ byte(i)
		}
		entries = append(entries, fmt.Sprintf("%q:%q", id, base64.StdEncoding.EncodeToString(raw)))
	}
	keys, err := grantcrypto.ParseKeyset(fmt.Sprintf(`{"active":%q,"keys":{%s}}`, ids[0], strings.Join(entries, ",")))
	if err != nil {
		t.Fatalf("ParseKeyset: %v", err)
	}
	sealer, err := grantcrypto.NewSealer(keys)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return sealer
}

type stubKeys struct{ sealer *grantcrypto.Sealer }

func (s stubKeys) Sealer(context.Context) *grantcrypto.Sealer { return s.sealer }

// vanishingKeys stops handing out a sealer once gone is set.
//
// It is the only way to make sealing FAIL: a Sealer holding a key cannot fail to
// seal a non-empty value, so the failure has to come from the keyset not being
// there. That is a real state rather than a contrivance — the loaders are
// per-request and re-read their secret on a TTL, so a key retired, a secret
// store that starts refusing, or a rotation mid-pass all look exactly like this
// from inside one call.
type vanishingKeys struct {
	sealer *grantcrypto.Sealer
	gone   bool
}

func (v *vanishingKeys) Sealer(context.Context) *grantcrypto.Sealer {
	if v.gone {
		return nil
	}
	return v.sealer
}

type stubOAuth struct{ cfg *cfoauth.Config }

func (s stubOAuth) Config(context.Context) *cfoauth.Config { return s.cfg }

// fakeResolver answers from a map. No test in this package resolves a real name:
// the whole safety story here is meant to be checkable without a network.
type fakeResolver struct {
	mu    sync.RWMutex
	txt   map[string][]string
	cname map[string]string

	// fail answers a name with something OTHER than absence — a SERVFAIL or a
	// timeout. It is the state internal/observe calls unknown, and the one the
	// asymmetry in checkProof turns on.
	fail map[string]error
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if err, ok := f.fail[dnsplan.NormalizeName(name)]; ok {
		return nil, err
	}
	if values, ok := f.txt[dnsplan.NormalizeName(name)]; ok {
		return values, nil
	}
	return nil, notFound(name)
}

func (f *fakeResolver) LookupCNAME(_ context.Context, name string) (string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if err, ok := f.fail[dnsplan.NormalizeName(name)]; ok {
		return "", err
	}
	if value, ok := f.cname[dnsplan.NormalizeName(name)]; ok {
		return value, nil
	}
	return "", notFound(name)
}

// failWith makes a name answer with something OTHER than absence — the state
// internal/observe calls unknown, and the one half of checkProof's asymmetry
// that must NOT stop a pass.
func (f *fakeResolver) failWith(name string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[dnsplan.NormalizeName(name)] = err
}

func (f *fakeResolver) remove(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.txt, dnsplan.NormalizeName(name))
}

// notFound is how a resolver spells NXDOMAIN, and also "the name exists but
// holds no record of this type". internal/observe recognises exactly this and
// nothing else as absence.
func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// recordingProvider counts what reached the customer's zone. Writes are what the
// tests above assert on: several of them exist only to prove a number is zero.
type recordingProvider struct {
	writes  int
	reads   int
	created []string
	failErr error

	// live is what the zone already holds, keyed by owner name. Nil means an
	// empty zone, which is what most tests want.
	live map[string][]dnsprovider.LiveRecord
}

func (r *recordingProvider) Name() string { return "stub" }

func (r *recordingProvider) FindZone(context.Context, string, string) (string, error) {
	return "zone-1", nil
}

func (r *recordingProvider) ListRecordsAt(_ context.Context, _, _, name string) ([]dnsprovider.LiveRecord, error) {
	r.reads++
	return r.live[dnsplan.NormalizeName(name)], nil
}

func (r *recordingProvider) CreateRecord(_ context.Context, _, _ string, desired dnsprovider.Desired) (string, error) {
	r.writes++
	if r.failErr != nil {
		return "", r.failErr
	}
	r.created = append(r.created, desired.Name)
	return "record-1", nil
}

func (r *recordingProvider) PatchRecord(context.Context, string, string, string, dnsprovider.Desired) error {
	r.writes++
	return r.failErr
}

func (r *recordingProvider) SameValue(_, live, desired string) bool { return live == desired }
func (r *recordingProvider) IsDuplicate(error) bool                 { return false }
func (r *recordingProvider) IsAmbiguous(error) bool                 { return false }

// oauthServer answers token, refresh and revoke, and records what it saw.
type oauthServer struct {
	tokenCalls   int
	refreshCalls int
	revokeCalls  int
	revokedHints []string
	nextRefresh  string
	tokenStatus  int
	tokenBody    string

	// onToken fires while a token or refresh request is being served, which is
	// the only place a test can change the world at the exact moment a pass has
	// consumed a credential and not yet stored the replacement.
	onToken func()
}

func (o *oauthServer) start(t *testing.T) (oauthLoader, *http.Client) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if strings.HasSuffix(r.URL.Path, "/revoke") {
			o.revokeCalls++
			o.revokedHints = append(o.revokedHints, r.Form.Get("token_type_hint"))
			w.WriteHeader(http.StatusOK)
			return
		}
		o.tokenCalls++
		if r.Form.Get("grant_type") == "refresh_token" {
			o.refreshCalls++
		}
		if o.onToken != nil {
			o.onToken()
		}
		if o.tokenStatus != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(o.tokenStatus)
			_, _ = w.Write([]byte(o.tokenBody))
			return
		}
		refresh := o.nextRefresh
		if refresh == "" {
			refresh = "refresh-1"
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"access-1","refresh_token":%q,"token_type":"bearer","expires_in":3600}`, refresh)
	}))
	t.Cleanup(ts.Close)
	return stubOAuth{cfg: &cfoauth.Config{
		Config: oauth2.Config{
			ClientID: "cid", ClientSecret: "csec", RedirectURL: "https://account.example/cb",
			Scopes: []string{"zone.read", "dns.write", "offline_access"},
			Endpoint: oauth2.Endpoint{
				AuthURL: ts.URL + "/auth", TokenURL: ts.URL + "/token", AuthStyle: oauth2.AuthStyleInParams,
			},
		},
		RevokeURL: ts.URL + "/revoke", AuthMethod: cfoauth.AuthClientSecretPost,
	}}, ts.Client()
}

func nowUnix() int64 { return time.Now().Unix() }

// fakeCA and fakeEdge are the two upstreams. Neither is reachable over a
// network in a test, and both record what they were ASKED — which is half of
// what the relay tests assert, because "we never ask AWS about cdn" is not
// observable in the output.
type fakeCA struct {
	asked   [][]string
	records []dnsplan.Record
	err     error
}

func (f *fakeCA) ValidationRecords(_ context.Context, hosts []string) ([]dnsplan.Record, error) {
	f.asked = append(f.asked, append([]string(nil), hosts...))
	return f.records, f.err
}

type fakeEdge struct {
	asked  []string
	proofs map[string]dnsplan.Record
	err    error
}

func (f *fakeEdge) ServingProof(_ context.Context, host string) (dnsplan.Record, bool, error) {
	f.asked = append(f.asked, host)
	if f.err != nil {
		return dnsplan.Record{}, false, f.err
	}
	record, ready := f.proofs[host]
	return record, ready, nil
}
