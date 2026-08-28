package consent

import (
	"errors"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/testsupport"
	"strings"
	"testing"
)

// 🔴 A CHALLENGE REDEEMS ONLY FOR THE PAGE IT WAS PRINTED ON. Each of the three
// components is moved on its own, because a MAC over a concatenation that
// dropped one would still pass every round-trip test.
func TestAChallengeRedeemsOnlyForThePageItWasMintedFor(t *testing.T) {
	sealer := testsupport.SealerFrom(t, testsupport.GoldenKeyset(t))
	const other = "example.org"
	here, elsewhere := lane2Plan(t, fixtureAnchor), lane2Plan(t, other)
	pageHere, pageElsewhere := renderedPage(t, here, fixtureNonce), renderedPage(t, elsewhere, fixtureNonce)

	challenge, err := Challenge(sealer, fixtureNonce, fixtureAnchor, pageHere)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if _, err := Redeem(sealer, fixtureNonce, fixtureAnchor, pageHere, challenge); err != nil {
		t.Fatalf("the challenge from a served page must redeem: %v", err)
	}

	for _, tc := range []struct {
		what          string
		nonce, anchor string
		page          string
	}{
		{"a page served for another anchor", fixtureNonce, other, pageElsewhere},
		{"this page's bytes claimed for another anchor", fixtureNonce, other, pageHere},
		{"this anchor with another page's bytes", fixtureNonce, fixtureAnchor, pageElsewhere},
		{"a reference this registration was not printed with", "f0e1d2c3b4a5968778695a4b3c2d1e0f", fixtureAnchor, pageHere},
	} {
		if _, err := Redeem(sealer, tc.nonce, tc.anchor, tc.page, challenge); !errors.Is(err, ErrConsent) {
			t.Errorf("%s must not redeem, got %v", tc.what, err)
		}
	}
}

// 🔴 THE VALUE ON THE PAGE IS NOT THE AGREEMENT. Both are MACs under one keyset
// over the same reference and anchor; only the HKDF info separates them. If they
// ever shared one, every page served would carry its own acknowledgement — the
// exact collapse Offer and Redeem exist to prevent.
func TestAChallengeIsNotAnAcknowledgement(t *testing.T) {
	sealer := testsupport.SealerFrom(t, testsupport.GoldenKeyset(t))
	page := renderedPage(t, lane2Plan(t, fixtureAnchor), fixtureNonce)

	challenge, err := Challenge(sealer, fixtureNonce, fixtureAnchor, page)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if Verify(sealer, fixtureNonce, fixtureAnchor, challenge) {
		t.Fatal("🔴 the challenge printed on the page verifies as an acknowledgement")
	}
	token, err := Redeem(sealer, fixtureNonce, fixtureAnchor, page, challenge)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if !Verify(sealer, fixtureNonce, fixtureAnchor, token) {
		t.Fatal("what Redeem mints must be the acknowledgement Authorize checks")
	}
	if strings.HasPrefix(token, challengeValuePrefix) || strings.HasPrefix(challenge, valuePrefix) {
		t.Fatal("the two values must be tellable apart by their prefix alone")
	}
}

// A challenge minted before a rotation still redeems, for the reason Verify
// accepts a token under any key: a keyset rotated while somebody was reading the
// page would otherwise refuse an agreement given seconds later.
func TestAChallengeMintedUnderARetiredKeyStillRedeems(t *testing.T) {
	page := renderedPage(t, lane2Plan(t, fixtureAnchor), fixtureNonce)
	before := testsupport.SealerFrom(t, testsupport.Keyset(t, "k1", "k2"))
	after := testsupport.SealerFrom(t, testsupport.Keyset(t, "k2", "k1"))

	challenge, err := Challenge(before, fixtureNonce, fixtureAnchor, page)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	token, err := Redeem(after, fixtureNonce, fixtureAnchor, page, challenge)
	if err != nil {
		t.Fatalf("a challenge minted under the retired key must still redeem: %v", err)
	}
	if !Verify(after, fixtureNonce, fixtureAnchor, token) {
		t.Fatal("the acknowledgement must verify under the keyset that minted it")
	}
	// And a keyset that never held the minting key is a different deployment.
	if _, err := Redeem(testsupport.SealerFrom(t, testsupport.Keyset(t, "k9")), fixtureNonce, fixtureAnchor, page, challenge); !errors.Is(err, ErrConsent) {
		t.Errorf("another deployment's challenge must not redeem here, got %v", err)
	}
}

func TestRedeemFailsClosed(t *testing.T) {
	sealer := testsupport.SealerFrom(t, testsupport.GoldenKeyset(t))
	page := renderedPage(t, lane2Plan(t, fixtureAnchor), fixtureNonce)
	if _, err := Redeem(nil, fixtureNonce, fixtureAnchor, page, "anything"); !errors.Is(err, ErrConsent) {
		t.Errorf("no keyset must refuse, got %v", err)
	}
	for _, candidate := range []string{
		"",
		"mschal1-",
		"not-a-challenge",
		strings.Repeat("a", maxChallenge+1),
	} {
		if _, err := Redeem(sealer, fixtureNonce, fixtureAnchor, page, candidate); !errors.Is(err, ErrConsent) {
			t.Errorf("the candidate %q must refuse, got %v", candidate, err)
		}
	}
	// A page nobody rendered is not a page: Redeem must never fall back to
	// checking the reference and the anchor alone.
	challenge, err := Challenge(sealer, fixtureNonce, fixtureAnchor, page)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if _, err := Redeem(sealer, fixtureNonce, fixtureAnchor, "", challenge); !errors.Is(err, ErrConsent) {
		t.Errorf("an empty disclosure must refuse, got %v", err)
	}
	if _, err := Challenge(nil, fixtureNonce, fixtureAnchor, page); !errors.Is(err, ErrConsent) {
		t.Errorf("Challenge with no keyset must refuse, got %v", err)
	}
}

// 🔴 THE OFFER CARRIES EXACTLY ONE FORM AND IT POSTS TO ITSELF. No action
// attribute, so the acknowledgement goes back to whatever served the page and
// cannot be redirected by an edit here; everything TestPageLoadsNothingAndPostsNowhere
// forbids stays forbidden.
func TestTheOfferPostsToItselfAndNowhereElse(t *testing.T) {
	sealer := testsupport.SealerFrom(t, testsupport.GoldenKeyset(t))
	plan := lane2Plan(t, fixtureAnchor)
	page := renderedPage(t, plan, fixtureNonce)
	challenge, err := Challenge(sealer, fixtureNonce, fixtureAnchor, page)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	offer, err := Offer(plan, fixtureNonce, challenge)
	if err != nil {
		t.Fatalf("Offer: %v", err)
	}
	lower := strings.ToLower(offer)
	if got := strings.Count(lower, "<form"); got != 1 {
		t.Errorf("want exactly one form, got %d", got)
	}
	if !strings.Contains(lower, `<form method="post">`) {
		t.Error("the form must post, and to the URL it was served from")
	}
	for _, forbidden := range []string{
		"<script", "src=", "href=", "action=", "<iframe", "<link", "<img",
		"javascript:", "http://", "https://", "@import", "url(", "onclick", "onload",
	} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("the offer contains %q; it must load nothing and post only to itself", forbidden)
		}
	}
	if !strings.Contains(offer, challenge) {
		t.Error("the offer must carry the challenge, or nobody can acknowledge it")
	}
	// 🔴 THE CHALLENGE BINDS THE DISCLOSURE, NOT THE OFFER. Redeeming against the
	// served bytes would be circular — the challenge is inside them — and the
	// value a customer agreed to is the text, not the button.
	if _, err := Redeem(sealer, fixtureNonce, fixtureAnchor, offer, challenge); !errors.Is(err, ErrConsent) {
		t.Errorf("the challenge must be over Page's bytes, not Offer's, got %v", err)
	}
	if _, err := Offer(plan, fixtureNonce, "  "); !errors.Is(err, ErrConsent) {
		t.Errorf("an offer with no challenge is a page nobody can acknowledge, got %v", err)
	}
}
