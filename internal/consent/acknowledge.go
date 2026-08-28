package consent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/grantcrypto"
)

const (
	// hkdfChallengeInfo namespaces the challenge, for the reason hkdfInfo gives.
	// 🔴 IT MUST NEVER EQUAL hkdfInfo: the challenge is printed on the page, so
	// under one info the page would carry its own acknowledgement.
	hkdfChallengeInfo = "github.com/mirrorstack-ai/dns-delegate-engine/internal/consent:challenge/v1"

	// challengePrefix versions the challenge's MAC input from inside the MAC, as
	// messagePrefix does for the acknowledgement.
	challengePrefix = "ms-dns-consent-challenge/v1"

	// challengeValuePrefix is deliberately not valuePrefix, so a reader holding
	// both values does not have to work out which is which.
	challengeValuePrefix = "mschal1-"

	// maxChallenge bounds the candidate Redeem will fold, so a redemption cannot
	// be turned into an allocation. What this service mints is 60 characters.
	maxChallenge = 128
)

// Challenge is the value an acknowledgement must be redeemed with: a MAC over
// the reference, the anchor and the SHA-256 of the disclosure Page rendered.
// Offer prints it into that page, and Redeem is the only thing that turns one
// into a Token.
//
// 🔴 IT BINDS THE BYTES, NOT JUST THE REGISTRATION. A challenge stops verifying
// the moment the disclosure changes — a reworded page, a moved routing target, a
// rotated proof value — so an acknowledgement can never assert agreement to a
// screen nobody was shown.
//
// It carries no clock, and that is deliberate: a window here would imply a bound
// the acknowledgement it redeems into does not have (see Token's residual
// limit), and it would break the determinism the page is audited by — two renders
// of one registration are the same bytes.
func Challenge(s *grantcrypto.Sealer, nonce, anchor, page string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("%w: %w", ErrConsent, grantcrypto.ErrNoKeyset)
	}
	msg, err := challengeMessage(nonce, anchor, page)
	if err != nil {
		return "", err
	}
	active, _ := s.MAC(hkdfChallengeInfo, msg)
	if len(active) != grantcrypto.MACSize {
		return "", fmt.Errorf("%w: the keyset produced no MAC", ErrConsent)
	}
	return encode(challengeValuePrefix, active), nil
}

// Redeem verifies a challenge against the disclosure it was minted for and mints
// the acknowledgement. It is the ONLY path to a Token outside this package's own
// tests, which is what keeps rendering and agreeing two events.
//
// It accepts a challenge under any key in the keyset and compares in constant
// time, for the reasons Verify gives.
func Redeem(s *grantcrypto.Sealer, nonce, anchor, page, candidate string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("%w: %w", ErrConsent, grantcrypto.ErrNoKeyset)
	}
	if len(candidate) > maxChallenge {
		return "", fmt.Errorf("%w: the challenge is %d bytes, and nothing this service mints is over %d",
			ErrConsent, len(candidate), maxChallenge)
	}
	msg, err := challengeMessage(nonce, anchor, page)
	if err != nil {
		return "", err
	}
	_, all := s.MAC(hkdfChallengeInfo, msg)
	if len(all) == 0 {
		return "", fmt.Errorf("%w: the keyset produced no MAC", ErrConsent)
	}
	folded := fold(candidate)
	match := false
	for _, mac := range all {
		if len(mac) != grantcrypto.MACSize {
			return "", fmt.Errorf("%w: the keyset produced a short MAC", ErrConsent)
		}
		// No early return on a match: see the constant-time note on Verify.
		if hmac.Equal([]byte(folded), []byte(encode(challengeValuePrefix, mac))) {
			match = true
		}
	}
	// 🔴 THE ACKNOWLEDGEMENT IS MINTED BEFORE THE COMPARISON IS ACTED ON, so a
	// refused redemption costs what an accepted one costs. Minting after the check
	// would make a success one HMAC dearer than a failure, and the route this runs
	// behind is unauthenticated: a timing difference there answers "was that the
	// challenge off the page" to anyone who asks.
	token, err := Token(s, nonce, anchor)
	if err != nil {
		return "", err
	}
	if !match {
		return "", fmt.Errorf(
			"%w: this challenge was not printed on a page this service served for this registration", ErrConsent)
	}
	return token, nil
}

// challengeMessage is the exact byte string every challenge is a MAC over.
//
//	"ms-dns-consent-challenge/v1\x00" + reference + "\x00" + anchor + "\x00" + sha256(page)
//
// Pin it, for the reason message says: changing it invalidates every page in
// flight, and a customer mid-consent is then told to start again.
func challengeMessage(nonce, anchor, page string) ([]byte, error) {
	reference, name, err := bind(nonce, anchor)
	if err != nil {
		return nil, err
	}
	if page == "" {
		return nil, fmt.Errorf("%w: there is no disclosure for a challenge to bind to", ErrConsent)
	}
	sum := sha256.Sum256([]byte(page))
	return []byte(challengePrefix + separator + reference + separator + name +
		separator + hex.EncodeToString(sum[:])), nil
}
