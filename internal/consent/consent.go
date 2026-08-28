// Package consent is the one screen this service refuses to delegate to a
// console: the description of a standing wildcard grant, served by the code that
// will do the writing, and an acknowledgement that only this deployment can mint.
//
// Only lane 2 needs it, and the reason is enumerability rather than risk
// appetite. Lanes 1 and 3 publish a CLOSED record set that can be listed in full
// before anything is authorized, so a console can show a customer the whole of
// what will land in their zone and this repository's job is only to keep the
// console's list and the writer's list the same bytes (docs/DESIGN.md §2, "one
// derivation, two paths"). `*.<anchor>` cannot be listed: it is a standing grant
// to write names that do not exist yet, so the customer is agreeing to a RULE
// rather than to a list, and the only honest place to read a rule is the code
// that applies it. A console can be truthful today and drift tomorrow, invisibly
// to the person the wildcard exposes. pageMarkup says this to the customer.
//
// The acknowledgement is a MAC rather than a flag, for the same reason the
// ownership proof is: one the private half could author would put us back where
// we started. `authorize` refuses a lane-2 grant unless handed a token this
// deployment's keyset produced for THIS page's reference and THIS anchor, and no
// key that can produce one exists in MirrorStack's private half.
//
// Nothing here talks to a DNS provider, a resolver, a database or the network.
// Page is a pure function of a plan and a nonce; Token and Verify are pure
// functions of those plus this deployment's keyset.
package consent

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"strings"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/grantcrypto"
)

// ErrConsent is the single refusal this package returns, from Page and from Token
// alike: ONE error at the boundary, for the reason dnsplan, lane and derive all
// give. The specific cause travels in the wrapped text, where logs and tests read
// it.
//
// One refusal additionally wraps dnsplan.ErrAnchorEscape, so a plan naming
// something outside its anchor answers to both checks: the caller's, and an
// operator grepping this service for every containment failure. Verify returns no
// error at all — see there for why.
var ErrConsent = errors.New("consent: refused")

const (
	// hkdfInfo is the HKDF domain separator for the consent acknowledgement,
	// namespaced for the reason internal/proof's is. Its info is the same shape with
	// its own path in it, which keeps an ownership proof — a value we publish in
	// public DNS for anyone to read — from being replayable as a customer's
	// agreement to a standing wildcard.
	hkdfInfo = "github.com/mirrorstack-ai/dns-delegate-engine/internal/consent:acknowledgement/v1"

	// messagePrefix versions the MAC input from inside the MAC, so a future v2
	// message shape can never produce a v1 value.
	messagePrefix = "ms-dns-consent/v1"

	// separator joins the message components. NUL cannot occur in a DNS name or in
	// a nonce this service mints — see message.
	separator = "\x00"

	// valuePrefix makes an acknowledgement self-identifying in a log or a support
	// ticket, and versions the ENCODING separately from the message. Deliberately
	// NOT internal/proof's `msv1-`, so a reader holding both values does not have
	// to work out which is which.
	valuePrefix = "msack1-"

	// maxNonce bounds the reference this package will MAC over. The nonce this
	// service mints is 32 hexadecimal characters (internal/sealed.NewNonce, 128
	// bits), so anything materially longer is not one we issued, and the bound stops
	// a caller turning a verification — reachable before anything else about the
	// request is established — into an allocation.
	maxNonce = 128
)

// Required reports whether a lane needs this service's own consent page. Only
// org_app_domain does; the package comment says why.
//
// 🔴 IT IS AN ALLOW-LIST OF THE LANES THAT DO NOT NEED THE PAGE, NOT A TEST FOR
// THE ONE THAT DOES. A fourth lane would skip the page by default under
// `l == OrgAppDomain` and demands one by default here; the unfamiliar case has to
// fail toward asking, because "broader than a list" is the property a new lane is
// most likely to share. lane.Parse refuses an unrecognised lane long before this
// is reached; this is what that refusal degrades to if it is moved or forgotten.
// Page fails closed in the opposite direction, so a new lane is blocked rather
// than shown a page that lies about it — see the lane check there.
func Required(l lane.Lane) bool {
	switch l {
	case lane.OrgPlatformDomain, lane.AppDomain:
		return false
	}
	return true
}

// Token is the acknowledgement: an HMAC over the page's reference and the anchor,
// under this deployment's keyset.
//
// 🔴 IT PROVES THIS SERVICE SERVED THIS PAGE FOR THIS REGISTRATION. The minting
// key never leaves this deployment; an ack the private half could author would be
// a screen claiming a customer was told about a standing wildcard, with nothing
// behind it.
//
// 🔴 MINT ON ACKNOWLEDGEMENT, NEVER ON RENDER. Page deliberately returns no
// token: if it did, "served" and "agreed to" would be one event and anybody able
// to fetch the URL — the private half included — would hold the agreement.
// Nothing in the type system enforces that ordering; the code serving the page
// owns it.
//
// It binds exactly what the page displays — the anchor and the reference — and
// NOT the identity: a derive.Plan carries none, so the page never shows one. The
// identity binding comes from the sealed registration the reference was minted
// into.
//
// 🔴 SO VERIFY AGAINST THE NONCE OUT OF THAT SEALED REGISTRATION, NEVER ONE THE
// CALLER SENT. A reference arriving beside the token is a pair whose halves are
// both the caller's, and a MAC over two values the caller chose is a signature on
// its own statement: one acknowledgement would satisfy every later authorization
// on that anchor, forever, with the customer shown nothing again.
//
// 🔴 THE LIMIT THAT REMAINS: an acknowledgement is scoped to one REGISTRATION,
// not to one authorization attempt. The same token verifies for every
// authorization of that domain on that lane for as long as the registration
// exists, so a customer who agreed once and abandoned the connect can have the
// grant authorized later without seeing the page again.
//
// It cannot be closed here. Single use needs a counter; this service owns no
// database (CLAUDE.md, DESIGN §7), and a counter inside a sealed envelope does not
// help, because the private half can hand back an EARLIER envelope — a rollback in
// the direction that grants more authority. Re-registering mints a new reference,
// so an old ack fails against the NEW registration, but it does not retire the OLD
// one, which remains replayable. The two controls that do stop a live grant are
// the customer's: delete the ownership proof, or revoke at the provider
// (DESIGN §8).
func Token(s *grantcrypto.Sealer, nonce, anchor string) (string, error) {
	if s == nil {
		// No keyset means no acknowledgement, never one under an absent key: that
		// would be a single constant every deployment agreed on.
		return "", fmt.Errorf("%w: %w", ErrConsent, grantcrypto.ErrNoKeyset)
	}
	msg, err := message(nonce, anchor)
	if err != nil {
		return "", err
	}
	active, _ := s.MAC(hkdfInfo, msg)
	if len(active) != grantcrypto.MACSize {
		return "", fmt.Errorf("%w: the keyset produced no MAC", ErrConsent)
	}
	return encode(active), nil
}

// Verify reports whether a token is one this deployment minted for this reference
// and this anchor.
//
// It accepts a token under ANY key in the keyset, for the rotation reason
// internal/proof.Accepted gives: a key rotated between serving a page and
// completing an authorization would otherwise reject an acknowledgement genuinely
// given seconds earlier. Rotation is a verify-side concern here exactly as it is
// a decrypt-side concern in grantcrypto.Open.
//
// The comparison is constant-time, as in internal/proof.Matches, and the loop
// runs to completion so its duration does not report which key matched, or
// whether one did.
//
// It returns a bool and no error, the one place this package differs from the
// rest of the service: no keyset, a malformed reference, an unparseable value and
// a MAC that does not match are the same answer to the only question a caller may
// act on, and distinguishing them here would tell whoever is guessing which half
// of the guess was wrong. A deployment with no keyset fails Token first, loudly,
// at startup.
func Verify(s *grantcrypto.Sealer, nonce, anchor, token string) bool {
	if s == nil {
		return false
	}
	msg, err := message(nonce, anchor)
	if err != nil {
		return false
	}
	candidate := fold(token)
	if candidate == "" {
		return false
	}
	_, all := s.MAC(hkdfInfo, msg)
	if len(all) == 0 {
		return false
	}
	match := false
	for _, mac := range all {
		if len(mac) != grantcrypto.MACSize {
			// A short MAC is a defect in the keyset, not a property of the
			// candidate, so refusing here reveals nothing about the token.
			return false
		}
		// No early return on a match: see the constant-time note above.
		if hmac.Equal([]byte(candidate), []byte(encode(mac))) {
			match = true
		}
	}
	return match
}

// message is the exact byte string every acknowledgement is a MAC over.
//
//	"ms-dns-consent/v1\x00" + nonce + "\x00" + anchor
//
// Pin it. Changing the version tag, the separator, the order or the normalization
// invalidates every acknowledgement in flight — a much smaller blast radius than
// internal/proof's equivalent (an authorization attempt lives ten minutes, a
// published ownership proof lives for years), but a customer mid-consent told to
// start again is still being told something went wrong that did not.
//
// No component may contain the separator, for the reason internal/proof.message
// gives; here a nonce carrying a NUL would let one acknowledgement cover two
// anchors.
//
// The anchor is normalized and the nonce only trimmed. An anchor arrives spelled
// several legitimate ways (a trailing root dot, mixed case from a form) and
// folding is what stops one registration having two acknowledgement values; a
// nonce is a value this service minted, so accepting a spelling we never issued
// would be tolerance with nothing to tolerate.
func message(nonce, anchor string) ([]byte, error) {
	nonce = strings.TrimSpace(nonce)
	anchor = dnsplan.NormalizeName(anchor)
	if len(nonce) > maxNonce {
		return nil, fmt.Errorf("%w: the reference is %d bytes, and nothing this service mints is over %d",
			ErrConsent, len(nonce), maxNonce)
	}
	if len(anchor) > dnsplan.MaxDNSName {
		return nil, fmt.Errorf("%w: the anchor is %d bytes, over the %d-byte DNS limit",
			ErrConsent, len(anchor), dnsplan.MaxDNSName)
	}
	for _, part := range []string{nonce, anchor} {
		if part == "" || strings.Contains(part, separator) {
			return nil, fmt.Errorf(
				"%w: an acknowledgement needs a reference and an anchor, each present and separator-free", ErrConsent)
		}
	}
	return []byte(messagePrefix + separator + nonce + separator + anchor), nil
}

// encode renders a MAC as the string an acknowledgement travels as:
// grantcrypto.EncodeMAC under this package's prefix. Two of that function's
// reasons apply here rather than all of them — this token is never typed into
// somebody else's web form, but it is logged, quoted in a support thread and
// copied between two systems, and it must not be base64, because the case
// folding in fold would make two distinct MACs one acknowledgement. 59
// characters with the prefix.
func encode(mac []byte) string {
	return grantcrypto.EncodeMAC(valuePrefix, mac)
}

// fold normalizes a candidate token into the form encode produces: trimming and
// case folding only, deliberately narrower than internal/proof's fold, which also
// strips the quotes a DNS control panel wraps a TXT value in. This value never
// lives in a zone file, and every accepted spelling of a security value is one
// more thing a reader has to reason about. Neither step widens what is accepted —
// case folding is a bijection on base32's alphabet.
func fold(token string) string {
	return strings.ToLower(strings.TrimSpace(token))
}
