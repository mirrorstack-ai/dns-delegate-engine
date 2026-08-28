// Package consent is the one screen this service refuses to delegate to a
// console: the description of a standing wildcard grant, served by the code that
// will do the writing, and an acknowledgement that only this deployment can mint.
//
// 🔴 ONE LANE NEEDS THIS, AND THE REASON IS ENUMERABILITY RATHER THAN RISK
// APPETITE.
//
// Lanes 1 and 3 publish a CLOSED record set. Connecting a platform domain writes
// four routing CNAMEs under a fixed label table and their certificate pointers;
// connecting a domain on one app writes exactly two records at the hostname
// itself. Both sets can be listed in full, before anything is authorized, on any
// screen — so MirrorStack's console can show a customer the whole of what will
// land in their zone, and this repository's job is only to make sure the list
// the console renders and the list the writer publishes are the same bytes
// (docs/DESIGN.md §2, "one derivation, two paths").
//
// Lane 2 cannot be listed. `*.<anchor>` is a standing grant to write names that
// do not exist yet — every app the org will ever deploy, at hostnames nobody has
// chosen — and no screen can enumerate a set whose members have not been named.
// The customer is therefore not agreeing to a list; they are agreeing to a RULE,
// and the only honest place to read a rule is the code that applies it. That is
// why the description comes from here rather than from a console this repository
// cannot vouch for: a console can be truthful today and drift tomorrow, and the
// drift would be invisible to exactly the person the wildcard exposes.
//
// The acknowledgement is a MAC rather than a flag, for the same reason the
// ownership proof is a MAC rather than a name we chose: an acknowledgement the
// private half could author would put us back where we started. `authorize`
// refuses a lane-2 grant unless it is handed a token this deployment's keyset
// produced for THIS page's reference and THIS anchor, and no key that can
// produce one exists anywhere in MirrorStack's private half.
//
// Nothing here talks to a DNS provider, a resolver, a database or the network.
// Page is a pure function of a plan and a nonce; Token and Verify are pure
// functions of those plus this deployment's keyset.
package consent

import (
	"crypto/hmac"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/grantcrypto"
)

// ErrConsent is the single refusal this package returns, from Page and from
// Token alike.
//
// Deliberately ONE error at the boundary, for the reason dnsplan, lane and
// derive all give: every caller's check is then identical —
// errors.Is(err, ErrConsent) — and a refusal added here later cannot slip past a
// caller that switched on the set of sentinels it happened to know about. The
// specific cause travels in the wrapped text, where logs and tests read it.
//
// One refusal additionally wraps dnsplan.ErrAnchorEscape, so a plan naming
// something outside its anchor answers to both checks: the caller's, and an
// operator grepping this service for every containment failure it has ever
// refused. Verify returns no error at all — see there for why.
var ErrConsent = errors.New("consent: refused")

const (
	// hkdfInfo is the HKDF domain separator for the consent acknowledgement, and
	// it is namespaced on purpose. Sealer.MAC is a general primitive; a second
	// use of it that picked a colliding info would share a subkey with this one,
	// and a value minted for that other purpose could then be presented as an
	// acknowledgement. internal/proof's info is the same shape with this
	// package's path in it, which is what keeps an ownership proof — a value we
	// publish deliberately, in public DNS, for anyone to read — from ever being
	// replayable as a customer's agreement to a standing wildcard.
	hkdfInfo = "github.com/mirrorstack-ai/dns-delegate-engine/internal/consent:acknowledgement/v1"

	// messagePrefix versions the MAC input independently of the encoding. It is
	// inside the MAC rather than beside it, so a future v2 message shape can
	// never produce a v1 value.
	messagePrefix = "ms-dns-consent/v1"

	// separator joins the message components. NUL because it cannot occur in a
	// DNS name or in a nonce this service mints, which is what makes the
	// concatenation injective — see message.
	separator = "\x00"

	// valuePrefix makes an acknowledgement self-identifying in a log or a
	// support ticket, and versions the ENCODING separately from the message. It
	// is deliberately NOT internal/proof's `msv1-`: the two values are already
	// cryptographically independent, and a reader who has both in front of them
	// should not have to work out which is which.
	valuePrefix = "msack1-"

	// maxNonce bounds the reference this package will MAC over.
	//
	// The nonce this service mints is 32 hexadecimal characters
	// (internal/sealed.NewNonce, 128 bits). Anything materially longer is not
	// one we issued, and the bound exists so a caller cannot turn a verification
	// — which is reachable before anything else about the request has been
	// established — into an allocation. The same guard shape as
	// internal/sealed's envelope cap, for the same reason.
	maxNonce = 128
)

// Required reports whether a lane needs this service's own consent page.
//
// Only org_app_domain does, and the reason is enumerability rather than risk
// appetite: lanes 1 and 3 publish a CLOSED, listable record set, so a console
// screen can show the customer exactly what will be written. A wildcard cannot
// be enumerated — it is a standing grant to write names that do not exist yet —
// so the description has to come from the code that will do the writing.
//
// 🔴 IT IS AN ALLOW-LIST OF THE LANES THAT DO NOT NEED THE PAGE, NOT A TEST FOR
// THE ONE THAT DOES.
//
// The two agree on today's vocabulary and disagree on tomorrow's. A fourth lane
// added to package lane would skip the consent page by default under
// `l == OrgAppDomain`, and demands it by default here — and the unfamiliar case
// has to fail toward asking, because the reason lane 2 needs this screen is that
// its grant is broader than a list, and "broader than a list" is exactly the
// property a new lane is most likely to share. An unrecognised lane is refused
// by lane.Parse long before this is reached; this is what that refusal degrades
// to if it is ever moved or forgotten.
//
// Note the deliberate asymmetry with Page, which refuses everything that is not
// org_app_domain: Required fails closed toward DEMANDING a page, and Page fails
// closed toward refusing to render one whose sentences it cannot vouch for.
// Together they mean a new lane is blocked rather than shown a page that lies
// about it.
func Required(l lane.Lane) bool {
	switch l {
	case lane.OrgPlatformDomain, lane.AppDomain:
		return false
	}
	return true
}

// Token is the acknowledgement: an HMAC over the page's reference and the
// anchor, under this deployment's keyset.
//
// 🔴 IT PROVES THIS SERVICE SERVED THIS PAGE FOR THIS REGISTRATION. An ack the
// private half could author would put us back where we started — a screen
// somewhere claiming a customer was told about a standing wildcard, with nothing
// behind it. The minting key never leaves this deployment.
//
// 🔴 MINT ON ACKNOWLEDGEMENT, NEVER ON RENDER. Page deliberately returns no
// token: if it did, "served" and "agreed to" would be one event and anybody able
// to fetch the URL — the private half included — would hold the agreement.
// Nothing in the type system enforces that ordering; the code serving the page
// owns it.
//
// It binds exactly what the page displays: the anchor and the reference. NOT the
// identity — a derive.Plan carries none, so the page never shows one, and a
// token asserting the customer acknowledged something they were not shown would
// claim more than it can support. The identity binding comes from the sealed
// registration the reference was minted into.
//
// 🔴 SO VERIFY AGAINST THE NONCE OUT OF THAT SEALED REGISTRATION, NEVER ONE THE
// CALLER SENT. A reference arriving beside the token is a pair whose halves are
// both the caller's, and a MAC over two values the caller chose is a signature on
// its own statement — one acknowledgement would satisfy every later authorization
// on that anchor, forever, with the customer shown nothing again.
//
// 🔴 THE LIMIT THAT REMAINS, because it is real and checkable: an acknowledgement
// is scoped to one REGISTRATION, not to one authorization attempt. The same token
// verifies for every authorization of that domain on that lane for as long as the
// registration exists, so a customer who agreed once and abandoned the connect can
// have the grant authorized later without seeing the page again.
//
// It cannot be closed here. Single use needs a counter; this service owns no
// database (CLAUDE.md, DESIGN §7), and a counter inside a sealed envelope does not
// help because the private half can hand back an EARLIER envelope — a rollback in
// the direction that grants more authority. Re-registering is not a way out
// either: it mints a new reference, so an old ack fails against the NEW
// registration, but it does not retire the OLD one, which remains replayable.
//
// The two controls that do stop a live grant are the customer's: delete the
// ownership proof, or revoke at the provider (DESIGN §8).
func Token(s *grantcrypto.Sealer, nonce, anchor string) (string, error) {
	if s == nil {
		// No keyset means no acknowledgement — never an acknowledgement under an
		// absent key, which would be one constant every deployment agreed on.
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

// Verify reports whether a token is one this deployment minted for this
// reference and this anchor.
//
// 🔴 IT ACCEPTS A TOKEN UNDER ANY KEY IN THE KEYSET, NOT ONLY THE ACTIVE ONE.
// The same rotation argument internal/proof makes for a published ownership
// value: a key rotated between serving a page and completing an authorization
// would otherwise reject an acknowledgement a customer had genuinely given
// seconds earlier, and the customer would be sent round the consent flow again
// with nothing to tell them why. Rotation is a verify-side concern here exactly
// as it is a decrypt-side concern in grantcrypto.Open.
//
// 🔴 THE COMPARISON IS CONSTANT-TIME. The candidate is supplied by the caller
// and the expected value is a MAC under a key that never leaves this deployment
// — the exact shape a byte-at-a-time comparison leaks. The loop runs to
// completion so its duration does not report which key matched, or whether one
// did.
//
// It returns a bool and no error, which is the one place this package differs
// from the rest of the service, and it is deliberate: every reason a token could
// fail — no keyset, a malformed reference, an unparseable value, a MAC that does
// not match — is the same answer to the only question a caller may act on, and
// distinguishing them at this boundary would tell whoever is guessing which half
// of the guess was wrong. Anything a caller genuinely needs to distinguish (a
// deployment with no keyset at all) fails Token first, loudly, at startup.
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
// 🔴 PIN IT. Changing any part — the version tag, the separator, the order, the
// normalization — invalidates every acknowledgement in flight. That is a much
// smaller blast radius than internal/proof's equivalent (an authorization
// attempt lives ten minutes, a published ownership proof lives for years), which
// is precisely why it is worth stating: the temptation to treat this one as
// editable is the difference, and a customer mid-consent being told to start
// again is still a customer being told something went wrong that did not.
//
// 🔴 NO COMPONENT MAY CONTAIN THE SEPARATOR, and that is what keeps the encoding
// injective. The message is a flat concatenation, so a nonce permitted to carry
// a NUL could re-partition it: ("a\x00example.net", "") and ("a", "example.net")
// would produce identical bytes, and one acknowledgement would cover two
// anchors. NUL cannot occur in a DNS name or in a hex nonce, so refusing it
// costs nothing and closes the question permanently.
//
// The anchor is normalized and the nonce is only trimmed. The asymmetry is not
// an oversight: an anchor arrives spelled several legitimate ways (a trailing
// root dot from a resolver, mixed case from a form) and folding them is what
// stops one registration having two acknowledgement values, while a nonce is a
// value this service minted and handed out, so accepting a spelling we never
// issued would be tolerance with nothing to tolerate.
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

// encode renders a MAC as the string an acknowledgement travels as.
//
// The same alphabet as internal/proof's published value, and for one of the same
// reasons rather than all of them: this token is never typed into somebody
// else's web form, but it is logged, quoted in a support thread, and copied
// between two systems, so it may only contain characters that survive that
// without quoting — no `+`, `/`, `=`, quote, backslash, semicolon, space or
// newline. Lowercase because that is what the rest of this service normalizes
// to, so a value read back needs one fold rather than two. 32 bytes encode to 52
// characters, 59 with the prefix.
//
// It is deliberately NOT base64: two distinct MACs can differ only in the case
// of one character there, so the case folding in fold would make two different
// acknowledgements the same value. base32's alphabet has no such pair.
func encode(mac []byte) string {
	return valuePrefix + strings.ToLower(
		base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mac))
}

// fold normalizes a candidate token into the form encode produces.
//
// Trimming and case folding only — deliberately narrower than internal/proof's
// fold, which also strips the quotes a DNS control panel wraps a TXT value in.
// This value never lives in a zone file, so that tolerance would be tolerance
// for a case that cannot arise, and every accepted spelling of a security value
// is one more thing a reader has to reason about.
//
// Neither step widens what is accepted: case folding is a bijection on base32's
// alphabet, so two different MACs cannot fold onto each other.
func fold(token string) string {
	return strings.ToLower(strings.TrimSpace(token))
}
