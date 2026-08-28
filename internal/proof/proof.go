// Package proof derives the one record in a delegated DNS plan that this
// service must never write: the TXT at `_mirrorstack-challenge.<anchor>` that
// demonstrates the customer controls the name every other record hangs beneath.
//
// 🔴 A PROOF WE PUBLISH OURSELVES PROVES NOTHING. The record used to be inside
// the set this service published, gated on a public lookup of that same record —
// so our own write satisfied it. Anchor containment still bounded a plan to a
// subtree, but a subtree of a name nobody had demonstrated any claim to: a bound
// on blast radius rather than on authority.
//
// The fix splits the record in two, and neither half suffices alone. The VALUE is
// a MAC under a key that never leaves this deployment, so nobody outside it can
// mint one for a domain, an identity or a lane they were not given — not a secret
// from the customer, we show it to them, but from everyone else, a compromised
// private half included. PUBLISHING it takes control of the zone: the thing being
// demonstrated, and the half we deliberately cannot perform.
//
// `verify` re-checks the record on EVERY pass rather than once at registration,
// because ownership stops being true the day a domain changes hands.
//
// Nothing here talks to a DNS provider, a resolver, a database or the network —
// a pure function of (lane, identity, anchor) and this deployment's keyset.
package proof

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

// Prefix is where the ownership proof lives: one label above the anchor.
//
// The trailing dot is part of the constant so that `Prefix + anchor` is the whole
// name. The version of this bug that ships is
// `_mirrorstack-challengeexample.com`: it resolves to nothing and never verifies.
//
// It sits at the ANCHOR itself, never at a derived host: one record has to cover
// every hostname a lane derives, and a proof at `account.example.com` would say
// nothing about `api.example.com`. They can be delegated to different people.
const Prefix = "_mirrorstack-challenge."

// ErrProof is the single refusal this package returns: ONE error at the boundary,
// for the reason dnsplan gives — naming the rejected component tells a caller,
// and through it an attacker, which half of a guess was wrong. The specific cause
// travels in the wrapped text, where logs and tests read it.
var ErrProof = errors.New("proof: cannot compute an ownership proof")

const (
	// hkdfInfo is the HKDF domain separator for the ownership proof, namespaced on
	// purpose: Sealer.MAC is a general primitive, and a second use of it under a
	// colliding info would share this subkey, so a value minted for that other
	// purpose could be published at the challenge name and pass verification.
	hkdfInfo = "github.com/mirrorstack-ai/dns-delegate-engine/internal/proof:ownership/v1"

	// messagePrefix versions the MAC input independently of the encoding, from
	// inside the MAC, so a future v2 message shape can never produce a v1 value.
	messagePrefix = "ms-dns-ownership/v1"

	// separator joins the message components. NUL cannot occur in a DNS name, a
	// UUID or a lane, which makes the concatenation injective — see message.
	separator = "\x00"

	// valuePrefix makes a published proof self-identifying in a zone somebody else
	// inherits, and versions the ENCODING separately from the message: a value
	// starting `msv1-` is one this build knows how to read.
	valuePrefix = "msv1-"
)

// Name is the owner of the ownership proof: `_mirrorstack-challenge.<anchor>`.
//
// 🔴 IT RETURNS "" RATHER THAN A NAME THAT CANNOT BE RIGHT: only the empty
// one fails loudly, where a prefix concatenated onto nothing and handed to a
// provider creates a record at the ZONE APEX. Not a hypothetical class of bug —
// Cloudflare returns its ownership-verification object with empty strings once
// the proof is no longer required, and an unguarded read of it published exactly
// that write.
//
// The anchor is normalized first, so a trailing root dot, mixed case or stray
// whitespace cannot produce two names for one domain and send a customer looking
// for a record we never derived.
func Name(anchor string) string {
	anchor = dnsplan.NormalizeName(anchor)
	if anchor == "" {
		return ""
	}
	name := Prefix + anchor
	if len(name) > dnsplan.MaxDNSName {
		return ""
	}
	return name
}

// Prover computes ownership proofs under this deployment's keyset. A struct
// rather than an interface: a seam here is one a caller could substitute a
// permissive implementation into. A zero Prover fails closed — see message.
type Prover struct{ Sealer *grantcrypto.Sealer }

// Expected is the single value the customer is told to publish — the MAC under
// the active key — and is what a console renders and a support answer quotes.
// Accepted, not this, is what a verifier compares against: a rotation must not
// invalidate a value we handed out yesterday.
func (p Prover) Expected(l lane.Lane, identity, anchor string) (string, error) {
	message, err := p.message(l, identity, anchor)
	if err != nil {
		return "", err
	}
	active, _ := p.Sealer.MAC(hkdfInfo, message)
	if len(active) != grantcrypto.MACSize {
		return "", fmt.Errorf("%w: the keyset produced no MAC", ErrProof)
	}
	return encode(active), nil
}

// Accepted is every value verify() will accept: one per key in the keyset. A
// caller comparing against it by hand must fold case and compare in constant
// time; use Matches, which does both.
//
// 🔴 ROTATION MUST NOT BREAK A PUBLISHED PROOF. A customer who published the
// value we gave them must not wake up to a domain that stopped advancing because
// we rotated a key they never saw. Dropping a key from the keyset is therefore a
// migration with a support cost, never a cleanup: it invalidates every proof
// published under it, and every affected customer has to edit a TXT record in
// their own zone before their domain advances again.
func (p Prover) Accepted(l lane.Lane, identity, anchor string) ([]string, error) {
	message, err := p.message(l, identity, anchor)
	if err != nil {
		return nil, err
	}
	_, all := p.Sealer.MAC(hkdfInfo, message)
	if len(all) == 0 {
		return nil, fmt.Errorf("%w: the keyset produced no MACs", ErrProof)
	}
	out := make([]string, 0, len(all))
	for _, mac := range all {
		if len(mac) != grantcrypto.MACSize {
			return nil, fmt.Errorf("%w: the keyset produced a short MAC", ErrProof)
		}
		out = append(out, encode(mac))
	}
	return out, nil
}

// Matches reports whether any value observed at the challenge name is one this
// registration accepts. Observed values are folded first (see fold), which is the
// whole reason the encoding is case-insensitive base32.
//
// 🔴 THE COMPARISON IS CONSTANT-TIME. The candidate is entirely
// attacker-controlled — whatever somebody published at a public name — while the
// expected value is the secret being guessed. Otherwise an attacker who cannot
// obtain (lane, someone else's org id, that org's domain) any other way asks us
// to compare, repeatedly, and reads the answer off the clock.
func (p Prover) Matches(l lane.Lane, identity, anchor string, observed []string) (bool, error) {
	accepted, err := p.Accepted(l, identity, anchor)
	if err != nil {
		return false, err
	}
	match := false
	for _, candidate := range observed {
		candidate = fold(candidate)
		if candidate == "" {
			continue
		}
		for _, want := range accepted {
			// No early return: the loop's duration must not report how far down the
			// list the match was found.
			if hmac.Equal([]byte(candidate), []byte(want)) {
				match = true
			}
		}
	}
	return match, nil
}

// Record is the ownership row as it appears in a plan.
//
// THE SOURCE IS THE CUSTOMER: THIS SERVICE MUST NEVER PUBLISH THIS RECORD — a
// plan handing this row to a provider returns the design to the defect the
// package comment describes. It is in Record form only so `describe` can render
// the same bytes for the manual path and the delegated path from one function,
// keeping the list a customer is told to add by hand from drifting.
//
// Proxied is false and explicit. It is meaningless for a TXT — the orange cloud
// applies to a hostname — but dnsplan.Record does not omit the field, and a zero
// value would make "grey on purpose" indistinguishable from "nobody decided".
func (p Prover) Record(l lane.Lane, identity, anchor string) (dnsplan.Record, error) {
	value, err := p.Expected(l, identity, anchor)
	if err != nil {
		return dnsplan.Record{}, err
	}
	name := Name(anchor)
	if name == "" {
		return dnsplan.Record{}, fmt.Errorf("%w: anchor has no challenge name", ErrProof)
	}
	return dnsplan.Record{Type: "TXT", Name: name, Value: value, Proxied: false}, nil
}

// message is the exact byte string every proof is a MAC over.
//
//	"ms-dns-ownership/v1\x00" + lane + "\x00" + identity + "\x00" + anchor
//
// 🔴 PIN IT. Changing any part — the version tag, the separator, the order, the
// normalization — changes every proof value in existence, and every customer who
// published the one we gave them would find their domain quietly stopped
// advancing, with a correct-looking record in their zone and nothing to tell them
// why. TestGoldenValue exists so that cost is paid at a failing build instead of
// at a support queue.
//
// 🔴 THE LANE IS INSIDE THE MAC. The three lanes are not degrees of one
// permission (docs/DESIGN.md §2): lane 1 puts MirrorStack in front of four fixed
// hostnames, lane 2 hands us `*.<anchor>` — every name under the domain,
// including ones the customer has not thought of — and lane 3 binds one hostname
// to one app whose owner may be a person with no organization anywhere. A
// customer who agreed to one has not agreed to another.
//
// 🔴 NO COMPONENT MAY CONTAIN THE SEPARATOR, which is what keeps the encoding
// injective. An identity permitted to carry a NUL could re-partition the flat
// concatenation: (lane, "x\x00example.com", "") and (lane, "x", "example.com")
// are identical bytes, so one proof would authorize two registrations. NUL cannot
// occur in a DNS name, a UUID or a lane.
func (p Prover) message(l lane.Lane, identity, anchor string) ([]byte, error) {
	if p.Sealer == nil {
		// No keyset means no proof, never a proof under an absent key: that would
		// be one constant shared by every customer of this deployment.
		return nil, fmt.Errorf("%w: %w", ErrProof, grantcrypto.ErrNoKeyset)
	}
	// The anchor is normalized and the identity case-folded because this value
	// lives in somebody else's zone: an id spelled in upper case, or an anchor with
	// a trailing root dot, would mint a second proof for the same registration and
	// silently invalidate the record the customer already published. Folding the
	// identity is safe BECAUSE §5 pins it to a canonical hyphenated UUID, whose
	// spelling is case-insensitive; this line would have to go if a case-sensitive
	// identifier ever arrived here.
	lanePart := string(l)
	identity = strings.ToLower(strings.TrimSpace(identity))
	anchor = dnsplan.NormalizeName(anchor)
	// The lane is taken verbatim: its vocabulary is closed and owned by package
	// lane, and folding it here would accept spellings that package rejects.
	for _, part := range []string{lanePart, identity, anchor} {
		if part == "" || strings.Contains(part, separator) {
			return nil, fmt.Errorf("%w: lane, identity and anchor must each be present and separator-free", ErrProof)
		}
	}
	return []byte(messagePrefix + separator + lanePart + separator + identity + separator + anchor), nil
}

// encode renders a MAC as the string a customer types into a DNS provider's web
// form. Chosen for a human and a web form, not for density: the value is copied
// off a MirrorStack screen, typed into somebody else's control panel, stored by a
// system we have never seen, and read back by us out of public DNS, so it may
// only contain characters that survive that whole round trip.
//
// base32 (RFC 4648), lowercase, unpadded. Case-insensitive by construction, and
// DNS tooling does fold case; base64 would not survive that at all, because two
// distinct MACs can differ only in the case of one character and folding would
// make them one value. Its alphabet is A–Z and 2–7 — no 0, 1, 8 or 9, so 0/O and
// 1/l cannot be confused reading a value off one screen onto another — and it
// holds no `+`, `/`, `=`, quote, backslash, semicolon, space or newline, so
// nothing a zone file's quoting rules, or a form that trims and splits on
// whitespace, can mangle, escape or truncate. Padding is dropped because `=` is
// the character most often stripped in transit; lowercase because the rest of
// this service normalizes DNS data to it, so a value read back needs one fold
// rather than two.
//
// 32 bytes encode to 52 characters, 57 with the prefix. One TXT character-string
// holds 255, so the value is never chunked and there is no ambiguity about how a
// multi-string TXT reassembles: the record has exactly one string, compared
// whole.
func encode(mac []byte) string {
	return valuePrefix + strings.ToLower(
		base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mac))
}

// fold normalizes a value observed in public DNS into the form encode produces.
// The quote stripping is for the customer who pasted `"msv1-…"`: quotes are a
// zone file's syntax rather than part of the value, and some panels hand them
// back. Nothing here widens what is accepted — the value still has to be the
// right 52 characters.
func fold(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	return strings.ToLower(strings.TrimSpace(value))
}
