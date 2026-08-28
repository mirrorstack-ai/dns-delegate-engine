// Package proof derives the one record in a delegated DNS plan that this
// service must never write: the TXT at `_mirrorstack-challenge.<anchor>` that
// demonstrates the customer controls the name every other record hangs beneath.
//
// 🔴 A PROOF WE PUBLISH OURSELVES PROVES NOTHING.
//
// The ownership record used to be inside the set this service published, and
// the gate on proceeding was a public lookup of that same record. So the proof
// was satisfied by our own write, and "the customer proved they own this anchor"
// was a sentence with no fact behind it. Anchor containment still bounded every
// plan to a subtree — but a subtree of a name nobody had demonstrated any claim
// to, which is a bound on blast radius rather than on authority.
//
// Splitting the record into two halves is the entire fix, and neither half is
// sufficient alone:
//
//   - The VALUE is a MAC under a key that never leaves this deployment, so
//     nobody outside it can mint one for a domain, an identity or a lane they
//     were not given. It is not a secret from the customer — we show it to them
//     — it is a secret from everyone else, including from a compromised private
//     half that wants to aim this service at a name it has no claim to.
//   - PUBLISHING it requires control of the zone, which is exactly the thing
//     being demonstrated, and it is the half we deliberately cannot perform.
//
// That is why `verify` re-checks the record on EVERY pass rather than once at
// registration. Ownership of a domain is not a fact established forever by one
// lookup; it is a fact that can stop being true the day a domain changes hands,
// and a standing grant that outlives it would be a credential aimed at somebody
// else's zone.
//
// Nothing here talks to a DNS provider, a resolver, a database or the network.
// It is a pure function of (lane, identity, anchor) and this deployment's
// keyset, so the derivation can be read and tested without a Cloudflare account.
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
// The trailing dot is part of the constant so that `Prefix + anchor` is the
// whole name and no call site has to remember to add a separator — the version
// of this bug that ships is the one that silently produces
// `_mirrorstack-challengeexample.com`, a name that resolves to nothing and a
// verification that never passes.
//
// It sits at the ANCHOR itself, never at a derived host. One record has to cover
// every hostname a lane derives, and a proof published at `account.example.com`
// would say nothing whatsoever about `api.example.com` — they can be delegated
// to different people. Proving the shared parent is what makes the four siblings
// on lane 1, or every future `<slug>.example.net` on lane 2, provable at all.
const Prefix = "_mirrorstack-challenge."

// ErrProof is the single refusal this package returns.
//
// Deliberately ONE error at the boundary, for the reason dnsplan gives: naming
// which component was rejected tells a caller — and through it an attacker —
// which half of a guess was wrong. The specific cause travels in the wrapped
// text, which is what logs and tests read.
var ErrProof = errors.New("proof: cannot compute an ownership proof")

const (
	// hkdfInfo is the HKDF domain separator for the ownership proof, and it is
	// namespaced on purpose. Sealer.MAC is a general primitive; a second use of
	// it that picked a colliding info would share a subkey with this one, and a
	// value minted for that other purpose could then be published at the
	// challenge name and pass verification. A fully-qualified name cannot
	// collide by accident.
	hkdfInfo = "github.com/mirrorstack-ai/dns-delegate-engine/internal/proof:ownership/v1"

	// messagePrefix versions the MAC input independently of the encoding. It is
	// inside the MAC rather than beside it, so a future v2 message shape can
	// never produce a v1 value.
	messagePrefix = "ms-dns-ownership/v1"

	// separator joins the message components. NUL because it cannot occur in a
	// DNS name, a UUID or a lane, which is what makes the concatenation
	// injective — see message.
	separator = "\x00"

	// valuePrefix makes a published proof self-identifying in a zone somebody
	// else inherits, and versions the ENCODING separately from the message: a
	// value that starts `msv1-` is one this build knows how to read.
	valuePrefix = "msv1-"
)

// Name is the owner of the ownership proof: `_mirrorstack-challenge.<anchor>`.
//
// 🔴 IT RETURNS "" RATHER THAN A NAME THAT CANNOT BE RIGHT. Empty is the
// dangerous case: a caller that concatenated a prefix onto nothing and handed
// the result to a provider would create a record at the ZONE APEX. That is not a
// hypothetical class of bug — Cloudflare returns its ownership-verification
// object with empty strings once the proof is no longer required, and an
// unguarded read of it published exactly that write. A name that is half-right
// is worse than no name, because only the empty one fails loudly.
//
// The anchor is normalized first, so the caller's spelling — trailing root dot,
// mixed case, stray whitespace — cannot produce two different names for one
// domain and send a customer looking for a record at a name we never derived.
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

// Prover computes ownership proofs under this deployment's keyset.
//
// A struct rather than an interface: there is exactly one derivation of this
// value, and a seam here would be a seam a caller could substitute a
// permissive implementation into. The Sealer is the only dependency, and a zero
// Prover fails closed rather than computing a proof with no key — a proof under
// an absent key would be a constant, identical for every customer.
type Prover struct{ Sealer *grantcrypto.Sealer }

// Expected is the single value the customer is told to publish — the MAC under
// the active key.
//
// It is what a console renders and what a support answer quotes. Accepted, not
// this, is what a verifier compares against, because a rotation must not
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

// Accepted is every value verify() will accept: one per key in the keyset.
//
// 🔴 ROTATION MUST NOT BREAK A PUBLISHED PROOF. A customer who published the
// value we gave them must not wake up to a domain that stopped advancing because
// we rotated a key they never saw. Retiring a key is therefore a deliberate act
// with a customer-visible consequence: it invalidates every proof published
// under it, and every affected customer has to edit a TXT record in their own
// zone before their domain advances again. Dropping a key from the keyset is a
// migration with a support cost, never a cleanup.
//
// A caller comparing against this set by hand must fold case and compare in
// constant time. Use Matches, which does both.
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
// registration accepts.
//
// 🔴 THE COMPARISON IS CONSTANT-TIME, AND THAT IS NOT CEREMONY HERE. The
// candidate is entirely attacker-controlled — it is whatever somebody published
// at a public name — while the expected value is the secret being guessed, which
// is the exact shape a byte-at-a-time comparison leaks. An attacker who cannot
// obtain (lane, someone else's org id, that org's domain) any other way can
// otherwise ask us to compare, repeatedly, and read the answer off the clock.
//
// Observed values are folded before comparison — trimmed, unquoted, lowercased —
// because that is the whole reason the encoding is case-insensitive base32. A
// customer's DNS control panel may echo a TXT value back in a different case or
// wrapped in the zone file's quotes, and a proof that broke on that would send
// them to support with a record that looks correct on their screen.
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
			// No early return: the loop runs to completion so its duration does
			// not report how far down the list the match was found.
			if hmac.Equal([]byte(candidate), []byte(want)) {
				match = true
			}
		}
	}
	return match, nil
}

// Record is the ownership row as it appears in a plan.
//
// 🔴 THE SOURCE IS THE CUSTOMER: THIS SERVICE MUST NEVER PUBLISH THIS RECORD.
// That is the whole fix — a proof we write ourselves proves nothing, so a plan
// that included this row in what it hands a provider would return the design to
// the defect it was built to close. It is here in Record form for one reason
// only: `describe` renders the same bytes for the manual path and the delegated
// path from one function, so the list a customer is told to add by hand cannot
// drift from the list this service reasons about.
//
// Proxied is false and explicit. It is meaningless for a TXT — Cloudflare's
// orange cloud applies to a hostname, not to a TXT record — but dnsplan.Record
// deliberately does not omit the field, and leaving it to a zero value would
// make "grey on purpose" indistinguishable from "nobody decided".
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
// normalization — changes every proof value in existence. Every customer who
// published the value we gave them would find their domain quietly stopped
// advancing, with a correct-looking record in their zone and nothing to tell
// them why. A change here is a migration with a customer-visible cost, never a
// tidy-up, and TestGoldenValue exists so that cost is paid at a failing build
// instead of at a support queue.
//
// 🔴 THE LANE IS INSIDE THE MAC. A console proof does not authorize an
// app-domain wildcard, and neither authorizes a domain on a single app. The
// three are not degrees of one permission: lane 1 puts MirrorStack in front of
// four fixed hostnames, lane 2 hands us `*.<anchor>` — every name under the
// domain, including ones the customer has not thought of — and lane 3 binds one
// hostname to one app whose owner may be a person with no organization anywhere.
// A customer who agreed to the first has not agreed to the second. Making each a
// separate, deliberate act costs one field in a MAC.
//
// 🔴 NO COMPONENT MAY CONTAIN THE SEPARATOR, and that is what keeps the encoding
// injective. The message is a flat concatenation, so an identity permitted to
// carry a NUL could re-partition it: (lane, "x\x00example.com", "") and
// (lane, "x", "example.com") would produce identical bytes, and one proof would
// authorize two registrations. NUL cannot occur in a DNS name, a UUID or a lane,
// so refusing it costs nothing and closes the question permanently.
func (p Prover) message(l lane.Lane, identity, anchor string) ([]byte, error) {
	if p.Sealer == nil {
		// No keyset means no proof — never a proof under an absent key, which
		// would be one constant shared by every customer of this deployment.
		return nil, fmt.Errorf("%w: %w", ErrProof, grantcrypto.ErrNoKeyset)
	}
	// The anchor is normalized and the identity is case-folded because this
	// value lives in somebody else's zone. A call site that spelled the id in
	// upper case, or passed the anchor with a trailing root dot, would otherwise
	// mint a second proof for the same registration and silently invalidate the
	// record the customer already published. Folding the identity is safe
	// specifically BECAUSE §5 pins it to a canonical hyphenated UUID, whose
	// spelling is case-insensitive by definition; it would not be safe for a
	// case-sensitive identifier, and this line would have to go if one ever
	// arrived here.
	lanePart := string(l)
	identity = strings.ToLower(strings.TrimSpace(identity))
	anchor = dnsplan.NormalizeName(anchor)
	// The lane is taken verbatim: its vocabulary is closed and owned by package
	// lane, and folding it here would be this package quietly accepting spellings
	// that package rejects.
	for _, part := range []string{lanePart, identity, anchor} {
		if part == "" || strings.Contains(part, separator) {
			return nil, fmt.Errorf("%w: lane, identity and anchor must each be present and separator-free", ErrProof)
		}
	}
	return []byte(messagePrefix + separator + lanePart + separator + identity + separator + anchor), nil
}

// encode renders a MAC as the string a customer types into a DNS provider's web
// form.
//
// 🔴 THE ENCODING IS CHOSEN FOR A HUMAN AND A WEB FORM, NOT FOR DENSITY. This
// value is copied off a MirrorStack screen, pasted or typed into somebody else's
// control panel, stored by a system we have never seen, and read back by us out
// of public DNS. It may therefore only contain characters that survive that
// whole round trip:
//
//   - base32 (RFC 4648) is case-insensitive by construction, and DNS tooling
//     does fold case. base64 would not survive that at all: two distinct MACs
//     can differ only in the case of one character, so folding would make them
//     the same value.
//   - Its alphabet is A–Z and 2–7 — no 0, 1, 8 or 9 — so 0/O and 1/l cannot be
//     confused by someone reading the value off one screen and onto another.
//   - It contains no `+`, `/`, `=`, quote, backslash, semicolon, space or
//     newline: nothing a zone file's quoting rules, or a form that trims and
//     splits on whitespace, can mangle, escape or truncate. Padding is dropped
//     for the same reason — `=` is the character most often stripped in transit.
//   - Lowercase because that is what the rest of this service normalizes DNS
//     data to, so a value read back needs one fold rather than two.
//
// 32 bytes encode to 52 characters, 57 with the prefix. One TXT
// character-string holds 255, so the value is never chunked and there is no
// ambiguity about how a multi-string TXT reassembles — the record has exactly
// one string, and a resolver's answer is compared whole.
func encode(mac []byte) string {
	return valuePrefix + strings.ToLower(
		base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mac))
}

// fold normalizes a value observed in public DNS into the form encode produces.
//
// The quote stripping is for the customer who pasted `"msv1-…"` — quotes are
// part of a zone file's syntax rather than of the value, and some panels hand
// them back. Trimming and case folding are the same tolerance the encoding was
// chosen to make safe. Nothing here widens what is accepted: the value still has
// to be the right 52 characters.
func fold(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	return strings.ToLower(strings.TrimSpace(value))
}
