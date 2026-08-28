package grantcrypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"sort"
	"strings"
)

// MACSize is the width of every value MAC produces. HMAC-SHA256 is 32 bytes,
// fixed here rather than left for a caller to infer, so a short or empty result
// is a length check away from being caught instead of being encoded and handed
// to a customer as a proof.
const MACSize = sha256.Size

// EncodeMAC renders a MAC as the string it travels as: prefix, then RFC 4648
// base32, lowercase and unpadded.
//
// Chosen for a human and a form, not for density: an ownership proof is copied
// off a MirrorStack screen, typed into somebody else's DNS control panel, stored
// by a system we have never seen and read back out of public DNS, so it may only
// hold characters that survive that whole round trip. base32 is
// case-insensitive by construction and DNS tooling does fold case; base64 would
// not survive that at all, because two distinct MACs can differ only in the case
// of one character. Its alphabet is A–Z and 2–7 — no 0, 1, 8 or 9, so 0/O and
// 1/l cannot be confused reading a value off one screen onto another — and it
// holds no `+`, `/`, `=`, quote, backslash, semicolon, space or newline, so
// nothing a zone file's quoting rules, or a form that trims and splits on
// whitespace, can mangle, escape or truncate. Padding is dropped because `=` is
// the character most often stripped in transit; lowercase because the rest of
// this service normalizes DNS data to it.
//
// 32 bytes encode to 52 characters. One TXT character-string holds 255, so a
// published value is never chunked and there is no ambiguity about how a
// multi-string TXT reassembles.
//
// The prefix is the caller's: it makes a value self-identifying wherever it is
// found, and versions the ENCODING separately from the message the MAC covers.
func EncodeMAC(prefix string, mac []byte) string {
	return prefix + strings.ToLower(
		base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mac))
}

// MAC computes HMAC-SHA256 under an HKDF-derived subkey of every key in the
// keyset. It returns the MAC under the ACTIVE key first, then a MAC under every
// key in the keyset (active included).
//
// 🔴 NO KEY MATERIAL LEAVES THIS PACKAGE. The subkey is derived rather than
// used directly so a MAC can never be confused with, or used to attack, the
// AES-GCM sealing key: 'info' is the domain separator.
//
// That separation is load-bearing rather than hygienic. The one caller publishes
// its output as a DNS TXT value — a string this service deliberately hands to a
// customer and expects to find in public DNS — while the same keyset seals
// Cloudflare refresh tokens. Using one key for both would make every published
// proof a free chosen-message sample against the key protecting the credentials,
// and it would make "rotate the MAC key" and "rotate the sealing key" the same
// irreversible act. HKDF gives each use an independent subkey, so a caller that
// picks a fresh 'info' gets a fresh key without an operator touching anything.
//
// Why 'all' exists: a MAC this service published once may be sitting in a
// customer's zone for months. Verifying only under the active key would mean a
// key rotation silently stopped every domain that was already proven. The set is
// the same idea as Open using the ENVELOPE's key rather than the active one —
// rotation is a decrypt-side and verify-side concern, never a re-publish request
// aimed at the customer.
//
// Why 'all' is sorted by key id: Go randomizes map iteration order per range, so
// walking s.keys.Keys directly would return the same set in a different order on
// two calls in ONE process. Anything that logged, hashed, diffed or golden-tested
// the set would then be flaky for no reason at all. Sorting by id — deliberately
// NOT active-first — also keeps the order stable across a rotation that only
// flips Active, and keeps the ordering from encoding which key is active, since
// 'all' is precisely the set a verifier walks so that it does not need to know.
//
// 🔴 COMPARE THE RESULT WITH hmac.Equal, NEVER WITH bytes.Equal OR ==. The
// candidate a verifier checks is attacker-controlled (it is whatever is published
// at a public name) and the expected value is the secret, so a byte-at-a-time
// comparison is a timing oracle on the MAC.
//
// It fails closed: an empty 'info' (no domain separation), an empty message, a
// keyset whose active key is missing, or any derivation failure returns
// (nil, nil). A caller must treat a nil 'active' as a refusal — MAC has no error
// to return, so the nil IS the refusal, and encoding a zero-length MAC would
// publish a proof that every keyset agrees on.
func (s *Sealer) MAC(info string, message []byte) (active []byte, all [][]byte) {
	if info == "" || len(message) == 0 {
		return nil, nil
	}
	// Derived from s.keys.Active directly rather than lifted out of the loop, so
	// 'active' and 'all' are two independent answers and a test asserting that
	// 'all' contains 'active' is asserting something.
	active, ok := s.macUnder(s.keys.Active, info, message)
	if !ok {
		return nil, nil
	}
	ids := make([]string, 0, len(s.keys.Keys))
	for id := range s.keys.Keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	all = make([][]byte, 0, len(ids))
	for _, id := range ids {
		sum, ok := s.macUnder(id, info, message)
		if !ok {
			return nil, nil
		}
		all = append(all, sum)
	}
	return active, all
}

// macUnder derives one key's subkey and MACs the message with it.
//
// The key lookup is checked rather than assumed. ParseKeyset guarantees the
// active key is present, but a Keyset assembled in code does not, and hkdf.Key
// over a nil secret returns a perfectly ordinary-looking MAC that every empty
// keyset in the world would agree on.
func (s *Sealer) macUnder(id, info string, message []byte) ([]byte, bool) {
	key, ok := s.keys.Keys[id]
	if !ok || len(key) != KeySize {
		return nil, false
	}
	// No salt: the input is already a full-entropy 32-byte key rather than a
	// password or a shared secret with structure, so HKDF's salt has nothing to
	// do here. 'info' carries the whole separation, which is why an empty one is
	// refused above.
	subkey, err := hkdf.Key(sha256.New, key, nil, info, KeySize)
	if err != nil {
		return nil, false
	}
	mac := hmac.New(sha256.New, subkey)
	mac.Write(message)
	return mac.Sum(nil), true
}
