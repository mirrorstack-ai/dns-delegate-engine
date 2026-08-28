package sealed

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/grantcrypto"
)

// ---------------------------------------------------------------------------
// Properties, over arbitrary input.
//
// The example-based tests in sealed_test.go name the cases somebody thought of.
// These name the CLAIM instead, and Go's fuzzer looks for the case nobody did.
// Every target here is offline by construction: the only thing it touches is a
// keyset built from a constant in this file. No network, no database, no
// Cloudflare account, no clock that a fuzzed input can move.
// ---------------------------------------------------------------------------

// Two registration envelopes, sealed once under testSealer's key and pasted
// here rather than re-sealed at run time.
//
// 🔴 THEY ARE CONSTANTS BECAUSE A FUZZ TARGET MUST BE DETERMINISTIC. AES-GCM
// draws a fresh random nonce per seal, so an envelope minted inside the target
// would make the tampered string a different string on every run, and a failure
// the fuzzer reported this morning would not reproduce this afternoon.
//
// The two differ in PLAINTEXT LENGTH on purpose. base64's encoded length is not
// a whole number of input bytes for every input, and which of the two shapes an
// envelope lands in turns out to matter — see FuzzTamperedCiphertextNeverOpens.
const (
	// A lane-1 registration: no consent reference. Ciphertext length is a
	// multiple of 3, so its base64 form has no spare bits.
	fuzzEnvelopeNoReference = "v1.test-k1.VZaEp2IGErRp+77p.hZixj5yMN52Hqb+CGDPK5TWpQCK5XPM5ODJhCcxsiBtjG2YyEv5PgY+Y7k41hCsy09wMrmbGiDvqKMVL3RrICtxWAOmTkvdYaYCDotjqgdGls4YvILd58XJuOn469pPn4/tCi1CMWZR60a8CBjgICeTiyKzV7FbTeXHBc2NCkVOD4SjBF4/swKD/qMaRj6H+xEhYv88NjXFo"

	// The same registration carrying a consent reference. Its ciphertext length
	// is NOT a multiple of 3.
	fuzzEnvelopeWithReference = "v1.test-k1.xgiHIeiaFh6ZllND.hi3L+Vmv1dLARN7dIGb4fexew1VAqh/Gv6/pmUwkOEDjcM4G8EHP9y6NYNpnCFWBx6SvkbHSxiWa7gYYIPaAbRArC/SjeT1r+13yzpNngHNEULn/Bldds9qC636ZuXVypf+0U6aaglkYDm0o9YUhn503V0+CfFeaxBM0tufeWOsCwvczq9GjmSKFTw24pCNSDvvsqcMxX6ksv5ANzy+ycCUjSwWtmiia1EdNtmk/V0nHyZ2gaDGQzEaur6gES5qn2KjCUxA+0e3h+PE"
)

// FuzzArbitraryBytesNeverOpen encodes the README's claim that MirrorStack's
// private half "can keep an envelope and it can withhold one — it cannot
// author, edit or reorder one".
//
// 🔴 THE FAILURE THIS EXISTS TO CATCH IS A SILENT ONE: an Open that returns a
// nil error together with an empty or half-built value. Every caller in this
// service reads the identity, the lane and the anchor straight out of what Open
// returned; a zero-valued Registration accepted as real is a registration on
// lane "", for identity "", anchored at "" — a value with no owner and no
// containment bound, arriving on the path that decides what may be written into
// a customer's zone.
//
// So for ANY string at all, both Open functions must either refuse, or hand
// back a value that still satisfies the package's own validate(). There is no
// third answer.
func FuzzArbitraryBytesNeverOpen(f *testing.F) {
	// The tricky cases the example-based tests already name, plus the shapes
	// they do not: a truncation is what a storage layer that clipped a column
	// hands back, and it is not the same input as a flipped byte.
	seeds := []string{
		"",
		" ",
		"v1",
		"v1.test-k1",
		"...",
		"v1.test-k1..",
		// Valid base64 that is not an envelope at all.
		base64.RawStdEncoding.EncodeToString([]byte("this is not an envelope")),
		// Envelope-shaped, with base64 that decodes to nothing meaningful.
		"v1.test-k1.AAAAAAAAAAAAAAAA." + base64.RawStdEncoding.EncodeToString([]byte("not a ciphertext")),
		// A key this deployment does not hold.
		strings.Replace(fuzzEnvelopeNoReference, testKeyID, "retired-k0", 1),
		// A version this build does not know.
		"v2" + strings.TrimPrefix(fuzzEnvelopeNoReference, "v1"),
		// Past the length this package will even attempt.
		strings.Repeat("a", maxEnvelope+1),
		fuzzEnvelopeNoReference,
		fuzzEnvelopeWithReference,
	}
	// One flipped byte, at each of several offsets across the envelope: the
	// version, the key id, the nonce and the ciphertext are four different
	// refusals and a seed corpus should reach all four.
	for _, frac := range []int{0, 4, 12, 20, 40, 60, 80, 99} {
		seeds = append(seeds, fuzzFlipByte(fuzzEnvelopeNoReference, frac))
	}
	// Truncated at each of several lengths, including one byte short.
	base := fuzzEnvelopeWithReference
	for _, frac := range []int{1, 10, 25, 50, 75, 90, 99} {
		seeds = append(seeds, base[:len(base)*frac/100])
	}
	seeds = append(seeds, base[:len(base)-1])
	for _, seed := range seeds {
		f.Add(seed)
	}

	sealer := testSealer(f)
	f.Fuzz(func(t *testing.T, envelope string) {
		if r, err := OpenRegistration(sealer, envelope); err == nil {
			if r == (Registration{}) {
				t.Fatalf("OpenRegistration returned the ZERO registration with a nil error for %q", envelope)
			}
			if err := r.validate(); err != nil {
				t.Fatalf("OpenRegistration returned %+v, which its own validate() refuses: %v", r, err)
			}
			// validate() is the package's rule; these are the three fields a
			// caller reads without asking, spelled out so a validate() that
			// ever stopped covering one of them is still caught here.
			if r.Lane == "" || r.Identity == "" || r.Anchor == "" || r.IssuedAt <= 0 {
				t.Fatalf("OpenRegistration returned a half-built registration %+v", r)
			}
		}

		if a, err := OpenAuthState(sealer, envelope); err == nil {
			if a == (AuthState{}) {
				t.Fatalf("OpenAuthState returned the ZERO auth state with a nil error for %q", envelope)
			}
			if err := a.validate(); err != nil {
				t.Fatalf("OpenAuthState returned %+v, which its own validate() refuses: %v", a, err)
			}
			if a.Lane == "" || a.Identity == "" || a.Anchor == "" || a.Nonce == "" || a.IssuedAt <= 0 {
				t.Fatalf("OpenAuthState returned a half-built auth state %+v", a)
			}
		}

		// A refusal must also be a refusal a caller can act on. Every path out
		// of this package's Open functions is one of two sentinels, and a bare
		// unwrapped error would be one no caller matches.
		if _, err := OpenRegistration(sealer, envelope); err != nil &&
			!errors.Is(err, ErrInvalidEnvelope) && !errors.Is(err, ErrExpired) {
			t.Fatalf("OpenRegistration refused %q with an unclassified error: %v", envelope, err)
		}
		if _, err := OpenAuthState(sealer, envelope); err != nil &&
			!errors.Is(err, ErrInvalidEnvelope) && !errors.Is(err, ErrExpired) {
			t.Fatalf("OpenAuthState refused %q with an unclassified error: %v", envelope, err)
		}
	})
}

// FuzzOneEnvelopeTypeNeverOpensAsTheOther encodes the claim that a REGISTRATION
// and an AUTH STATE are different things, not two readings of one string.
//
// 🔴 WITHOUT DISTINCT AADs THE TEN-MINUTE WINDOW WOULD BE OPTIONAL. Both
// plaintexts carry a lane, an identity and an anchor under the same JSON keys,
// so a registration decoded as a state satisfies every field they share. A
// registration is STANDING and never expires; a state is refused after
// AuthStateTTL. Present a registration where a state is expected and the window
// is not broken, it is simply never reached — the value that arrived never had
// one. The reverse is as bad pointed the other way: a ten-minute value would
// become the permanent identity of a customer's domain.
//
// The refusal must come from the AEAD rather than from a field check further
// in. A field check is a rule someone can relax in a later commit; the AAD is
// arithmetic. That is why grantcrypto.ErrMalformed is asserted and not just
// "some error happened".
func FuzzOneEnvelopeTypeNeverOpensAsTheOther(f *testing.F) {
	for _, wire := range laneWireValues {
		f.Add(wire, testIdentity, testAnchor, testNonce, testIssuedAt, false)
		f.Add(wire, testIdentity, testAnchor, testNonce, testIssuedAt, true)
	}
	// The spellings canonicalize() rewrites on the way in, and the ones it
	// deliberately leaves alone for validate() to report.
	f.Add("org_app_domain", strings.ToUpper(testIdentity), "EXAMPLE.COM.", testReference, testIssuedAt, true)
	f.Add("app_domain", otherIdentity, "  sub.example.net  ", testNonce, int64(1), false)
	f.Add("", "", "", "", int64(0), false)
	f.Add("org_platform_domain", testIdentity, "example.com", "", testIssuedAt, false)

	sealer := testSealer(f)
	f.Fuzz(func(t *testing.T, wire, identity, anchor, nonce string, issuedAt int64, ack bool) {
		l, err := laneOrSkip(wire)
		if err != nil {
			t.Skip()
		}

		registration := Registration{
			Lane: l, Identity: identity, Anchor: anchor,
			ConsentNonce: nonce, IssuedAt: issuedAt,
		}
		if envelope, _, err := SealRegistration(sealer, registration); err == nil {
			// It must be a registration, so this is not a vacuous assertion.
			if _, err := OpenRegistration(sealer, envelope); err != nil {
				t.Fatalf("a registration this package sealed does not open as one: %v", err)
			}
			_, err := OpenAuthState(sealer, envelope)
			if err == nil {
				t.Fatalf("a REGISTRATION opened as an AUTH STATE: %+v", registration)
			}
			if !errors.Is(err, ErrInvalidEnvelope) || !errors.Is(err, grantcrypto.ErrMalformed) {
				t.Fatalf("registration-as-state was refused by a field check rather than by the AEAD: %v", err)
			}
		}

		state := AuthState{
			Lane: l, Identity: identity, Anchor: anchor,
			Nonce: nonce, IssuedAt: issuedAt, ConsentAck: ack,
		}
		if envelope, err := SealAuthState(sealer, state); err == nil {
			_, err := OpenRegistration(sealer, envelope)
			if err == nil {
				t.Fatalf("an AUTH STATE opened as a REGISTRATION: %+v", state)
			}
			if !errors.Is(err, ErrInvalidEnvelope) || !errors.Is(err, grantcrypto.ErrMalformed) {
				t.Fatalf("state-as-registration was refused by a field check rather than by the AEAD: %v", err)
			}
		}
	})
}

// FuzzTamperedCiphertextNeverOpens encodes the claim a stateless service rests
// its whole design on: a value handed back by MirrorStack's private half can be
// treated as this service's own, because no edit to it can change what it says.
//
// 🔴 THE PROPERTY IS ABOUT MEANING, NOT ABOUT BYTES, AND THE DIFFERENCE IS
// MEASURED RATHER THAN ASSUMED. The obvious spelling — "any single-byte edit
// makes Open fail" — is FALSE, and this target is what established that. An
// envelope's last base64 character can carry spare bits that Go's non-strict
// decoder ignores, so an envelope whose ciphertext length is not a multiple of
// three has up to three other spellings that decode to the identical bytes and
// open to the identical registration. Nothing in this repository keys on an
// envelope string, so nothing here is weakened by it; it is recorded in
// FuzzEnvelopeStringsAreNotCanonical below so that a future reader who reaches
// for the string as a dedup or blocklist key finds it stated rather than
// discovers it.
//
// What must hold without exception is the part a customer cares about: an
// edited envelope NEVER means something else. Either it is refused, or it opens
// to exactly the registration that was sealed.
func FuzzTamperedCiphertextNeverOpens(f *testing.F) {
	// Both ciphertext shapes, and the offsets the example-based test names: the
	// first ciphertext byte, the version, the key id, the nonce, and the tag at
	// the very end.
	for _, which := range []uint8{0, 1} {
		for _, pos := range []uint32{0, 1, 3, 4, 11, 12, 20, 40, 120, 200, 296, 297, 298} {
			for _, val := range []uint8{0x00, 'A', 'a', '.', '/', 0xff} {
				f.Add(which, pos, val)
			}
		}
	}

	sealer := testSealer(f)
	f.Fuzz(func(t *testing.T, which uint8, pos uint32, val uint8) {
		base := fuzzEnvelopeNoReference
		if which%2 == 1 {
			base = fuzzEnvelopeWithReference
		}
		want, err := OpenRegistration(sealer, base)
		if err != nil {
			t.Fatalf("the fixture envelope no longer opens, so this target proves nothing: %v", err)
		}

		edited := []byte(base)
		i := int(pos % uint32(len(edited)))
		if edited[i] == val {
			// The no-op edit: the same string, which of course still opens.
			t.Skip()
		}
		edited[i] = val

		// 🔴 THE PROPERTY. An edit may be refused, and it may be ignored by the
		// decoder — it may NEVER change what the envelope says.
		if got, err := OpenRegistration(sealer, string(edited)); err == nil && got != want {
			t.Fatalf("editing byte %d of the envelope to %#x changed what it means:\n got %+v\nwant %+v", i, val, got, want)
		}

		// The strict half, taken where there is no encoding slack to hide in: a
		// change to the ciphertext BYTES must always be refused by GCM. This is
		// the assertion the AEAD is actually responsible for.
		parts := strings.Split(base, ".")
		if len(parts) != 4 {
			t.Fatalf("envelope has %d parts, want 4", len(parts))
		}
		ciphertext, err := base64.RawStdEncoding.DecodeString(parts[3])
		if err != nil || len(ciphertext) == 0 {
			t.Fatalf("decode fixture ciphertext: %v", err)
		}
		j := int(pos) % len(ciphertext)
		if ciphertext[j] == val {
			t.Skip()
		}
		ciphertext[j] = val
		parts[3] = base64.RawStdEncoding.EncodeToString(ciphertext)
		if _, err := OpenRegistration(sealer, strings.Join(parts, ".")); err == nil {
			t.Fatalf("a ciphertext with byte %d set to %#x still opened", j, val)
		} else if !errors.Is(err, ErrInvalidEnvelope) || !errors.Is(err, grantcrypto.ErrMalformed) {
			t.Fatalf("a tampered ciphertext was refused for the wrong reason: %v", err)
		}
	})
}

// FuzzEnvelopeStringsAreNotCanonical records the measured limit of the property
// above, so it is a stated fact rather than something the next reader trips on.
//
// An envelope string is NOT a canonical name for the value it carries: where
// base64 leaves spare bits in the final character, several distinct strings
// open to the identical registration. That is harmless in this repository —
// nothing here keys on the string — and it would stop being harmless the moment
// something outside it deduplicated, blocklisted or compared envelopes by their
// text. Test the plaintext, never the ciphertext string.
func FuzzEnvelopeStringsAreNotCanonical(f *testing.F) {
	f.Add(uint8(0))
	f.Add(uint8(1))

	sealer := testSealer(f)
	f.Fuzz(func(t *testing.T, which uint8) {
		base := fuzzEnvelopeNoReference
		if which%2 == 1 {
			base = fuzzEnvelopeWithReference
		}
		want, err := OpenRegistration(sealer, base)
		if err != nil {
			t.Fatalf("fixture: %v", err)
		}
		// Every alternative spelling that opens at all must open to the SAME
		// registration. A second spelling that meant something else would be a
		// forgery, and that is the line this whole file defends.
		edited := []byte(base)
		last := len(edited) - 1
		orig := edited[last]
		for v := range 256 {
			if byte(v) == orig {
				continue
			}
			edited[last] = byte(v)
			if got, err := OpenRegistration(sealer, string(edited)); err == nil && got != want {
				t.Fatalf("an alternative spelling of the envelope opened to a DIFFERENT registration: %+v", got)
			}
		}
	})
}

// fuzzFlipByte flips one bit of the byte at the given percentage through s, so
// a seed corpus can name "a tampered envelope" without a magic index.
func fuzzFlipByte(s string, percent int) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	b[len(b)*percent/100%len(b)] ^= 0x01
	return string(b)
}

// laneOrSkip parses a lane the way validateSubject will. A fuzzed lane that is
// not one of the three is not an interesting input here: SealRegistration would
// refuse it before an envelope existed to confuse with another.
func laneOrSkip(wire string) (lane.Lane, error) {
	return lane.Parse(wire)
}
