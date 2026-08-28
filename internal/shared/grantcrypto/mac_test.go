package grantcrypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

const macInfo = "test/mac/v1"

func macOf(t *testing.T, s *Sealer, info string, message string) ([]byte, [][]byte) {
	t.Helper()
	active, all := s.MAC(info, []byte(message))
	if len(active) != MACSize {
		t.Fatalf("active MAC is %d bytes, want %d", len(active), MACSize)
	}
	return active, all
}

// 🔴 THE SUBKEY IS NOT THE SEALING KEY. If MAC ever HMAC'd with the raw keyset
// entry, every proof this service publishes into a customer's public zone would
// be a chosen-message sample against the key that seals Cloudflare refresh
// tokens — and rotating one would mean rotating the other. This test is the only
// thing standing between "we derive a subkey" and a one-line change that drops
// the derivation because the tests still passed.
func TestMACDoesNotUseTheSealingKeyDirectly(t *testing.T) {
	s := sealerFor(t, "k1")
	active, _ := macOf(t, s, macInfo, "message")

	raw := hmac.New(sha256.New, s.keys.Keys["k1"])
	raw.Write([]byte("message"))
	if bytes.Equal(active, raw.Sum(nil)) {
		t.Fatal("the MAC is HMAC under the raw sealing key: the HKDF derivation is gone")
	}
}

// 🔴 'info' IS THE DOMAIN SEPARATOR, AND IT HAS TO ACTUALLY SEPARATE. A second
// use of MAC that reused another use's info would let a value minted for one
// purpose be presented as a proof of the other.
func TestMACSeparatesDomains(t *testing.T) {
	s := sealerFor(t, "k1")
	one, _ := macOf(t, s, "purpose/one", "message")
	two, _ := macOf(t, s, "purpose/two", "message")
	if bytes.Equal(one, two) {
		t.Fatal("two different info strings produced the same MAC")
	}
}

// Go randomizes map iteration order per range, so an unsorted result would
// differ between two calls in ONE process. Anything that logs, hashes or golden
// tests the set would be flaky for no reason.
func TestMACIsDeterministicAcrossCalls(t *testing.T) {
	s := sealerFor(t, "kb", "ka", "kc")
	_, first := macOf(t, s, macInfo, "message")
	for i := 0; i < 32; i++ {
		_, again := macOf(t, s, macInfo, "message")
		if len(again) != len(first) {
			t.Fatalf("call %d returned %d MACs, want %d", i, len(again), len(first))
		}
		for j := range first {
			if !bytes.Equal(first[j], again[j]) {
				t.Fatalf("call %d differs from the first at position %d", i, j)
			}
		}
	}
}

// One MAC per key, and the active one is among them. A verifier walks 'all'
// precisely so it does not have to know which key is active.
func TestMACCoversEveryKeyAndIncludesTheActiveOne(t *testing.T) {
	s := sealerFor(t, "k1", "k2", "k3")
	active, all := macOf(t, s, macInfo, "message")
	if len(all) != 3 {
		t.Fatalf("got %d MACs for a 3-key keyset", len(all))
	}
	found := false
	for i, mac := range all {
		if len(mac) != MACSize {
			t.Fatalf("MAC %d is %d bytes, want %d", i, len(mac), MACSize)
		}
		if hmac.Equal(mac, active) {
			found = true
		}
	}
	if !found {
		t.Fatal("the active MAC is not in the accepted set")
	}
	// Every key must contribute a DISTINCT MAC, or 'all' is quietly one key wide
	// and rotation coverage is imaginary.
	for i := range all {
		for j := i + 1; j < len(all); j++ {
			if bytes.Equal(all[i], all[j]) {
				t.Fatalf("MACs %d and %d are identical: two keys produced one value", i, j)
			}
		}
	}
}

// 🔴 ROTATION MUST NOT BREAK A PUBLISHED PROOF. A customer who published the
// value we gave them must still verify after we rotate a key they never saw. The
// accepted SET is therefore stable across a rotation that only moves 'active';
// only the value we hand out next moves. The fixture keys are derived from their
// ids, so reordering the ids rotates without changing any key's material.
func TestMACSetIsStableAcrossRotation(t *testing.T) {
	before, beforeAll := macOf(t, sealerFor(t, "k1", "k2"), macInfo, "message")
	after, afterAll := macOf(t, sealerFor(t, "k2", "k1"), macInfo, "message")

	if len(beforeAll) != len(afterAll) {
		t.Fatalf("the accepted set changed size across a rotation: %d then %d", len(beforeAll), len(afterAll))
	}
	for i := range beforeAll {
		if !bytes.Equal(beforeAll[i], afterAll[i]) {
			t.Fatalf("the accepted set changed at position %d across a rotation", i)
		}
	}
	if bytes.Equal(before, after) {
		t.Fatal("the active MAC did not move when the active key did")
	}
	// The value published before the rotation is still accepted after it.
	accepted := false
	for _, mac := range afterAll {
		if hmac.Equal(mac, before) {
			accepted = true
		}
	}
	if !accepted {
		t.Fatal("a proof minted under the pre-rotation key is no longer accepted")
	}
}

// MAC has no error to return, so a nil 'active' IS the refusal. Encoding a
// zero-length MAC would publish a proof every keyset in the world agrees on.
func TestMACFailsClosed(t *testing.T) {
	s := sealerFor(t, "k1")
	for name, call := range map[string]func() ([]byte, [][]byte){
		"empty info":    func() ([]byte, [][]byte) { return s.MAC("", []byte("message")) },
		"empty message": func() ([]byte, [][]byte) { return s.MAC(macInfo, nil) },
		"active key missing": func() ([]byte, [][]byte) {
			// A Keyset assembled in code rather than by ParseKeyset can violate
			// the invariant ParseKeyset enforces.
			broken := &Sealer{keys: &Keyset{Active: "gone", Keys: s.keys.Keys}}
			return broken.MAC(macInfo, []byte("message"))
		},
		"key of the wrong length": func() ([]byte, [][]byte) {
			// hkdf.Key over a truncated key returns a perfectly ordinary-looking
			// MAC, so the width has to be checked rather than assumed.
			broken := &Sealer{keys: &Keyset{
				Active: "short",
				Keys:   map[string][]byte{"short": make([]byte, KeySize-1)},
			}}
			return broken.MAC(macInfo, []byte("message"))
		},
	} {
		active, all := call()
		if active != nil || all != nil {
			t.Fatalf("%s: returned a MAC instead of failing closed", name)
		}
	}
}
