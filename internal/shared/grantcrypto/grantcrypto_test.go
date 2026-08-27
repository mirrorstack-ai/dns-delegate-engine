package grantcrypto

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func testKeyset(t *testing.T, ids ...string) string {
	t.Helper()
	keys := map[string]string{}
	for _, id := range ids {
		// Derived from the ID, never from its position: a rotation fixture
		// reorders the ids, and position-derived material would silently change
		// the bytes under a stable id — making a rotation test pass for the
		// wrong reason.
		raw := make([]byte, KeySize)
		for j := range raw {
			raw[j] = id[j%len(id)] ^ byte(j)
		}
		keys[id] = base64.StdEncoding.EncodeToString(raw)
	}
	b, err := json.Marshal(keysetJSON{Active: ids[0], Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func sealerFor(t *testing.T, ids ...string) *Sealer {
	t.Helper()
	ks, err := ParseKeyset(testKeyset(t, ids...))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSealer(ks)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSealOpenRoundTrip(t *testing.T) {
	s := sealerFor(t, "k1")
	env, id, err := s.Seal("refresh-token-value", "aad-1")
	if err != nil {
		t.Fatal(err)
	}
	if id != "k1" {
		t.Fatalf("key id = %q", id)
	}
	if strings.Contains(env, "refresh-token-value") {
		t.Fatal("the envelope leaks the plaintext")
	}
	got, err := s.Open(env, "aad-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "refresh-token-value" {
		t.Fatalf("round trip = %q", got)
	}
}

// 🔴 THE AAD IS WHAT STOPS A CIPHERTEXT MOVING BETWEEN ROWS. Without it, a
// grant row's sealed token could be copied into another org's row by a database
// write alone and would still decrypt — so org A's credential would be used
// against org A's zone on org B's behalf.
func TestOpenRefusesADifferentAAD(t *testing.T) {
	s := sealerFor(t, "k1")
	env, _, err := s.Seal("secret", "cf-dns-grant\x00org-A\x00dom-1\x00acme.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []string{
		"cf-dns-grant\x00org-B\x00dom-1\x00acme.example", // moved between orgs
		"cf-dns-grant\x00org-A\x00dom-2\x00acme.example", // moved between domains
		"cf-dns-grant\x00org-A\x00dom-1\x00other.example",
		"",
	} {
		if _, err := s.Open(env, wrong); err == nil {
			t.Fatalf("opened under the wrong AAD %q", wrong)
		}
	}
}

// A rotated-away key must fail closed, not silently return garbage.
func TestOpenUnderAKeysetMissingTheKeyFails(t *testing.T) {
	env, _, err := sealerFor(t, "k1").Seal("secret", "aad")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sealerFor(t, "k2").Open(env, "aad"); err == nil {
		t.Fatal("opened an envelope whose key is not in the keyset")
	}
}

// An old key kept in the keyset must still open envelopes sealed under it,
// which is the whole point of `active` being separate from `keys`.
func TestOpenUsesTheEnvelopesKeyNotTheActiveOne(t *testing.T) {
	old := sealerFor(t, "k1", "k2")
	env, id, err := old.Seal("secret", "aad")
	if err != nil {
		t.Fatal(err)
	}
	if id != "k1" {
		t.Fatalf("sealed under %q, want the active key", id)
	}
	// Same key material, but k2 is now active. k1 is still present.
	rotated, err := ParseKeyset(testKeyset(t, "k2", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSealer(rotated)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Open(env, "aad")
	if err != nil {
		t.Fatalf("an envelope sealed under a retired-but-present key must still open: %v", err)
	}
	if got != "secret" {
		t.Fatalf("round trip after rotation = %q", got)
	}
	// And the rotated sealer now seals under the NEW active key.
	_, id2, err := s.Seal("next", "aad")
	if err != nil {
		t.Fatal(err)
	}
	if id2 != "k2" {
		t.Fatalf("sealed under %q after rotation, want k2", id2)
	}
}

// 🔴 A key id travels in the CLEAR inside every envelope. A dot would split a
// three-part envelope into four and make one key's ciphertext parse as
// another's nonce.
func TestParseKeysetRejectsAKeyIDContainingTheSeparator(t *testing.T) {
	raw := make([]byte, KeySize)
	doc, _ := json.Marshal(keysetJSON{
		Active: "v1.bad",
		Keys:   map[string]string{"v1.bad": base64.StdEncoding.EncodeToString(raw)},
	})
	if _, err := ParseKeyset(string(doc)); err == nil {
		t.Fatal("accepted a key id containing the envelope separator")
	}
}

// Every refusal is an error rather than a partial keyset: one that loads with a
// bad key would seal fine and fail to open exactly one row, months later.
func TestParseKeysetRefusalsAreTotal(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, KeySize-1))
	good := base64.StdEncoding.EncodeToString(make([]byte, KeySize))
	for name, raw := range map[string]string{
		"empty":            "",
		"not json":         "{",
		"no active":        `{"keys":{"k1":"` + good + `"}}`,
		"no keys":          `{"active":"k1","keys":{}}`,
		"active missing":   `{"active":"k9","keys":{"k1":"` + good + `"}}`,
		"key wrong length": `{"active":"k1","keys":{"k1":"` + short + `"}}`,
		"key not base64":   `{"active":"k1","keys":{"k1":"!!!"}}`,
		"unnamed key":      `{"active":"k1","keys":{"":"` + good + `"}}`,
	} {
		if _, err := ParseKeyset(raw); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// 🔴 A NIL SEALER MEANS "REVOKE IMMEDIATELY", NEVER "STORE UNSEALED". NewSealer
// refuses a nil keyset rather than degrading to a no-op that would write the
// customer's refresh token in plaintext.
func TestNewSealerRefusesANilKeyset(t *testing.T) {
	if _, err := NewSealer(nil); err == nil {
		t.Fatal("NewSealer(nil) must not produce a working sealer")
	}
}
