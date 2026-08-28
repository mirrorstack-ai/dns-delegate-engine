package proof

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/grantcrypto"
)

// fuzzKeysetJSON builds a keyset of `ids` with `active` as the active key.
//
// The material is derived from each key id rather than from its position, so a
// keyset the fuzzer reorders or re-points is the SAME keys with a different
// active one — which is exactly the shape a rotation has, and the shape a test
// that derived material from an index would silently fail to produce.
//
// Nothing here reaches a secrets manager, a network or a disk: the keyset is a
// literal, so every target in this file is a pure function of its input.
func fuzzKeysetJSON(t testing.TB, ids []string, active string) string {
	t.Helper()
	keys := make(map[string]string, len(ids))
	for _, id := range ids {
		raw := make([]byte, grantcrypto.KeySize)
		for j := range raw {
			raw[j] = id[j%len(id)] ^ byte(j)
		}
		keys[id] = base64.StdEncoding.EncodeToString(raw)
	}
	encoded, err := json.Marshal(struct {
		Active string            `json:"active"`
		Keys   map[string]string `json:"keys"`
	}{active, keys})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// fuzzProver builds a Prover over a literal keyset.
func fuzzProver(t testing.TB, ids []string, active string) Prover {
	t.Helper()
	keys, err := grantcrypto.ParseKeyset(fuzzKeysetJSON(t, ids, active))
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := grantcrypto.NewSealer(keys)
	if err != nil {
		t.Fatal(err)
	}
	return Prover{Sealer: sealer}
}

// fuzzProofKey is the (lane, identity, anchor) triple AFTER the normalization
// the derivation documents: the lane verbatim, the identity trimmed and folded,
// the anchor normalized.
//
// It is what "differ in any of lane, identity or anchor" has to mean. Two
// spellings of one anchor are one registration on purpose — a customer who typed
// a trailing root dot must not be handed a second proof that invalidates the
// record already in their zone — so a target that compared raw bytes would be
// asserting the opposite of the design.
func fuzzProofKey(l lane.Lane, identity, anchor string) string {
	return string(l) + "\x00" +
		strings.ToLower(strings.TrimSpace(identity)) + "\x00" +
		dnsplan.NormalizeName(anchor)
}

// fuzzProofSeeds is the (lane, identity, anchor) corpus every proof target
// starts from: the three lanes, the spellings a control panel or a caller
// actually produces, and the shapes the derivation must refuse.
func fuzzProofSeeds() []struct{ lane, identity, anchor string } {
	const identity = "11111111-2222-3333-4444-555555555555"
	return []struct{ lane, identity, anchor string }{
		{string(lane.OrgPlatformDomain), identity, "example.com"},
		{string(lane.OrgAppDomain), identity, "example.net"},
		{string(lane.AppDomain), identity, "example.org"},
		{string(lane.OrgPlatformDomain), strings.ToUpper(identity), "EXAMPLE.COM"},
		{string(lane.OrgPlatformDomain), "  " + identity + "  ", "  example.com.  "},
		{string(lane.OrgAppDomain), identity, "a.b.c.example.org"},
		{string(lane.AppDomain), "00000000-0000-0000-0000-000000000000", "example.com"},
		// Refusals: an absent component, and the separator that would make the
		// concatenation re-partitionable.
		{"", identity, "example.com"},
		{string(lane.AppDomain), "", "example.com"},
		{string(lane.AppDomain), identity, ""},
		{string(lane.AppDomain), identity, "."},
		{string(lane.AppDomain), "x\x00example.com", ""},
		{string(lane.AppDomain), "x", "\x00example.com"},
		{"not_a_lane", identity, "example.com"},
		{string(lane.AppDomain), identity, strings.Repeat("a.", 200) + "example.com"},
	}
}

// FuzzProofValueIsAlwaysPublishableAsTXT asserts the claim a customer meets in
// person: the ownership proof is a value they can TYPE into their own DNS
// provider's web form, and get back out again unchanged.
//
// For ANY lane, identity and anchor the derivation accepts, the value must be
// non-empty, short enough to be a single TXT character-string with room to spare
// (255 is the wire cap; this stays under 64), and contain only characters that
// survive a zone file, a form that trims and splits on whitespace, and a copy
// off one screen onto another: no quote, no backslash, no whitespace, no control
// byte, no non-ASCII, no `=`, `+`, `/` or `;`.
//
// A value that needs escaping is a value that gets mistyped, and a mistyped proof
// is a domain that silently never advances with a correct-looking record sitting
// in the customer's zone.
func FuzzProofValueIsAlwaysPublishableAsTXT(f *testing.F) {
	prover := fuzzProver(f, []string{"k1", "k2"}, "k1")
	for _, seed := range fuzzProofSeeds() {
		f.Add(seed.lane, seed.identity, seed.anchor)
	}

	f.Fuzz(func(t *testing.T, laneRaw, identity, anchor string) {
		value, err := prover.Expected(lane.Lane(laneRaw), identity, anchor)
		if err != nil {
			if value != "" {
				t.Fatalf("Expected refused but returned %q; a refusal must hand the customer nothing", value)
			}
			return
		}

		if value == "" {
			t.Fatalf("Expected(%q, %q, %q) accepted and produced an empty proof", laneRaw, identity, anchor)
		}
		if len(value) > 64 {
			t.Fatalf("proof value is %d bytes; one TXT character-string holds 255 and this must stay well under it: %q", len(value), value)
		}
		if !strings.HasPrefix(value, valuePrefix) {
			t.Fatalf("proof value %q does not identify itself with %q, so a zone somebody inherits cannot tell what it is", value, valuePrefix)
		}
		for i := 0; i < len(value); i++ {
			c := value[i]
			if c < 0x21 || c > 0x7e {
				t.Fatalf("proof value %q carries byte %#x at %d — whitespace, a control byte or non-ASCII does not survive a DNS form", value, c, i)
			}
			if strings.IndexByte("\"\\=+/; '`,()", c) >= 0 {
				t.Fatalf("proof value %q carries %q at %d, which a zone file or a web form can escape, split or truncate", value, c, i)
			}
		}
		// Everything after the self-identifying prefix is lowercase base32
		// (RFC 4648): a-z and 2-7 only, so 0/O and 1/l cannot be confused by
		// someone reading the value off one screen and onto another.
		for i, c := range value[len(valuePrefix):] {
			if (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7') {
				continue
			}
			t.Fatalf("proof value %q carries %q at %d, outside the case-insensitive base32 alphabet", value, c, i+len(valuePrefix))
		}
		if value != strings.ToLower(value) {
			t.Fatalf("proof value %q is not lowercase, so reading it back out of DNS would need two folds rather than one", value)
		}
		// The value the customer publishes is the value we would verify. A
		// derivation that was not a pure function of its input would mean a
		// support answer quoting one value and a verifier expecting another.
		if again, err := prover.Expected(lane.Lane(laneRaw), identity, anchor); err != nil || again != value {
			t.Fatalf("Expected is not deterministic: %q then (%q, %v)", value, again, err)
		}
	})
}

// FuzzProofBindsLaneIdentityAndAnchor asserts the claim that makes each lane a
// separate, deliberate act of consent.
//
// 🔴 THE LANE IS INSIDE THE MAC. A console proof does not authorize an app-domain
// wildcard, and neither authorizes a domain bound to a single app. Lane 1 puts
// MirrorStack in front of four fixed hostnames; lane 2 hands us `*.<anchor>` —
// every name under the domain, including ones the customer has not thought of;
// lane 3 binds one hostname to one app. A customer who agreed to the first has
// not agreed to the second, so the proof for one must be worthless on another.
//
// For ANY two inputs: if they normalize to the same (lane, identity, anchor)
// they must produce the SAME value — two spellings of one anchor are one
// registration, and a second value would strand the record the customer already
// published. If they normalize to different triples, the values must DIFFER. That
// is the injectivity the NUL separator buys: no identity may carry the separator,
// so no triple can be re-partitioned into another one, and no proof can be moved
// between a lane, an org or a domain it was not minted for.
func FuzzProofBindsLaneIdentityAndAnchor(f *testing.F) {
	prover := fuzzProver(f, []string{"k1"}, "k1")
	seeds := fuzzProofSeeds()
	for i, a := range seeds {
		b := seeds[(i+1)%len(seeds)]
		f.Add(a.lane, a.identity, a.anchor, b.lane, b.identity, b.anchor)
	}
	// The pairs that matter most: one component apart, everything else identical.
	const id1 = "11111111-2222-3333-4444-555555555555"
	const id2 = "11111111-2222-3333-4444-555555555556"
	f.Add(string(lane.OrgPlatformDomain), id1, "example.com", string(lane.OrgAppDomain), id1, "example.com")
	f.Add(string(lane.OrgAppDomain), id1, "example.com", string(lane.AppDomain), id1, "example.com")
	f.Add(string(lane.AppDomain), id1, "example.com", string(lane.AppDomain), id2, "example.com")
	f.Add(string(lane.AppDomain), id1, "example.com", string(lane.AppDomain), id1, "example.net")
	f.Add(string(lane.AppDomain), id1, "example.com", string(lane.AppDomain), strings.ToUpper(id1), "EXAMPLE.COM.")
	// The re-partitioning attempt the separator exists to close.
	f.Add(string(lane.AppDomain), "x\x00example.com", "y", string(lane.AppDomain), "x", "example.com\x00y")

	f.Fuzz(func(t *testing.T, lane1, identity1, anchor1, lane2, identity2, anchor2 string) {
		value1, err1 := prover.Expected(lane.Lane(lane1), identity1, anchor1)
		value2, err2 := prover.Expected(lane.Lane(lane2), identity2, anchor2)

		same := fuzzProofKey(lane.Lane(lane1), identity1, anchor1) ==
			fuzzProofKey(lane.Lane(lane2), identity2, anchor2)

		if same {
			if (err1 == nil) != (err2 == nil) {
				t.Fatalf("one registration, two answers: (%q,%q,%q) -> %v but (%q,%q,%q) -> %v",
					lane1, identity1, anchor1, err1, lane2, identity2, anchor2, err2)
			}
			if err1 == nil && value1 != value2 {
				t.Fatalf("one registration spelled two ways produced two proofs: (%q,%q,%q) = %q, (%q,%q,%q) = %q",
					lane1, identity1, anchor1, value1, lane2, identity2, anchor2, value2)
			}
			return
		}

		if err1 != nil || err2 != nil {
			return
		}
		if value1 == value2 {
			t.Fatalf("🔴 one proof authorizes two registrations: (%q,%q,%q) and (%q,%q,%q) both produce %q",
				lane1, identity1, anchor1, lane2, identity2, anchor2, value1)
		}
	})
}

// FuzzAcceptedAlwaysContainsExpected asserts the claim a customer is owed after
// they have done their part: ROTATION MUST NOT BREAK A PUBLISHED PROOF.
//
// A customer who published the value we handed them must not wake up to a domain
// that stopped advancing because we rotated a key they never saw. So for any
// keyset — any number of keys, any one of them active — the set a verifier
// accepts must contain the value a console shows, and Matches must say yes to it
// through the manglings a real DNS control panel performs: quoting it, or echoing
// it back in a different case.
func FuzzAcceptedAlwaysContainsExpected(f *testing.F) {
	for _, seed := range fuzzProofSeeds() {
		f.Add(seed.lane, seed.identity, seed.anchor, uint8(0))
	}
	const identity = "11111111-2222-3333-4444-555555555555"
	for _, shape := range []uint8{1, 2, 7, 9, 23, 57, 200, 255} {
		f.Add(string(lane.OrgAppDomain), identity, "example.com", shape)
	}

	f.Fuzz(func(t *testing.T, laneRaw, identity, anchor string, shape uint8) {
		// One keyset shape per input: 1..8 keys, with any one of them active —
		// including a keyset whose active key is not the first, which is what a
		// rotation actually looks like.
		count := int(shape%8) + 1
		ids := make([]string, 0, count)
		for i := 0; i < count; i++ {
			ids = append(ids, string(rune('a'+i))+"-key")
		}
		prover := fuzzProver(t, ids, ids[int(shape>>3)%count])

		shown, err := prover.Expected(lane.Lane(laneRaw), identity, anchor)
		accepted, acceptedErr := prover.Accepted(lane.Lane(laneRaw), identity, anchor)
		if err != nil {
			if acceptedErr == nil {
				t.Fatalf("Expected refused but Accepted returned %d values", len(accepted))
			}
			return
		}
		if acceptedErr != nil {
			t.Fatalf("Expected produced %q but Accepted refused: %v", shown, acceptedErr)
		}
		if len(accepted) != count {
			t.Fatalf("keyset of %d keys accepted %d values", count, len(accepted))
		}

		found := false
		for _, candidate := range accepted {
			if candidate == shown {
				found = true
			}
		}
		if !found {
			t.Fatalf("🔴 the value we hand the customer is not one a verifier accepts: Expected = %q, Accepted = %q (%d keys, active %q)",
				shown, accepted, count, prover.Sealer.ActiveKeyID())
		}

		// The same claim through the front door, and through what a control panel
		// does to a value on its way back out of public DNS.
		for _, observed := range []string{shown, `"` + shown + `"`, strings.ToUpper(shown), "  " + shown + "  "} {
			ok, err := prover.Matches(lane.Lane(laneRaw), identity, anchor, []string{observed})
			if err != nil {
				t.Fatalf("Matches(%q): %v", observed, err)
			}
			if !ok {
				t.Fatalf("🔴 a published proof stopped verifying once a panel touched it: %q", observed)
			}
		}
	})
}
