package dnsplan

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

const (
	testTarget = "3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f607"
	testAnchor = "example.com"
)

func goldenRecords() []Record {
	return []Record{
		{Type: "CNAME", Name: "app.example.com", Value: "edge.mirrorstack.ai", Proxied: true},
		{Type: "CNAME", Name: "_acme-challenge.app.example.com", Value: "x.acm-validations.aws"},
		{Type: "TXT", Name: "_cf-custom-hostname.app.example.com", Value: "abc123"},
	}
}

// 🔴 GOLDEN DIGEST — DO NOT REGENERATE TO MAKE A FAILURE GO AWAY.
//
// api-platform computes this same SHA-256 over this same fixture in
// TestDelegatedPlanGoldenDigest. The two repositories must agree byte for byte:
// api-platform derives and persists the digest before a customer authorizes,
// and this service re-derives it before it writes anything.
//
// If this test fails, a marshalled field changed. That invalidates every
// in-flight attempt in production — every customer mid-connect would be told the
// plan changed. Fix the drift; do not update the constant unless you are
// deliberately versioning the envelope (bump Version, and expect exactly that
// invalidation).
const goldenDigestHex = "c5fdeb2a95fd30f6091eb8ac9583561547a2481ab4bea5ce2e0fbc2ef494874c"

func TestGoldenDigest(t *testing.T) {
	snapshot, err := NewSnapshot(KindPlatform, testTarget, testAnchor, goldenRecords())
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	if got := hex.EncodeToString(snapshot.Digest()); got != goldenDigestHex {
		t.Fatalf("digest drift\n got: %s\nwant: %s", got, goldenDigestHex)
	}
}

// 🔴 NORMALIZATION MUST BE A FIXED POINT.
//
// Validate re-normalizes what NewSnapshot stored and refuses when the two
// disagree, so a name that normalizes differently on the second pass is accepted
// at authorize time and refused at publish time — reported as plan_invalid,
// whose contract says "this is a bug and retrying cannot help". A customer is
// then stranded mid-connect on a domain that is perfectly fine.
//
// Found by fuzzing: trimming the root dot AFTER trimming space uncovered a space
// the first trim had already run past, so "example.com ." became "example.com ".
func TestNormalizeNameIsIdempotent(t *testing.T) {
	for _, in := range []string{
		"example.com", "EXAMPLE.COM", " example.com ", "example.com.",
		"example.com .", "example.com. ", " example.com . ", "example.com..",
		"_acme-challenge.api.example.com.", "*.example.net.", "", ".", " . ",
	} {
		once := NormalizeName(in)
		if twice := NormalizeName(once); once != twice {
			t.Errorf("NormalizeName(%q) = %q, but normalizing that again gives %q", in, once, twice)
		}
		if strings.TrimSpace(once) != once {
			t.Errorf("NormalizeName(%q) = %q, which still carries whitespace", in, once)
		}
	}
}

// The consequence, asserted end to end: anything NewSnapshot accepts must
// survive its own Validate. The two gates run at different moments in one
// customer's connect and have to agree on every input, not only the tidy ones.
func TestWhatNewSnapshotAcceptsAlwaysValidates(t *testing.T) {
	long := strings.Repeat("t", MaxRecordIdentity)
	for _, tc := range []struct {
		name, anchor string
		records      []Record
	}{
		{"a stray space before the root dot", "shop.example.com .",
			[]Record{{Type: "CNAME", Name: "www.shop.example.com", Value: "edge.example.net"}}},
		{"a doubled root dot", "example.com..",
			[]Record{{Type: "CNAME", Name: "account.example.com", Value: "edge.example.net"}}},
		{"an identity at the bound", "example.com",
			[]Record{{Type: "TXT", Name: "_dcv.example.com", Value: long}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot, err := NewSnapshot(KindPlatform, testTarget, tc.anchor, tc.records)
			if err != nil {
				return // a refusal is always allowed; it is ACCEPTANCE that must hold up
			}
			if err := snapshot.Validate(snapshot.Digest()); err != nil {
				t.Fatalf("NewSnapshot accepted a plan its own Validate refuses: %v", err)
			}
		})
	}
}

// 🔴 THE DIGEST MUST BIND EVERY BYTE OF EVERY RECORD.
//
// Digest hashes json.Marshal of the envelope, and encoding/json SILENTLY folds
// each invalid UTF-8 byte to U+FFFD rather than failing — so two plans whose
// values genuinely differed hashed to one SHA-256. The digest is what binds what
// a customer reviewed to what gets written; a collision in it is that binding
// not existing.
//
// Found by FuzzDigestIsStableAndBinding. The fix refuses the input rather than
// repairing it: no legitimate DNS record carries invalid UTF-8, and a digest
// taken over a repaired value would bind the repair rather than the record.
func TestInvalidUTF8CannotCollideTwoPlansIntoOneDigest(t *testing.T) {
	build := func(value string) (Snapshot, error) {
		return NewSnapshot(KindPlatform, testTarget, "example.com",
			[]Record{{Type: "TXT", Name: "_cf-custom-hostname.example.com", Value: value}})
	}
	a, errA := build("token-\xff")
	b, errB := build("token-\xfe")
	if errA == nil || errB == nil {
		t.Fatalf("invalid UTF-8 must be refused outright: %v / %v", errA, errB)
	}
	// If it ever stops being refused, it must at least stop colliding.
	if errA == nil && errB == nil && bytes.Equal(a.Digest(), b.Digest()) {
		t.Fatal("two records differing byte-for-byte produced one digest")
	}
	if _, err := build("token-ok"); err != nil {
		t.Fatalf("valid UTF-8 must still be accepted: %v", err)
	}
}

// 🔴 THE SUFFIX-CONFUSION CASE, PINNED DIRECTLY AGAINST Contains.
//
// This test exists because a mutation found the gap: deleting the leading dot
// from Contains — so that `evilexample.com` counts as being under
// `example.com` — SURVIVED this package's entire suite. The table below names a
// "suffix-confusion neighbour", but its anchor is `app.example.com`, and
// `evilexample.com` is not a near-miss for that anchor: it does not end in it at
// all, with or without the dot. The case read correct and asserted nothing.
//
// The property did hold, but only because packages elsewhere happened to
// exercise it. That is not a bound a customer can rely on — deleting an
// unrelated test in internal/lane or internal/relay would have left the most
// quoted claim in the README unguarded. It is pinned here now, next to the code
// it is about.
func TestContainsRequiresALabelBoundary(t *testing.T) {
	cases := []struct {
		anchor, name string
		want         bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "account.example.com", true},
		{"example.com", "*.example.com", true},
		{"example.com", "_acme-challenge.api.example.com", true},

		// Each of these ENDS WITH the anchor string and must still be refused,
		// because the character before it is not a dot. This is the shape the
		// mutation exposed.
		{"example.com", "evilexample.com", false},
		{"example.com", "notexample.com", false},
		{"example.com", "xexample.com", false},
		{"app.example.com", "evilapp.example.com", false},
		{"shop.example.com", "myshop.example.com", false},

		// The anchor is not under its own child, and a parent is never reachable.
		{"shop.example.com", "example.com", false},
		{"example.com", "com", false},

		// Normalization must not open a hole: case and a trailing dot are the
		// two spellings the same name arrives in.
		{"EXAMPLE.com", "Account.Example.COM.", true},
		{"example.com", "evilexample.com.", false},

		{"", "example.com", false},
		{"example.com", "", false},
	}
	for _, tc := range cases {
		if got := Contains(tc.anchor, tc.name); got != tc.want {
			t.Errorf("Contains(%q, %q) = %v, want %v", tc.anchor, tc.name, got, tc.want)
		}
	}
}

func TestContainmentRefusesEscape(t *testing.T) {
	cases := []struct {
		name   string
		record string
	}{
		{"the apex above the anchor", "example.com.evil.test"},
		{"a sibling that merely shares a suffix", "notexample.com"},
		{"a suffix-confusion neighbour", "evilexample.com"},
		{"an unrelated zone", "www.someone-else.test"},
		{"the parent of the anchor", "com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			records := append(goldenRecords(), Record{
				Type: "CNAME", Name: tc.record, Value: "edge.mirrorstack.ai",
			})
			_, err := NewSnapshot(KindPlatform, testTarget, "app.example.com", records)
			if !errors.Is(err, ErrAnchorEscape) {
				t.Fatalf("want ErrAnchorEscape, got %v", err)
			}
			if !errors.Is(err, ErrPlanInvalid) {
				t.Fatalf("ErrAnchorEscape must wrap ErrPlanInvalid so the caller keeps one opaque boundary; got %v", err)
			}
		})
	}
}

// A customer zone is the case the public claim is about: the anchor is a name in
// somebody else's zone, and the grant covers that whole zone. Platform-zone
// coverage alone would prove nothing about the situation a customer is worried
// about.
func TestContainmentInACustomerZone(t *testing.T) {
	anchor := "shop.customer-owned.example"
	ok := []string{anchor, "www." + anchor, "*." + anchor, "_acme-challenge." + anchor}
	for _, name := range ok {
		if !Contains(anchor, name) {
			t.Fatalf("%q must be inside %q", name, anchor)
		}
	}
	// The records a customer fears losing: their apex, their www, their mail.
	notOK := []string{"customer-owned.example", "www.customer-owned.example", "mail.customer-owned.example", ""}
	for _, name := range notOK {
		if Contains(anchor, name) {
			t.Fatalf("%q must NOT be inside %q", name, anchor)
		}
	}
}

func TestContainmentIsCaseAndTrailingDotInsensitive(t *testing.T) {
	if !Contains("Example.COM.", "APP.example.com") {
		t.Fatal("anchor matching must fold case and the root dot")
	}
}

func TestValidateRejectsAStoredEscape(t *testing.T) {
	snapshot, err := NewSnapshot(KindPlatform, testTarget, testAnchor, goldenRecords())
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	digest := snapshot.Digest()

	// Simulate a row written by a build that predates containment: the records
	// escape, but the digest is self-consistent, so only a re-check catches it.
	tampered := snapshot
	tampered.Records = append([]Record(nil), snapshot.Records...)
	tampered.Identities = append([]string(nil), snapshot.Identities...)
	tampered.Records[0].Name = "www.someone-else.test"
	tampered.Identities[0] = "CNAME|www.someone-else.test|edge.mirrorstack.ai"
	if err := tampered.Validate(tampered.Digest()); !errors.Is(err, ErrAnchorEscape) {
		t.Fatalf("a self-consistent stored escape must still be refused, got %v", err)
	}

	// And an ordinary digest mismatch is still an ordinary refusal. Copy first:
	// append(digest[:31], ...) would write through digest's own backing array.
	wrong := append([]byte(nil), digest...)
	wrong[31] ^= 0xff
	if err := snapshot.Validate(wrong); !errors.Is(err, ErrPlanInvalid) {
		t.Fatalf("want ErrPlanInvalid on digest mismatch, got %v", err)
	}
	if err := snapshot.Validate(digest); err != nil {
		t.Fatalf("the untampered snapshot must validate: %v", err)
	}
}

func TestNormalizeRecordsDedupesAndCanonicalizes(t *testing.T) {
	records := []Record{
		{Type: " cname ", Name: "  APP.Example.com. ", Value: " edge.mirrorstack.ai "},
		{Type: "CNAME", Name: "app.example.com", Value: "edge.mirrorstack.ai"},
	}
	out, identities, err := NormalizeRecords(records)
	if err != nil {
		t.Fatalf("NormalizeRecords: %v", err)
	}
	if len(out) != 1 || len(identities) != 1 {
		t.Fatalf("want one deduped record, got %d", len(out))
	}
	if identities[0] != "CNAME|app.example.com|edge.mirrorstack.ai" {
		t.Fatalf("identity not canonical: %q", identities[0])
	}
}

func TestNormalizeRecordsRejectsUnsupportedTypes(t *testing.T) {
	// An A record, an MX record and an NS record are exactly the records a
	// customer's own site depends on. The plan vocabulary admits neither.
	for _, kind := range []string{"A", "AAAA", "MX", "NS", "SOA", ""} {
		_, _, err := NormalizeRecords([]Record{{Type: kind, Name: "example.com", Value: "1.2.3.4"}})
		if !errors.Is(err, ErrPlanPreparing) {
			t.Fatalf("type %q must be refused, got %v", kind, err)
		}
	}
}

func TestCanonicalUUIDIsStrict(t *testing.T) {
	if _, ok := CanonicalUUID(strings.ToUpper(testTarget)); !ok {
		t.Fatal("uppercase canonical form must be accepted")
	}
	got, ok := CanonicalUUID(strings.ToUpper(testTarget))
	if !ok || got != testTarget {
		t.Fatalf("must normalize to lowercase, got %q", got)
	}
	for _, bad := range []string{
		"",
		"3f2a1b4c5d6e4f708a91b2c3d4e5f607",       // unhyphenated
		"{3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f607}", // braced
		"3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f60",    // short
		"3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f60g",   // non-hex
		"3f2a1b4c_5d6e_4f70_8a91_b2c3d4e5f607",   // wrong separator
	} {
		if _, ok := CanonicalUUID(bad); ok {
			t.Fatalf("%q must be refused", bad)
		}
	}
}

func TestCoveredByAllowsGrowthNotShrinkageOrMutation(t *testing.T) {
	reviewed, err := NewSnapshot(KindPlatform, testTarget, testAnchor, goldenRecords()[:2])
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	grown, err := NewSnapshot(KindPlatform, testTarget, testAnchor, goldenRecords())
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	if !reviewed.CoveredBy(grown) {
		t.Fatal("a sibling finishing preparation must not strand the customer")
	}
	if grown.CoveredBy(reviewed) {
		t.Fatal("a shrunken plan is a plan the operator did not review")
	}

	mutated := goldenRecords()[:2]
	mutated[0].Value = "attacker.example"
	changed, err := NewSnapshot(KindPlatform, testTarget, testAnchor, mutated)
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	if reviewed.CoveredBy(changed) {
		t.Fatal("a mutated value is a different record")
	}

	other, err := NewSnapshot(KindApp, testTarget, testAnchor, goldenRecords())
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	if reviewed.CoveredBy(other) {
		t.Fatal("a different kind is a different authorization")
	}
}

func TestAssertReviewedNeverDecodesIntoAWrite(t *testing.T) {
	authoritative := []string{
		"CNAME|app.example.com|edge.mirrorstack.ai",
		"TXT|_cf.app.example.com|abc",
	}
	if err := AssertReviewed([]string{authoritative[1], authoritative[0]}, authoritative); err != nil {
		t.Fatalf("order must not matter: %v", err)
	}
	bad := [][]string{
		{},
		{authoritative[0]},
		{authoritative[0], authoritative[0]},
		{"CNAME|app.example.com|edge.mirrorstack.ai", "TXT|_cf.app.example.com|WRONG"},
		{"CNAME|APP.EXAMPLE.COM|edge.mirrorstack.ai", authoritative[1]}, // not normalized
		{"nonsense", authoritative[1]},
		{"A|app.example.com|1.2.3.4", authoritative[1]},
	}
	for i, reviewed := range bad {
		if err := AssertReviewed(reviewed, authoritative); !errors.Is(err, ErrPlanChanged) {
			t.Fatalf("case %d must be refused, got %v", i, err)
		}
	}
}

func TestPlanSizeIsBounded(t *testing.T) {
	records := make([]Record, 0, MaxRecords+1)
	for i := 0; i <= MaxRecords; i++ {
		records = append(records, Record{
			Type: "TXT", Name: "r.example.com", Value: strings.Repeat("x", i+1),
		})
	}
	if _, err := NewSnapshot(KindPlatform, testTarget, testAnchor, records); !errors.Is(err, ErrPlanPreparing) {
		t.Fatalf("an oversized plan must be refused, got %v", err)
	}
	if _, err := NewSnapshot(KindPlatform, testTarget, testAnchor, nil); !errors.Is(err, ErrPlanPreparing) {
		t.Fatalf("an empty plan must be refused, got %v", err)
	}
}
