package dnsplan

import (
	"bytes"
	"strings"
	"testing"
)

// Property tests for the oldest claim in the README:
//
//	"Can it touch a name you didn't see? No. Every record must sit at or under
//	 the anchor — the exact hostname you proved you own — or the whole plan is
//	 refused."
//
// The example-based tests next door assert that claim for the cases somebody
// thought of. These assert it over arbitrary input, so it also has to hold for
// the cases nobody thought of. Nothing here reaches a network, a database, or a
// Cloudflare account: this package is pure data and pure rules, which is the
// point of it being a separate package.

const (
	fuzzTargetID = "3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f607"
	fuzzAnchor   = "shop.customer-owned.example"
)

// fuzzLabelsContain decides "at or under" the way DNS means it, and the way the
// README's sentence means it: name is at or under anchor exactly when anchor's
// labels are a suffix of name's labels.
//
// This is deliberately NOT the string-suffix test Contains uses. Re-calling
// Contains to check Contains would assert nothing; deriving containment from
// labels means a change to Contains has to survive a second, independent reading
// of the same English claim.
func fuzzLabelsContain(anchor, name string) bool {
	if anchor == "" || name == "" {
		return false
	}
	anchorLabels := strings.Split(anchor, ".")
	nameLabels := strings.Split(name, ".")
	if len(nameLabels) < len(anchorLabels) {
		return false
	}
	offset := len(nameLabels) - len(anchorLabels)
	for i := range anchorLabels {
		if nameLabels[offset+i] != anchorLabels[i] {
			return false
		}
	}
	return true
}

// fuzzParentOf returns the name one label above anchor — the customer's apex,
// when the anchor is a hostname inside their zone. Empty when there is no parent.
func fuzzParentOf(anchor string) string {
	if i := strings.Index(anchor, "."); i >= 0 && i+1 < len(anchor) {
		return anchor[i+1:]
	}
	return ""
}

// FuzzContainsNeverEscapesTheAnchor asserts the README's containment sentence:
// a name is only ever inside the anchor when it IS the anchor, or sits under it
// as a strict subdomain. Everything else — the customer's apex, their www, a
// suffix-confusion neighbour like evilexample.com, an unrelated zone — is outside
// it, for every anchor and every name, not only the ones the unit tests name.
func FuzzContainsNeverEscapesTheAnchor(f *testing.F) {
	// The cases the existing unit tests name, so a plain `go test` exercises
	// them even with no -fuzz.
	seeds := [][2]string{
		{"example.com", "evilexample.com"},       // suffix confusion
		{"example.com", "notexample.com"},        // sibling sharing a suffix
		{"example.com", "example.com."},          // trailing root dot
		{"Example.COM.", "APP.example.com"},      // case + root dot on both sides
		{"example.com", "*.example.com"},         // a wildcard routing record
		{"example.com", "example.com"},           // the anchor itself
		{"", "example.com"},                      // empty anchor
		{"example.com", ""},                      // empty name
		{"example.com", "example"},               // a prefix, not a suffix
		{"example.com", "com"},                   // the parent of the anchor
		{"example.com", "example.com.evil.test"}, // the anchor as a prefix label
		{fuzzAnchor, "www.customer-owned.example"} /* the customer's own www */, {fuzzAnchor, "_acme-challenge." + fuzzAnchor},
		{"a..", "a."}, // a double dot: normalization is not idempotent
	}
	for _, seed := range seeds {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, anchor, name string) {
		normalizedAnchor := NormalizeName(anchor)
		normalizedName := NormalizeName(name)

		got := Contains(anchor, name)

		// The claim, read off the labels rather than off the implementation.
		if want := fuzzLabelsContain(normalizedAnchor, normalizedName); got != want {
			t.Fatalf("Contains(%q, %q) = %v, but label containment of %q under %q is %v",
				anchor, name, got, normalizedName, normalizedAnchor, want)
		}

		if got {
			// "At or under": either the exact hostname, or something strictly
			// longer that ends at a label boundary.
			if normalizedName != normalizedAnchor && !strings.HasSuffix(normalizedName, "."+normalizedAnchor) {
				t.Fatalf("Contains(%q, %q) accepted a name that is neither the anchor nor a subdomain of it", anchor, name)
			}
			if len(normalizedName) < len(normalizedAnchor) {
				t.Fatalf("Contains(%q, %q) accepted a name shorter than the anchor", anchor, name)
			}
		}

		// "Connecting shop.example.com cannot reach example.com": the name one
		// label above the anchor is never inside it.
		if parent := fuzzParentOf(normalizedAnchor); parent != "" && Contains(normalizedAnchor, parent) {
			t.Fatalf("the parent %q must never be inside the anchor %q", parent, normalizedAnchor)
		}

		// Suffix confusion, for an arbitrary anchor rather than for example.com.
		if normalizedAnchor != "" && Contains(anchor, "evil"+normalizedAnchor) {
			t.Fatalf("suffix confusion: %q must not be inside %q", "evil"+normalizedAnchor, normalizedAnchor)
		}

		// An empty anchor is not "everything"; it is nothing.
		if normalizedAnchor == "" && got {
			t.Fatalf("an empty anchor must contain nothing, but contained %q", name)
		}
	})
}

// fuzzKind maps two bits onto the two legal kinds and one that is not, so the
// fuzzer spends most of its budget on plans that can actually be accepted.
func fuzzKind(sel uint8) string {
	switch sel % 3 {
	case 0:
		return KindPlatform
	case 1:
		return KindApp
	default:
		return "platform-ish"
	}
}

func fuzzType(sel uint8) string {
	switch sel % 4 {
	case 0:
		return "CNAME"
	case 1:
		return "TXT"
	case 2:
		return " cname " // must normalize
	default:
		return "A" // must be refused
	}
}

// fuzzUnder builds a name below anchor, so the fuzzer reaches ACCEPTANCE often
// enough for the acceptance invariants to be exercised.
func fuzzUnder(prefix, anchor string) string {
	if prefix == "" {
		return anchor
	}
	return prefix + "." + anchor
}

func fuzzTarget(sel uint8, raw string) string {
	if sel%2 == 0 {
		return fuzzTargetID
	}
	return raw
}

// fuzzCheckAccepted asserts everything the README promises about a plan that was
// ACCEPTED. Refusal is always allowed and asserts nothing.
func fuzzCheckAccepted(t *testing.T, snapshot Snapshot) {
	t.Helper()

	if snapshot.Version != Version {
		t.Fatalf("accepted snapshot has version %d, want %d", snapshot.Version, Version)
	}
	if snapshot.Kind != KindPlatform && snapshot.Kind != KindApp {
		t.Fatalf("accepted snapshot has kind %q", snapshot.Kind)
	}
	if len(snapshot.Records) == 0 || len(snapshot.Records) > MaxRecords {
		t.Fatalf("accepted snapshot has %d records", len(snapshot.Records))
	}
	if len(snapshot.Identities) != len(snapshot.Records) {
		t.Fatalf("accepted snapshot has %d identities for %d records",
			len(snapshot.Identities), len(snapshot.Records))
	}
	for i, record := range snapshot.Records {
		// "Can it write an A record or an MX record? No."
		if record.Type != "CNAME" && record.Type != "TXT" {
			t.Fatalf("accepted record %d has type %q", i, record.Type)
		}
		// "Can it touch a name you didn't see? No."
		if !fuzzLabelsContain(NormalizeName(snapshot.Anchor), NormalizeName(record.Name)) {
			t.Fatalf("accepted record %d names %q, which is not at or under the anchor %q",
				i, record.Name, snapshot.Anchor)
		}
		want := record.Type + "|" + record.Name + "|" + record.Value
		if snapshot.Identities[i] != want {
			t.Fatalf("identity %d is %q, want %q", i, snapshot.Identities[i], want)
		}
	}
	// A plan that was accepted must still be publishable when it is read back
	// out of storage: NewSnapshot and Validate are the same boundary seen from
	// the two ends of a customer's connect.
	if err := snapshot.Validate(snapshot.Digest()); err != nil {
		t.Fatalf("NewSnapshot accepted a plan that Validate refuses: %v\nanchor=%q records=%#v",
			err, snapshot.Anchor, snapshot.Records)
	}
	if !snapshot.Equal(snapshot) || !snapshot.CoveredBy(snapshot) {
		t.Fatal("a snapshot must equal, and be covered by, itself")
	}
}

// FuzzNewSnapshotRefusesEveryEscape fuzzes the ACCEPTANCE side of the claim, not
// the rejection side: whatever NewSnapshot lets through must satisfy the
// promises the README makes about a published plan — every record at or under
// the anchor, CNAME or TXT only, and a snapshot that still validates against its
// own digest when it is read back before the write.
//
// A target that only asserted "bad input is refused" would test the escapes
// somebody imagined. This one tests every escape at once, by pinning what
// acceptance means.
func FuzzNewSnapshotRefusesEveryEscape(f *testing.F) {
	// sel, targetID, anchor, prefix, value, escapee name, escapee value.
	f.Add(uint8(0), fuzzTargetID, "example.com", "app", "edge.mirrorstack.ai", "", "")
	f.Add(uint8(0), fuzzTargetID, "example.com", "_acme-challenge.app", "x.acm-validations.aws", "", "")
	f.Add(uint8(0), fuzzTargetID, "example.com", "*", "edge.mirrorstack.ai", "", "")
	f.Add(uint8(0), fuzzTargetID, "app.example.com", "", "edge.mirrorstack.ai", "evilexample.com", "edge.mirrorstack.ai")
	f.Add(uint8(0), fuzzTargetID, "app.example.com", "", "edge.mirrorstack.ai", "example.com.evil.test", "edge.mirrorstack.ai")
	f.Add(uint8(0), fuzzTargetID, "app.example.com", "", "edge.mirrorstack.ai", "com", "edge.mirrorstack.ai")
	f.Add(uint8(0), fuzzTargetID, fuzzAnchor, "www", "edge.mirrorstack.ai", "www.customer-owned.example", "edge")
	f.Add(uint8(0), fuzzTargetID, "Example.COM.", " APP ", " edge.mirrorstack.ai ", "", "")
	f.Add(uint8(1), "3F2A1B4C-5D6E-4F70-8A91-B2C3D4E5F607", "example.com", "app", "edge", "", "")
	f.Add(uint8(1), "{3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f607}", "example.com", "app", "edge", "", "")
	f.Add(uint8(3), fuzzTargetID, "example.com", "app", "edge", "", "")
	f.Add(uint8(0), fuzzTargetID, "", "app", "edge", "", "")
	f.Add(uint8(0), fuzzTargetID, ".", "app", "edge", "", "")
	f.Add(uint8(0), fuzzTargetID, strings.Repeat("a.", 200)+"example.com", "app", "edge", "", "")

	f.Fuzz(func(t *testing.T, sel uint8, rawID, anchor, prefix, value, escapeeName, escapeeValue string) {
		records := []Record{{
			Type:    fuzzType(sel >> 2),
			Name:    fuzzUnder(prefix, anchor),
			Value:   value,
			Proxied: sel&0x80 != 0,
		}}
		if escapeeName != "" || escapeeValue != "" {
			records = append(records, Record{
				Type:  fuzzType(sel >> 4),
				Name:  escapeeName,
				Value: escapeeValue,
			})
		}

		snapshot, err := NewSnapshot(fuzzKind(sel>>1), fuzzTarget(sel, rawID), anchor, records)
		if err != nil {
			return // a refusal is always allowed
		}
		fuzzCheckAccepted(t, snapshot)
	})
}

// fuzzCopy deep-copies a snapshot so a mutation cannot write through a shared
// backing array into the original.
func fuzzCopy(snapshot Snapshot) Snapshot {
	out := snapshot
	out.Records = append([]Record(nil), snapshot.Records...)
	out.Identities = append([]string(nil), snapshot.Identities...)
	return out
}

// FuzzDigestIsStableAndBinding asserts the digest is what the README says it is:
// the thing that binds the plan a customer saw on their consent screen to the
// plan that gets written. That requires three properties, over arbitrary plans —
// it is the same for the same plan (api-platform recomputes it in a different
// process), equal plans agree on it (or an in-flight connect would be told the
// plan changed when it had not), and a plan differing in ANY byte of ANY record
// disagrees on it (or a substituted record would pass the check).
func FuzzDigestIsStableAndBinding(f *testing.F) {
	// sel, anchor, prefix, value, which field to mutate, replacement bytes.
	f.Add(uint8(0), "example.com", "app", "edge.mirrorstack.ai", uint8(0), "attacker.example")
	f.Add(uint8(0), "example.com", "app", "edge.mirrorstack.ai", uint8(1), "www.example.com")
	f.Add(uint8(0), "example.com", "app", "edge.mirrorstack.ai", uint8(2), "TXT")
	f.Add(uint8(1), "example.com", "_cf-custom-hostname.app", "abc123", uint8(0), "abc124")
	f.Add(uint8(0), fuzzAnchor, "www", "edge.mirrorstack.ai", uint8(0), "edge.mirrorstack.ai.")
	f.Add(uint8(0), "example.com", "app", "edge", uint8(0), "")
	f.Add(uint8(0), "example.com", "app", "a", uint8(0), "b")

	f.Fuzz(func(t *testing.T, sel uint8, anchor, prefix, value string, mutSel uint8, replacement string) {
		snapshot, err := NewSnapshot(fuzzKind(sel>>1), fuzzTargetID, anchor,
			[]Record{{Type: fuzzType(sel >> 2), Name: fuzzUnder(prefix, anchor), Value: value}})
		if err != nil {
			return
		}

		first, second := snapshot.Digest(), snapshot.Digest()
		if len(first) != 32 {
			t.Fatalf("digest length %d", len(first))
		}
		if !bytes.Equal(first, second) {
			t.Fatal("Digest is not deterministic across calls")
		}

		// Equal plans must agree: api-platform derives the same plan in another
		// process and the two digests have to meet.
		clone := fuzzCopy(snapshot)
		if !clone.Equal(snapshot) {
			t.Fatal("a deep copy must be Equal to its original")
		}
		if !bytes.Equal(clone.Digest(), first) {
			t.Fatal("two Equal snapshots produced different digests")
		}

		// A plan differing in any byte of any record must not reproduce the
		// digest a customer authorized.
		mutated := fuzzCopy(snapshot)
		index := int(mutSel>>2) % len(mutated.Records)
		switch mutSel % 3 {
		case 0:
			mutated.Records[index].Value = replacement
		case 1:
			mutated.Records[index].Name = replacement
		default:
			mutated.Records[index].Type = replacement
		}
		mutated.Identities[index] = mutated.Records[index].Type + "|" +
			mutated.Records[index].Name + "|" + mutated.Records[index].Value
		if mutated.Records[index] == snapshot.Records[index] {
			return // not a mutation
		}
		if bytes.Equal(mutated.Digest(), first) {
			t.Fatalf("a record that differs byte-for-byte produced the SAME digest\n"+
				"reviewed: %#v\nwritten:  %#v", snapshot.Records[index], mutated.Records[index])
		}
	})
}

// fuzzIsNormalizedIdentity decides, from the string alone, whether an identity is
// in the canonical TYPE|name|value form AssertReviewed requires.
func fuzzIsNormalizedIdentity(identity string) bool {
	if identity == "" || len(identity) > MaxRecordIdentity {
		return false
	}
	parts := strings.SplitN(identity, "|", 3)
	if len(parts) != 3 {
		return false
	}
	if parts[0] != "CNAME" && parts[0] != "TXT" {
		return false
	}
	if parts[1] == "" || parts[1] != NormalizeName(parts[1]) {
		return false
	}
	return parts[2] != "" && parts[2] == strings.TrimSpace(parts[2])
}

// fuzzIdentities turns a fuzzed blob into a slice, one identity per line, so the
// fuzzer can mutate a set of browser-supplied strings.
func fuzzIdentities(blob string) []string {
	if blob == "" {
		return nil
	}
	return strings.Split(blob, "\n")
}

func fuzzSortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// FuzzAssertReviewedNeverDecodes asserts the rule behind "no browser-supplied
// record is ever decoded into a provider write": the list the browser posts back
// is only ever an ASSERTION that the operator saw this exact set. Its only legal
// output is an error, and it may say "yes" for one reason only — the two sets are
// the same multiset of canonical identities. Anything else, including a set that
// merely looks similar, must be refused, because saying yes to it would let a
// screen the customer never saw authorize a write.
func FuzzAssertReviewedNeverDecodes(f *testing.F) {
	authoritative := "CNAME|app.example.com|edge.mirrorstack.ai\nTXT|_cf.app.example.com|abc"
	f.Add(authoritative, authoritative)
	f.Add("TXT|_cf.app.example.com|abc\nCNAME|app.example.com|edge.mirrorstack.ai", authoritative)               // reordered
	f.Add("", authoritative)                                                                                     // empty
	f.Add("CNAME|app.example.com|edge.mirrorstack.ai", authoritative)                                            // short
	f.Add("CNAME|app.example.com|edge.mirrorstack.ai\nCNAME|app.example.com|edge.mirrorstack.ai", authoritative) // duplicate
	f.Add("CNAME|app.example.com|edge.mirrorstack.ai\nTXT|_cf.app.example.com|WRONG", authoritative)             // mutated value
	f.Add("CNAME|APP.EXAMPLE.COM|edge.mirrorstack.ai\nTXT|_cf.app.example.com|abc", authoritative)               // not normalized
	f.Add("nonsense\nTXT|_cf.app.example.com|abc", authoritative)                                                // no shape
	f.Add("A|app.example.com|1.2.3.4\nTXT|_cf.app.example.com|abc", authoritative)                               // unsupported type
	f.Add("CNAME|app.example.com|edge.mirrorstack.ai\nTXT|_cf.app.example.com|abc ", authoritative)              // trailing space
	f.Add("CNAME|app.example.com.|edge.mirrorstack.ai\nTXT|_cf.app.example.com|abc", authoritative)              // trailing dot
	f.Add(authoritative, "")
	f.Add("|app.example.com|edge", "|app.example.com|edge")
	f.Add(strings.Repeat("CNAME|a.example.com|e\n", MaxRecords+1), authoritative)

	f.Fuzz(func(t *testing.T, reviewedBlob, authoritativeBlob string) {
		reviewed := fuzzIdentities(reviewedBlob)
		authorized := fuzzIdentities(authoritativeBlob)

		err := AssertReviewed(reviewed, authorized)

		// Derive, from the strings alone, whether the two are the same multiset
		// of canonical identities within the bounds the plan allows.
		sortedReviewed := fuzzSortedCopy(reviewed)
		sortedAuthorized := fuzzSortedCopy(authorized)
		same := len(reviewed) > 0 && len(reviewed) <= MaxRecords && len(reviewed) == len(authorized)
		for i, identity := range sortedReviewed {
			if !same {
				break
			}
			if !fuzzIsNormalizedIdentity(identity) || identity != sortedAuthorized[i] {
				same = false
			}
			if i > 0 && identity == sortedReviewed[i-1] {
				same = false // a duplicate is not a set the operator reviewed
			}
		}

		if err == nil && !same {
			t.Fatalf("AssertReviewed accepted a set that is not the authoritative one\nreviewed: %q\nauthoritative: %q",
				reviewed, authorized)
		}
		if err != nil && same {
			t.Fatalf("AssertReviewed refused the authoritative set itself: %v\nreviewed: %q\nauthoritative: %q",
				err, reviewed, authorized)
		}
		// Whatever it decides, its only output is an error: there is no value to
		// carry a browser-supplied string into a write.
		if err == nil && len(reviewed) != len(authorized) {
			t.Fatal("acceptance must imply the sets are the same size")
		}
	})
}
