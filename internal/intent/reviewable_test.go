package intent

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
)

// 🔴 THE REVIEWABLE SET AND THE DIGEST MUST BE THE SAME SET.
//
// A caller shows the customer a list, they authorize, and Complete binds what
// gets written to a digest. If the list and the digest cover different records,
// the review is of one thing and the bound is of another — and the customer has
// no way to tell, because both come back from the same call.
//
// This asserts the two agree by RECOMPUTING the digest from the reviewable
// identities alone, so a change to either side fails here rather than in a
// consent screen.
func TestTheReviewableSetIsExactlyWhatTheDigestBinds(t *testing.T) {
	for _, tc := range []struct {
		name     string
		lane     lane.Lane
		identity string
		domain   string
	}{
		{"platform", lane.OrgPlatformDomain, testOrg, platformDomain},
		{"app parent", lane.OrgAppDomain, testOrg, appParent},
		{"app domain", lane.AppDomain, testOrg, appHostname},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			out := h.register(t, tc.lane, tc.identity, tc.domain)

			if len(out.Reviewable) == 0 {
				t.Fatal("a registration must publish the set its digest binds")
			}

			// Rebuild the snapshot from the reviewable identities and check it
			// reproduces the digest the same response carried.
			records := make([]dnsplan.Record, 0, len(out.Reviewable))
			for _, id := range out.Reviewable {
				rec, ok := recordFromIdentity(id)
				if !ok {
					t.Fatalf("reviewable identity is not TYPE|name|value: %q", id)
				}
				records = append(records, rec)
			}
			reg := h.open(t, out.Registration)
			snapshot, err := dnsplan.NewSnapshot(snapshotKind(reg.Lane), reg.Identity, reg.Anchor, records)
			if err != nil {
				t.Fatalf("the reviewable set is not a publishable plan: %v", err)
			}
			if got := hex.EncodeToString(snapshot.Digest()); got != out.Digest {
				t.Fatalf("reviewable set does not reproduce the digest\n got: %s\nwant: %s", got, out.Digest)
			}
		})
	}
}

// 🔴 REVIEWABLE NOW EQUALS Records, AND THE OWNERSHIP ROW IS IN BOTH.
//
// It was a STRICT subset, because Records carried the ownership proof and that
// row was the customer's to publish. Both halves changed with the gate: the
// proof stopped gating Authorize, Complete and Advance, so a row nobody writes
// and nothing reads is a manual step for no effect, and derive.ownershipItem
// publishes it like any other.
//
// What must still hold is that the customer reviews EVERYTHING this service
// writes. Reviewing fewer rows than are published is the defect the equality
// catches — the set is what Complete's digest binds.
func TestTheReviewableSetIsEverythingThisServiceWrites(t *testing.T) {
	h := newHarness(t)
	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)

	if len(out.Reviewable) != len(out.Records) {
		t.Fatalf("reviewable (%d) must equal records (%d): everything derived is written",
			len(out.Reviewable), len(out.Records))
	}
	seen := false
	for _, id := range out.Reviewable {
		rec, ok := recordFromIdentity(id)
		if !ok {
			t.Fatalf("malformed identity %q", id)
		}
		if rec.Name == proofName(t, out) {
			seen = true
		}
	}
	if !seen {
		t.Fatal("the ownership proof must appear in the set this service binds itself to writing")
	}
}

func proofName(t *testing.T, out RegisteredResponse) string {
	t.Helper()
	return dnsplan.NormalizeName(out.Proof.Name)
}

// recordFromIdentity parses the TYPE|name|value form dnsplan emits. Local to the
// test on purpose: a caller comparing identities does exactly this, so parsing
// them here is the same act the contract promises is possible.
func recordFromIdentity(id string) (dnsplan.Record, bool) {
	parts := strings.SplitN(id, "|", 3)
	if len(parts) != 3 {
		return dnsplan.Record{}, false
	}
	return dnsplan.Record{Type: parts[0], Name: parts[1], Value: parts[2]}, true
}
