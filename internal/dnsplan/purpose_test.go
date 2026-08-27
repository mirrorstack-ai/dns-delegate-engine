package dnsplan

import (
	"errors"
	"strings"
	"testing"
)

// Classification is what the record tables in README.md and docs/RECORDS.md are
// written against, so every shape those documents name is pinned here.
func TestClassifyNamesEveryRecordWeCanPublish(t *testing.T) {
	for _, tc := range []struct {
		record Record
		want   Purpose
		why    string
	}{
		{Record{Type: "TXT", Name: "_mirrorstack-challenge.example.com"}, PurposeOwnership,
			"the shared proof at the anchor"},
		{Record{Type: "TXT", Name: "_MIRRORSTACK-CHALLENGE.Example.Com."}, PurposeOwnership,
			"names arrive spelled either way"},
		{Record{Type: "CNAME", Name: "account.example.com"}, PurposeRouting,
			"a connected hostname"},
		{Record{Type: "CNAME", Name: "*.example.app"}, PurposeRouting,
			"the app-domain wildcard"},
		{Record{Type: "CNAME", Name: "_9f8c.account.example.com",
			Value: "_1a2b.acm-validations.aws"}, PurposeCertificate,
			"an AWS ACM validation record"},
		{Record{Type: "TXT", Name: "_acme-challenge.account.example.com"}, PurposeCertificate,
			"a Cloudflare-minted DV challenge"},
		{Record{Type: "CNAME", Name: "_acme-challenge.account.example.com",
			Value: "abc.dcv.cloudflare.com"}, PurposeCertificate,
			"the delegated form of the same challenge"},

		// A name whose first label merely CONTAINS an underscore is not a
		// reserved name, and must not be mistaken for one — it is an ordinary
		// hostname a browser can reach.
		{Record{Type: "CNAME", Name: "my_app.example.com"}, PurposeRouting,
			"underscore not in first position"},
		{Record{Type: "CNAME", Name: "app._internal.example.com"}, PurposeRouting,
			"the reserved label is not the FIRST one"},
	} {
		if got := Classify(tc.record); got != tc.want {
			t.Errorf("Classify(%q) = %q, want %q — %s", tc.record.Name, got, tc.want, tc.why)
		}
	}
}

// The ownership record is identified by a literal label, not by "starts with an
// underscore", because it is the only record in a plan that sits AT the anchor.
// Mistaking it for a certificate record would put the wrong explanation in front
// of a customer at the one step every later step is gated on.
func TestOwnershipIsDistinguishedFromEveryOtherReservedName(t *testing.T) {
	if !strings.HasPrefix(OwnershipLabel, "_") {
		t.Fatalf("OwnershipLabel %q is not a reserved name", OwnershipLabel)
	}
	// Classification of this exact name is covered by the table above; what is
	// new here is that the shared proof counts as validation rather than as
	// something that carries traffic.
	owner := Record{Type: "TXT", Name: OwnershipLabel + ".example.com"}
	if !IsValidation(owner) {
		t.Error("the ownership record carries no traffic and must count as validation")
	}
	// Same label, one level down, is not the shared proof.
	if got := Classify(Record{Type: "TXT", Name: "a." + OwnershipLabel + ".example.com"}); got != PurposeRouting {
		t.Errorf("a name merely UNDER the ownership label classified as %q", got)
	}
}

// 🔴 The refusal that keeps a derivation bug from breaking a customer's TLS
// renewals months after anyone was looking. See assertNoProxiedValidation.
func TestAProxiedValidationRecordIsRefused(t *testing.T) {
	routing := Record{Type: "CNAME", Name: "account." + testAnchor, Value: "connect.mirrorstack.ai"}

	for _, record := range []Record{
		{Type: "TXT", Name: "_mirrorstack-challenge.example.com", Value: "tok", Proxied: true},
		{Type: "TXT", Name: "_acme-challenge.account.example.com", Value: "tok", Proxied: true},
		{Type: "CNAME", Name: "_acme-challenge.account.example.com", Value: "a.dcv.cloudflare.com", Proxied: true},
		{Type: "CNAME", Name: "_9f8c.account.example.com", Value: "_1a2b.acm-validations.aws", Proxied: true},
	} {
		_, err := NewSnapshot(KindPlatform, testTarget, testAnchor, []Record{routing, record})
		if !errors.Is(err, ErrProxiedValidation) {
			t.Errorf("NewSnapshot admitted a proxied %s: err = %v", record.Name, err)
		}
		// A caller matching only the boundary must still see the refusal.
		if !errors.Is(err, ErrPlanInvalid) {
			t.Errorf("the refusal for %s does not wrap ErrPlanInvalid", record.Name)
		}
	}

	// A PROXIED ROUTING RECORD IS FINE, and the rule must not creep onto it: a
	// console host inside a MirrorStack zone is served proxied on purpose, and
	// refusing that would take the org edge down rather than protect anything.
	proxiedRouting := routing
	proxiedRouting.Proxied = true
	if _, err := NewSnapshot(KindPlatform, testTarget, testAnchor, []Record{proxiedRouting}); err != nil {
		t.Errorf("a proxied ROUTING record was refused: %v", err)
	}
}

// Storage is untrusted input, so the rule is re-checked on the way back out —
// the same reasoning that re-checks containment in Validate. A row written
// before this rule existed must not publish now.
func TestValidateRejectsAStoredProxiedValidationRecord(t *testing.T) {
	records := []Record{
		{Type: "CNAME", Name: "account." + testAnchor, Value: "connect.mirrorstack.ai"},
		{Type: "TXT", Name: "_acme-challenge.account." + testAnchor, Value: "tok", Proxied: true},
	}
	// Identities come from NormalizeRecords rather than being spelled out here:
	// a second hand-written copy of the TYPE|name|value format would let this
	// test fail as "not normalized" the day that format changed, masking the
	// rule it exists to check.
	normalized, identities, err := NormalizeRecords(records)
	if err != nil {
		t.Fatalf("NormalizeRecords: %v", err)
	}
	stored := Snapshot{
		Version: Version, Kind: KindPlatform, TargetID: testTarget, Anchor: testAnchor,
		Records: normalized, Identities: identities,
	}
	// Digest computed over the row AS STORED, so the only thing that can refuse
	// it is the rule itself rather than an integrity mismatch.
	if err := stored.Validate(stored.Digest()); !errors.Is(err, ErrProxiedValidation) {
		t.Fatalf("Validate accepted a stored proxied validation record: %v", err)
	}
}

// Explain is the function the documentation is generated against, so its order
// and its coverage are contractual: every record, once, in publication order.
func TestExplainCoversEveryRecordInOrder(t *testing.T) {
	records := []Record{
		{Type: "TXT", Name: OwnershipLabel + "." + testAnchor, Value: "tok"},
		{Type: "CNAME", Name: "account." + testAnchor, Value: "connect.mirrorstack.ai"},
		{Type: "TXT", Name: "_acme-challenge.account." + testAnchor, Value: "chal"},
	}
	plan, err := NewSnapshot(KindPlatform, testTarget, testAnchor, records)
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	explained := plan.Explain()
	if len(explained) != len(records) {
		t.Fatalf("Explain returned %d entries for %d records", len(explained), len(records))
	}
	want := []Purpose{PurposeOwnership, PurposeRouting, PurposeCertificate}
	for i, entry := range explained {
		if entry.Record != plan.Records[i] {
			t.Errorf("entry %d is not plan record %d", i, i)
		}
		if entry.Purpose() != want[i] {
			t.Errorf("entry %d purpose = %q, want %q", i, entry.Purpose(), want[i])
		}
	}
	// The rendered line names the proxy answer explicitly rather than leaving a
	// reader to infer it from an absent field.
	if !strings.Contains(explained[1].String(), "DNS-only") {
		t.Errorf("a grey record did not say so: %q", explained[1].String())
	}
	proxied := Explanation{Record: Record{
		Type: "CNAME", Name: "account.example.com", Value: "x", Proxied: true}}
	if !strings.Contains(proxied.String(), "proxied") {
		t.Errorf("a proxied record did not say so: %q", proxied.String())
	}
}
