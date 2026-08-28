package relay

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
)

// ---------------------------------------------------------------------------
// 🔴 FINDING, 2026-08-28: FuzzCheckedRecordsAreAlwaysBounded AND
// FuzzServingProofsAreAlwaysBounded FAIL ON THEIR SEED CORPUS, AND THE DEFECT IS
// IN PRODUCTION CODE. Nothing has been changed to make them pass.
//
// dnsplan.NormalizeName is not idempotent — it trims whitespace BEFORE it trims
// the root dot, so `"_x.account.example.com ."` normalizes to
// `"_x.account.example.com "`, keeping the space. relayedRecord normalizes ONCE
// and that once-normalized name is what gets returned and published; but
// beneathAnyHost decides whether it is inside the host by calling
// dnsplan.Contains, which normalizes a SECOND time. So a record whose name is
// not, by direct string comparison, strictly beneath any requested host still
// survives the bound this package exists to apply.
//
// It is fail-safe today: the second normalization only ever removes characters,
// so nothing escapes the anchor. What is broken is the invariant — the name that
// was checked is not the name that gets used. See internal/observe/fuzz_test.go
// for the same root cause on the read side, and internal/dnsplan/plan.go:38 for
// the one-line fix, which has deliberately NOT been applied here.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Properties, over arbitrary upstream answers.
//
// Both targets here drive hostileCA and hostileEdge — the fakes relay_test.go
// already uses — with records built from fuzzer bytes. There is no ACM, no
// Cloudflare, no HTTP server and no credential anywhere in this file: every
// refusal below is made by relay's own free functions, ABOVE the interface,
// which is exactly the property being claimed.
// ---------------------------------------------------------------------------

// fuzzStrictlyBeneath is an INDEPENDENT reading of "this name sits strictly
// under one of the hosts we asked about".
//
// 🔴 IT DELIBERATELY DOES NOT CALL dnsplan.Contains. A property checked with
// the same helper the production path uses passes whenever both are wrong the
// same way — and `Contains` is the single boundary this repository's README
// stakes its whole promise on, so it is the last thing a check of that promise
// should borrow. This is the rule spelled out from the README's own words: at
// or under the proven name, and for a relayed record never AT it.
// fuzzTriageSkipKnownDefect is flipped ONLY by hand, to hold the known
// dnsplan.NormalizeName non-idempotence constant while looking for a SECOND
// defect behind it. It must be false in anything committed.
var fuzzTriageSkipKnownDefect = false

func fuzzAnyUnnormalized(hosts []string) bool {
	for _, h := range hosts {
		if h != dnsplan.NormalizeName(h) {
			return true
		}
	}
	return false
}

func fuzzStrictlyBeneath(hosts []string, name string) bool {
	for _, host := range hosts {
		if host == "" || name == host {
			continue
		}
		if strings.HasSuffix(name, "."+host) {
			return true
		}
	}
	return false
}

// fuzzTXTSafe is likewise an independent reading of "a byte a published TXT
// value may carry": printable ASCII, minus the quote that ends a TXT string and
// the backslash that escapes it.
func fuzzTXTSafe(s string) bool {
	for _, r := range s {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

func fuzzHosts(raw string) []string {
	if raw == "" {
		return nil
	}
	return strings.Split(raw, "\n")
}

// FuzzCheckedRecordsAreAlwaysBounded encodes the promise this repository exists
// to let a customer check for themselves:
//
// 🔴 MIRRORSTACK CANNOT PUBLISH A RECORD OF ITS OWN CHOOSING INTO YOUR ZONE —
// NOT EVEN IF ITS OWN UPSTREAM IS LYING TO IT.
//
// A relayed record is one this repository cannot show you: the value is minted
// by AWS or by Cloudflare, and a reader of this code cannot see it in advance.
// So the bounds live ABOVE the CertificateAuthority and EdgeHostnames
// interfaces, in the free functions internal/intent actually calls, rather than
// inside whichever adapter happens to be wired. A check that lived in acm.go
// would be a check the next certificate authority silently does not have, with
// every comment in this package still reading true.
//
// hostileCA and hostileEdge are not caricatures. From above the interface they
// are indistinguishable from a second certificate authority, a double someone
// wires by mistake, or a change inside AWS.
//
// What must hold for every record that survives:
//
//   - a validation record is a CNAME pointing into the AWS validation zone;
//   - a serving proof is a TXT with a bounded, publishable value;
//   - both sit at an UNDERSCORE label STRICTLY BENEATH a host this pass asked
//     about — never at the host itself, which is the one write that could take
//     a working site down rather than sit beside it;
//   - neither is proxied;
//   - the count never exceeds MaxRelayed, counted after dedup;
//   - and anything else is REFUSED, never silently dropped — a dropped record
//     is indistinguishable from a certificate AWS has not filled in yet, and
//     would sit "preparing" forever with nothing to read.
func FuzzCheckedRecordsAreAlwaysBounded(f *testing.F) {
	const (
		host  = "account.example.com"
		hosts = "account.example.com\napi.example.com"
		good  = "_y" + ValidationTargetSuffix
	)
	// The well-formed record, so the bound is not vacuously satisfied by
	// refusing everything.
	f.Add(hosts, "CNAME", "_x."+host, good, uint8(0))
	f.Add(hosts, "cname", "_X.Account.Example.com.", "_y.acm-validations.aws.", uint8(0))
	// Every case TestAHostileCertificateAuthorityIsRefusedAboveTheInterface names.
	f.Add(hosts, "CNAME", "_x.example.net", good, uint8(0))
	f.Add(hosts, "CNAME", "_x.notaccount.example.com", good, uint8(0))
	f.Add(hosts, "CNAME", host, good, uint8(0))
	f.Add(hosts, "CNAME", "www."+host, good, uint8(0))
	f.Add(hosts, "CNAME", "", good, uint8(0))
	f.Add(hosts, "TXT", "_x."+host, good, uint8(0))
	f.Add(hosts, "CNAME", "_x."+host, "attacker.example.net", uint8(0))
	f.Add(hosts, "CNAME", "_x."+host, "_y.acm-validations.aws.example.net", uint8(0))
	f.Add(hosts, "CNAME", "_x."+host, strings.Repeat("a", dnsplan.MaxDNSName)+ValidationTargetSuffix, uint8(0))
	// The estate that is ORDINARY rather than hostile, and the one past the
	// reserve: both only reachable with the synthetic records the count drives.
	f.Add(hosts, "CNAME", "_x."+host, good, uint8(60))
	f.Add(hosts, "CNAME", "_x."+host, good, uint8(200))
	// Host lists that are not host lists.
	f.Add("", "CNAME", "_x."+host, good, uint8(0))
	f.Add("\n\n", "CNAME", "_x."+host, good, uint8(0))
	f.Add(".", "CNAME", "_x."+host, good, uint8(0))
	// 🔴 A root dot with whitespace in front of it.
	f.Add(hosts, "CNAME", "_x."+host+" .", good, uint8(0))
	f.Add("account.example.com .", "CNAME", "_x."+host, good, uint8(0))

	f.Fuzz(func(t *testing.T, hostsRaw, recType, recName, recValue string, extra uint8) {
		// The RAW list is what a caller hands in, and ValidationRecords
		// normalizes it itself. Passing an already-normalized list instead
		// would normalize twice, which is not the production path.
		raw := fuzzHosts(hostsRaw)
		wanted := normalizeHosts(raw)

		records := []dnsplan.Record{{
			Type: recType, Name: recName, Value: recValue,
			// The upstream always ASKS for the orange cloud, so "proxied is an
			// answer, not a default" is exercised on every input.
			Proxied: true,
		}}
		// Synthetic well-formed records, so the dedup and the MaxRelayed reserve
		// are reachable. Every one of them is beneath the first wanted host,
		// which is what an ordinary re-issued certificate estate looks like.
		if len(wanted) > 0 {
			for i := range int(extra) {
				records = append(records, dnsplan.Record{
					Type:  "CNAME",
					Name:  fmt.Sprintf("_v%d.%s", i, wanted[0]),
					Value: fmt.Sprintf("_t%d%s", i, ValidationTargetSuffix),
				})
			}
		}

		got, err := ValidationRecords(context.Background(), hostileCA{records: records}, raw)
		if err != nil {
			if !errors.Is(err, ErrUnexpectedRecord) {
				t.Fatalf("ValidationRecords refused with an unclassified error: %v", err)
			}
			// 🔴 A refusal publishes NOTHING. A partial answer would put a
			// record nobody chose into a customer's zone alongside the refusal.
			if got != nil {
				t.Fatalf("a refusal returned %d records: %+v", len(got), got)
			}
			return
		}

		// 🔴 NEVER SILENTLY DROPPED. Every record handed in was either accepted
		// or refused by name; there is no third outcome. A dropped one looks
		// exactly like a certificate AWS has not issued yet.
		if len(wanted) > 0 && len(got) == 0 {
			t.Fatalf("ValidationRecords accepted %d records for hosts %q and returned none of them", len(records), wanted)
		}
		if len(got) > MaxRelayed {
			t.Fatalf("ValidationRecords returned %d records, past the %d reserve", len(got), MaxRelayed)
		}

		seen := make(map[string]struct{}, len(got))
		for _, r := range got {
			fuzzCheckRelayedName(t, "a certificate validation record", wanted, r)
			if r.Type != "CNAME" {
				t.Fatalf("a validation record survived as a %s: %+v", r.Type, r)
			}
			if !strings.HasSuffix(r.Value, ValidationTargetSuffix) {
				t.Fatalf("a validation record survived pointing at %q, not into %s", r.Value, ValidationTargetSuffix)
			}
			if len(r.Value) > dnsplan.MaxDNSName {
				t.Fatalf("a validation record survived with a %d-byte target", len(r.Value))
			}
			identity := r.Type + "|" + r.Name + "|" + r.Value
			if _, dup := seen[identity]; dup {
				t.Fatalf("ValidationRecords returned %q twice; the count is only meaningful after dedup", identity)
			}
			seen[identity] = struct{}{}
		}

		// 🔴 ORDER IS PART OF THE ANSWER. The plan's SHA-256 digest is computed
		// over the record list in order, and a digest that reorders between two
		// passes tells a customer mid-connect that the plan changed, at random,
		// with nothing having changed.
		if !sort.SliceIsSorted(got, func(i, j int) bool {
			if got[i].Name != got[j].Name {
				return got[i].Name < got[j].Name
			}
			return got[i].Value < got[j].Value
		}) {
			t.Fatalf("ValidationRecords returned an unordered answer: %+v", got)
		}
	})
}

// FuzzServingProofsAreAlwaysBounded is the same claim for record 7, whose value
// had NO bound at all until the example-based tests were written: Edge is nil in
// production today, so whatever can answer MirrorStack's custom_hostnames
// endpoint chooses the bytes that would be published under a customer's own
// name.
//
// 🔴 THE VALUE IS THE HALF ANCHOR CONTAINMENT CANNOT REACH. Containment bounds
// a record's NAME. Nothing bounds a relayed VALUE except this, and the publisher
// wraps a TXT value in quotes without escaping what is inside — so a quote in
// the value moves where that string ends, and a control character in it is how
// a log line is forged.
func FuzzServingProofsAreAlwaysBounded(f *testing.F) {
	const host = "account.example.com"
	f.Add(host, "TXT", ServingProofPrefix+host, "proof-value")
	f.Add(host, "txt", "_CF-Custom-Hostname.Account.Example.com", "proof-value")
	// Every case TestAHostileEdgeIsRefusedAboveTheInterface names.
	f.Add(host, "TXT", ServingProofPrefix+"example.net", "v")
	f.Add(host, "TXT", host, "v")
	f.Add(host, "TXT", "_other."+host, "v")
	f.Add(host, "CNAME", ServingProofPrefix+host, "v")
	f.Add(host, "TXT", ServingProofPrefix+host, "")
	f.Add(host, "TXT", ServingProofPrefix+host, strings.Repeat("a", maxServingProofValue+1))
	f.Add(host, "TXT", ServingProofPrefix+host, `proof" "injected`)
	f.Add(host, "TXT", ServingProofPrefix+host, `proof\injected`)
	f.Add(host, "TXT", ServingProofPrefix+host, "proof\nlog-line-forged")
	// A TXT value's trailing dot is DATA, not presentation, and must survive.
	f.Add(host, "TXT", ServingProofPrefix+host, "proof.")
	// Hosts that are not hosts, and the root dot with whitespace in front.
	f.Add("", "TXT", ServingProofPrefix+host, "v")
	f.Add(".", "TXT", ServingProofPrefix+host, "v")
	f.Add(strings.Repeat("a.", 200), "TXT", ServingProofPrefix+host, "v")
	f.Add(host+" .", "TXT", ServingProofPrefix+host, "v")
	f.Add(host, "TXT", ServingProofPrefix+host+" .", "v")

	f.Fuzz(func(t *testing.T, host, recType, recName, recValue string) {
		edge := hostileEdge{record: dnsplan.Record{
			Type: recType, Name: recName, Value: recValue, Proxied: true,
		}}

		record, ready, err := ServingProof(context.Background(), edge, host)

		// ServingProofs is the call internal/intent actually makes; a bound that
		// held only on the singular form would be a bound production never runs.
		proofs, pluralErr := ServingProofs(context.Background(), edge, []string{host})

		if err != nil {
			if ready {
				t.Fatalf("ServingProof reported ready alongside an error: %v", err)
			}
			if record != (dnsplan.Record{}) {
				t.Fatalf("a refusal still handed back %+v", record)
			}
			if pluralErr == nil || proofs != nil {
				t.Fatalf("ServingProofs accepted %+v that ServingProof refused: %v", proofs, pluralErr)
			}
			return
		}

		// hostileEdge always claims ready, so a nil error means the record was
		// accepted. Not-ready with no error would be a record dropped on the
		// floor, which only an adapter that knows what a certificate IS may do.
		if !ready {
			t.Fatalf("ServingProof returned not-ready and no error for a host the edge said was ready")
		}
		if pluralErr != nil || len(proofs) != 1 || proofs[0] != record {
			t.Fatalf("ServingProofs disagreed with ServingProof: %+v / %v", proofs, pluralErr)
		}

		normalizedHost := dnsplan.NormalizeName(host)
		fuzzCheckRelayedName(t, "a serving proof", []string{normalizedHost}, record)
		if record.Type != "TXT" {
			t.Fatalf("a serving proof survived as a %s: %+v", record.Type, record)
		}
		if !strings.HasPrefix(record.Name, ServingProofPrefix) {
			t.Fatalf("a serving proof survived named %q, not %s<host>", record.Name, ServingProofPrefix)
		}
		if record.Value == "" {
			t.Fatalf("a serving proof survived with no value; an empty value is a WAIT at the adapter, not a record")
		}
		if len(record.Value) > maxServingProofValue {
			t.Fatalf("a serving proof survived with a %d-byte value, past the %d a TXT string carries",
				len(record.Value), maxServingProofValue)
		}
		if !fuzzTXTSafe(record.Value) {
			t.Fatalf("a serving proof survived carrying a byte a published TXT value cannot: %q", record.Value)
		}
	})
}

// fuzzCheckRelayedName is the half both relayed records share, checked without
// borrowing the production helpers.
func fuzzCheckRelayedName(t *testing.T, what string, hosts []string, r dnsplan.Record) {
	t.Helper()
	if fuzzTriageSkipKnownDefect && (r.Name != dnsplan.NormalizeName(r.Name) || fuzzAnyUnnormalized(hosts)) {
		t.Skip()
	}
	if r.Name == "" || len(r.Name) > dnsplan.MaxDNSName {
		t.Fatalf("%s survived with an unusable name %q", what, r.Name)
	}
	if !strings.HasPrefix(r.Name, "_") {
		// An underscore label is not a name a browser ever resolves. Requiring
		// one is what keeps every relayed write BESIDE the customer's records
		// rather than on top of one.
		t.Fatalf("%s survived at %q, which is not an underscore name", what, r.Name)
	}
	if !fuzzStrictlyBeneath(hosts, r.Name) {
		t.Fatalf("%s survived at %q, which is not strictly beneath any of the hosts this pass asked about (%q)",
			what, r.Name, hosts)
	}
	// 🔴 THE NAME THAT WAS CHECKED MUST BE THE NAME THAT GETS PUBLISHED. Every
	// bound in this package is taken on the normalized form; a record that
	// leaves here still unnormalized is one whose bound was judged against a
	// different string than the one that reaches the customer's zone.
	if r.Name != dnsplan.NormalizeName(r.Name) {
		t.Fatalf("%s survived with the unnormalized name %q (normalizes to %q)",
			what, r.Name, dnsplan.NormalizeName(r.Name))
	}
	if r.Type != strings.ToUpper(strings.TrimSpace(r.Type)) {
		t.Fatalf("%s survived with the unnormalized type %q", what, r.Type)
	}
	// Cloudflare accepts proxied:true on an underscore name with no error at
	// all, then answers with addresses instead of following the record — so
	// issuance, or a renewal months later, fails with every dashboard green.
	if r.Proxied {
		t.Fatalf("%s survived proxied, having asked for it: %+v", what, r)
	}
}
