package lane

import (
	"strings"
	"testing"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
)

// fuzzReserved turns one arbitrary fuzz string into a small reserved-suffix
// list, so a target can vary the list as well as the name under inspection.
//
// The entries are handed through unrepaired — empty ones included — because an
// entry that normalizes to nothing is a case ValidateDomain deliberately treats
// as a malformed list rather than as no protection, and a helper that quietly
// dropped it would hide exactly that.
func fuzzReserved(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 6 {
		parts = parts[:6]
	}
	return parts
}

// fuzzAtOrUnder is an INDEPENDENT leading-dot suffix test.
//
// It deliberately does not call dnsplan.Contains: the property being asserted is
// that ValidateDomain's reserved check agrees with the plain-English rule a
// customer would apply ("is this name the suffix, or something beneath it"), and
// re-using the implementation under test to check the implementation under test
// asserts nothing.
func fuzzAtOrUnder(suffix, name string) bool {
	suffix = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(suffix), "."))
	if suffix == "" {
		return false
	}
	return name == suffix || strings.HasSuffix(name, "."+suffix)
}

// fuzzLabelProblem reports why one label of an ACCEPTED name is not publishable,
// or "" when it is fine. Written out here rather than shared with labelReason so
// the target checks the rule the package documents, not the code that implements
// it.
func fuzzLabelProblem(label string) string {
	switch {
	case label == "":
		return "an empty label"
	case len(label) > 63:
		return "a label over 63 bytes"
	case label[0] == '-':
		return "a label starting with a hyphen"
	case label[len(label)-1] == '-':
		return "a label ending with a hyphen"
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return "a byte outside letters, digits and hyphen"
	}
	return ""
}

// FuzzValidateDomainAcceptsOnlyPublishableNames asserts the claim the README
// makes about the anchor: MirrorStack will only ever accept, as the single bound
// on everything a delegated credential can reach, a name that is a real,
// publishable DNS name — and never one at or under a suffix this deployment
// reserved for itself.
//
// For ANY name and ANY small reserved list, an accepted name must be non-empty,
// at most 253 bytes, lowercase, carry no leading or trailing dot, be at least two
// LDH labels of 1..63 bytes each, contain no wildcard and no underscore label —
// and must not sit at or under any reserved suffix, checked here with an
// independent leading-dot suffix test rather than with the package's own.
//
// It also asserts the property a customer sees rather than reads: the name we
// hand back is the name we would hand back again. A validator that normalized
// differently on a second pass would mean the anchor stored on a registration and
// the anchor shown on a consent screen could be two different names.
//
// A refused name must return the empty string, because "" is the only refusal
// that cannot be concatenated into a record at somebody's zone apex.
func FuzzValidateDomainAcceptsOnlyPublishableNames(f *testing.F) {
	const label63 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// 3×64 + 50 + len("example.com") = 253, the exact wire limit; one more byte
	// of the short label puts it over.
	name253 := strings.Repeat(label63+".", 3) + strings.Repeat("a", 49) + ".example.com"
	name254 := strings.Repeat(label63+".", 3) + strings.Repeat("a", 50) + ".example.com"

	seeds := []struct{ name, reserved string }{
		{name253, ""},                  // exactly at the limit
		{name254, ""},                  // one byte over
		{label63 + ".example.com", ""}, // the longest legal label
		{strings.Repeat("a", 64) + ".example.com", ""}, // one byte over the label limit
		{"xn--bcher-kva.example.com", ""},              // an a-label, which we accept and never convert
		{"EXAMPLE.COM", ""},                            // case is folded, not refused
		{"example.com.", ""},                           // the root dot is presentation
		{"*.example.com", ""},                          // a wildcard is derived, never accepted
		{"_dmarc.example.com", ""},                     // a protocol owner
		{"_acme-challenge.example.com", ""},
		{"account.example.com", "example.com"}, // under a reserved suffix
		{"notexample.com", "example.com"},      // merely ends in the same letters
		{"example.com", "example.com"},         // the suffix itself
		{"example.com", "example.com,"},        // a list entry that protects nothing
		{"example.com", "EXAMPLE.COM."},        // a list entry that needs normalizing
		{"192.0.2.1", ""},                      // an address wearing a domain's shape
		{"com", ""},                            // a single label
		{"", ""},
	}
	for _, seed := range seeds {
		f.Add(seed.name, seed.reserved)
	}

	f.Fuzz(func(t *testing.T, name, reservedRaw string) {
		reserved := fuzzReserved(reservedRaw)
		got, err := ValidateDomain(name, reserved)
		if err != nil {
			if got != "" {
				t.Fatalf("ValidateDomain(%q) refused but returned %q; a refusal must return nothing publishable", name, got)
			}
			return
		}

		if got == "" {
			t.Fatalf("ValidateDomain(%q) accepted the empty name", name)
		}
		if len(got) > dnsplan.MaxDNSName {
			t.Fatalf("ValidateDomain(%q) = %q, %d bytes, over the %d-byte DNS limit", name, got, len(got), dnsplan.MaxDNSName)
		}
		if got != strings.ToLower(got) {
			t.Fatalf("ValidateDomain(%q) = %q, which is not lowercased", name, got)
		}
		if strings.HasPrefix(got, ".") || strings.HasSuffix(got, ".") {
			t.Fatalf("ValidateDomain(%q) = %q, which carries a leading or trailing dot", name, got)
		}
		if strings.Contains(got, "*") {
			t.Fatalf("ValidateDomain(%q) = %q, which spells a wildcard", name, got)
		}
		if strings.Contains(got, "_") {
			t.Fatalf("ValidateDomain(%q) = %q, which carries an underscore label", name, got)
		}
		labels := strings.Split(got, ".")
		if len(labels) < 2 {
			t.Fatalf("ValidateDomain(%q) = %q, a single label — a TLD nobody can own", name, got)
		}
		for _, label := range labels {
			if problem := fuzzLabelProblem(label); problem != "" {
				t.Fatalf("ValidateDomain(%q) = %q, which has %s: %q", name, got, problem, label)
			}
		}
		for _, entry := range reserved {
			if fuzzAtOrUnder(entry, got) {
				t.Fatalf("ValidateDomain(%q) = %q, which is at or under the reserved suffix %q", name, got, entry)
			}
		}

		again, err := ValidateDomain(got, reserved)
		if err != nil {
			t.Fatalf("ValidateDomain(%q) = %q, which ValidateDomain then refuses: %v", name, got, err)
		}
		if again != got {
			t.Fatalf("ValidateDomain is not a fixed point: %q -> %q -> %q", name, got, again)
		}
	})
}

// FuzzValidateSlugCannotSpellAnythingButALabel asserts the claim that bounds the
// one string in this design a caller chooses.
//
// 🔴 THE SLUG SELECTS *WHICH* NAME UNDER A PARENT THE CUSTOMER HAS ALREADY
// PROVEN — NEVER *WHAT* IS WRITTEN THERE.
//
// So for ANY input, an accepted slug must be one label and nothing else: no dot,
// no wildcard, no leading underscore, 1..63 bytes, lowercase LDH. The four
// protocol owners a caller must never be able to spell — `_acme-challenge`,
// `_cf-custom-hostname`, `_mirrorstack-challenge` and `_dmarc` — are asserted by
// name as well as by rule, because they are the ones whose meaning belongs to a
// certificate authority, to Cloudflare, or to a mail receiver rather than to us.
//
// Then the consequence the customer actually cares about: for any accepted slug
// and any accepted parent, `slug.parent` is still at or under that parent, is
// exactly ONE label beneath it — the depth `*.<parent>` routes — and is itself a
// name this service would publish. That composition is the property the slug rule
// exists to preserve; a slug rule that drifted from the domain rule would mint
// hostnames that pass here and are refused at publish, or that the wildcard never
// answers.
func FuzzValidateSlugCannotSpellAnythingButALabel(f *testing.F) {
	const label63 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	seeds := []struct{ slug, parent string }{
		{"blog", "example.net"},
		{"a", "example.net"},
		{"0", "example.net"},
		{"9lives", "example.net"},
		{"my-first-app", "example.net"},
		{"BLOG", "example.net"},
		{label63, "example.net"},
		{label63 + "a", "example.net"}, // one byte over the label limit
		{"_acme-challenge", "example.net"},
		{"_cf-custom-hostname", "example.net"},
		{"_mirrorstack-challenge", "example.net"},
		{"_dmarc", "example.net"},
		{"_blog", "example.net"},
		{"bl_g", "example.net"},
		{"*", "example.net"},
		{"*.blog", "example.net"},
		{"a.b", "example.net"},   // stays inside the anchor, and must still be refused
		{"blog.", "example.net"}, // a trailing dot
		{".blog", "example.net"},
		{"-lead", "example.net"},
		{"trail-", "example.net"},
		{"my blog", "example.net"},
		{" blog ", "example.net"}, // not trimmed for us
		{"café", "example.net"},
		{"blog", "a.b.c.example.org"}, // a deep parent
		{"blog", "EXAMPLE.COM."},      // a parent that needs normalizing
		{"blog", label63 + ".example.com"},
		{"", ""},
	}
	for _, seed := range seeds {
		f.Add(seed.slug, seed.parent)
	}

	f.Fuzz(func(t *testing.T, raw, parentRaw string) {
		slug, err := ValidateSlug(raw)
		if err != nil {
			if slug != "" {
				t.Fatalf("ValidateSlug(%q) refused but returned %q; a refusal must return nothing publishable", raw, slug)
			}
			return
		}

		if slug == "" {
			t.Fatalf("ValidateSlug(%q) accepted the empty slug", raw)
		}
		if len(slug) > 63 {
			t.Fatalf("ValidateSlug(%q) = %q, %d bytes, over the 63-byte label limit", raw, slug, len(slug))
		}
		if strings.Contains(slug, ".") {
			t.Fatalf("ValidateSlug(%q) = %q, which is a name rather than a label", raw, slug)
		}
		if strings.Contains(slug, "*") {
			t.Fatalf("ValidateSlug(%q) = %q, which spells a wildcard", raw, slug)
		}
		if strings.HasPrefix(slug, "_") {
			t.Fatalf("ValidateSlug(%q) = %q, which is an underscore label — where the protocols live", raw, slug)
		}
		for _, owner := range []string{"_acme-challenge", "_dmarc", "_cf-custom-hostname", "_mirrorstack-challenge"} {
			if slug == owner {
				t.Fatalf("ValidateSlug(%q) = %q, a name whose meaning belongs to somebody else", raw, slug)
			}
		}
		if slug != strings.ToLower(slug) {
			t.Fatalf("ValidateSlug(%q) = %q, which is not lowercased", raw, slug)
		}
		if problem := fuzzLabelProblem(slug); problem != "" {
			t.Fatalf("ValidateSlug(%q) = %q, which has %s", raw, slug, problem)
		}
		if again, err := ValidateSlug(slug); err != nil || again != slug {
			t.Fatalf("ValidateSlug is not a fixed point: %q -> %q -> (%q, %v)", raw, slug, again, err)
		}

		// The consequence. A parent the fuzzer did not manage to make valid is
		// replaced by a known-good one, so this half of the property is exercised
		// on every single input rather than only on the lucky ones.
		parent, err := ValidateDomain(parentRaw, nil)
		if err != nil {
			parent = "example.net"
		}
		host := slug + "." + parent
		if !dnsplan.Contains(parent, host) {
			t.Fatalf("slug %q composed %q, which is not at or under %q", slug, host, parent)
		}
		if strings.Count(host, ".") != strings.Count(parent, ".")+1 {
			t.Fatalf("slug %q composed %q, which is not exactly one label under %q — the wildcard would not route it", slug, host, parent)
		}
		// Over the wire limit the composed name is refused for its length alone,
		// which is a fact about the parent rather than about the slug.
		if len(host) <= dnsplan.MaxDNSName {
			if _, err := ValidateDomain(host, nil); err != nil {
				t.Fatalf("slug %q composed %q, which this service would refuse to publish: %v", slug, host, err)
			}
		}
	})
}
