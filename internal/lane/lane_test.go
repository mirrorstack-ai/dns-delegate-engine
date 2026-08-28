package lane

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
)

const (
	testAnchor  = "example.com"
	testAppRoot = "example.net"
)

// assertInvalid checks the one property every refusal in this package must have:
// it wraps ErrInvalid, so a caller's single errors.Is is enough, and it stays
// small enough to log.
func assertInvalid(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: want a refusal, got nil", what)
	}
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("%s: every refusal must wrap ErrInvalid so one errors.Is covers the package; got %v", what, err)
	}
	if len(err.Error()) > 512 {
		t.Fatalf("%s: refusal message is %d bytes — caller input must be bounded before it is quoted", what, len(err.Error()))
	}
}

// ─── Parse ──────────────────────────────────────────────────────────────────

func TestParseAcceptsExactlyThreeLanes(t *testing.T) {
	for _, want := range []Lane{OrgPlatformDomain, OrgAppDomain, AppDomain} {
		got, err := Parse(string(want))
		if err != nil {
			t.Fatalf("Parse(%q): %v", want, err)
		}
		if got != want {
			t.Fatalf("Parse(%q) = %q", want, got)
		}
	}
}

// The lane is a byte string inside the ownership proof the customer publishes,
// so a second accepted spelling of one lane would be a second valid proof for one
// domain. None of these are near-misses to be helpful about.
func TestParseRefusesEverythingElse(t *testing.T) {
	cases := []struct{ name, input string }{
		{"empty", ""},
		{"uppercase", "ORG_PLATFORM_DOMAIN"},
		{"mixed case", "Org_App_Domain"},
		{"leading space", " app_domain"},
		{"trailing space", "app_domain "},
		{"a trailing newline from a config file", "app_domain\n"},
		{"hyphens for underscores", "org-platform-domain"},
		{"camel case", "orgPlatformDomain"},
		{"the old kind vocabulary", "platform"},
		{"the other old kind", "app"},
		{"a prefix of a real lane", "org_platform"},
		{"a superstring of a real lane", "org_platform_domain_v2"},
		{"an oversized value, refused without being echoed whole", strings.Repeat("a", 4096)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.input)
			assertInvalid(t, err, "Parse")
			if got != "" {
				t.Fatalf("a refused Parse must return the zero Lane, got %q", got)
			}
		})
	}
}

// ─── Identity ───────────────────────────────────────────────────────────────

func TestIdentityKindPerLane(t *testing.T) {
	cases := []struct {
		lane Lane
		want IdentityKind
	}{
		{OrgPlatformDomain, IdentityOrg},
		{OrgAppDomain, IdentityOrg},
		// 🔴 Lane 3 carries an APP id. The owner may be a person, and there may be
		// no organization anywhere in the request.
		{AppDomain, IdentityApp},
	}
	for _, tc := range cases {
		if got := tc.lane.Identity(); got != tc.want {
			t.Fatalf("%q.Identity() = %q, want %q", tc.lane, got, tc.want)
		}
	}
}

// A caller that skipped Parse must not fall through into "org" by default: an
// org id is the thing an authorization check reaches for, and answering it for a
// lane nobody validated is how a check ends up passing on a request it never
// recognised.
func TestIdentityOfAnUnknownLaneMatchesNeitherKind(t *testing.T) {
	for _, l := range []Lane{"", "nope", "ORG_PLATFORM_DOMAIN", "org"} {
		got := l.Identity()
		if got == IdentityOrg || got == IdentityApp {
			t.Fatalf("Lane(%q).Identity() = %q — an unparsed lane must denote neither kind", l, got)
		}
	}
}

// ─── PlatformLabels and Hosts ───────────────────────────────────────────────

// 🔴 THE TRIPWIRE ON THE FIXED SIBLING TABLE.
//
// Each label is a hostname inside a customer's own domain and a subject on a
// publicly-trusted certificate. Adding a fifth or renaming one is a product
// decision with a certificate and a customer conversation attached; it must fail
// here rather than appear in a zone.
func TestPlatformLabelsIsTheFixedTable(t *testing.T) {
	want := []string{"account", "api", "apps", "cdn"}
	if len(PlatformLabels) != len(want) {
		t.Fatalf("PlatformLabels has %d entries, want %d: %v", len(PlatformLabels), len(want), PlatformLabels)
	}
	for i := range want {
		if PlatformLabels[i] != want[i] {
			t.Fatalf("PlatformLabels[%d] = %q, want %q", i, PlatformLabels[i], want[i])
		}
	}
}

func TestHosts(t *testing.T) {
	cases := []struct {
		name   string
		lane   Lane
		anchor string
		want   []string
	}{
		{
			name:   "the platform lane derives four siblings and never the apex",
			lane:   OrgPlatformDomain,
			anchor: testAnchor,
			want: []string{
				"account.example.com", "api.example.com",
				"apps.example.com", "cdn.example.com",
			},
		},
		{
			name:   "the app-domain lane derives one wildcard, ever",
			lane:   OrgAppDomain,
			anchor: testAppRoot,
			want:   []string{"*.example.net"},
		},
		{
			name:   "the app lane derives the anchor itself and nothing beneath it",
			lane:   AppDomain,
			anchor: "example.org",
			want:   []string{"example.org"},
		},
		{
			name:   "the anchor is normalized: DNS is case-insensitive and the root dot is presentation",
			lane:   OrgPlatformDomain,
			anchor: "  Example.COM.  ",
			want: []string{
				"account.example.com", "api.example.com",
				"apps.example.com", "cdn.example.com",
			},
		},
		{
			name:   "a sub-anchor keeps the derivation inside it",
			lane:   OrgPlatformDomain,
			anchor: "shop.example.com",
			want: []string{
				"account.shop.example.com", "api.shop.example.com",
				"apps.shop.example.com", "cdn.shop.example.com",
			},
		},
		// A host built on a bad anchor is a name under no anchor at all —
		// "account." + "" is the one to picture. Answering nothing is the legible
		// refusal for a function that cannot return an error.
		{name: "an empty anchor derives nothing", lane: OrgPlatformDomain, anchor: "", want: nil},
		{name: "a blank anchor derives nothing", lane: AppDomain, anchor: "   ", want: nil},
		{name: "a single-label anchor derives nothing", lane: OrgPlatformDomain, anchor: "com", want: nil},
		{name: "a wildcard anchor derives nothing", lane: OrgAppDomain, anchor: "*.example.net", want: nil},
		{name: "an underscore anchor derives nothing", lane: AppDomain, anchor: "_acme-challenge.example.org", want: nil},
		{name: "an unparsed lane derives nothing", lane: "nope", anchor: testAnchor, want: nil},
		{name: "the zero lane derives nothing", lane: "", anchor: testAnchor, want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.lane.Hosts(tc.anchor)
			if len(got) != len(tc.want) {
				t.Fatalf("Hosts(%q) = %v, want %v", tc.anchor, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("Hosts(%q)[%d] = %q, want %q", tc.anchor, i, got[i], tc.want[i])
				}
			}
		})
	}
}

// 🔴 THE INVARIANT THE REST OF THE SERVICE LEANS ON.
//
// dnsplan.Contains refuses an out-of-anchor record before any provider write, but
// a derivation that produced one would only be refused after a credential had
// already been exchanged. The customer-zone anchors here are the case the public
// claim is about: the anchor is a name in somebody else's zone.
func TestEveryDerivedHostIsAtOrUnderTheAnchor(t *testing.T) {
	anchors := []string{
		"example.com",
		"shop.example.com",
		"example.net",
		"a.b.c.example.org",
	}
	for _, l := range []Lane{OrgPlatformDomain, OrgAppDomain, AppDomain} {
		for _, anchor := range anchors {
			hosts := l.Hosts(anchor)
			if len(hosts) == 0 {
				t.Fatalf("lane %q derived nothing for a valid anchor %q", l, anchor)
			}
			for _, host := range hosts {
				if !dnsplan.Contains(anchor, host) {
					t.Fatalf("lane %q derived %q, which is not at or under %q", l, host, anchor)
				}
			}
		}
	}
}

// The platform lane must not reach the apex. An org connecting example.com keeps
// serving its own website there; the four siblings are the entire footprint, and
// a fifth name would be one nobody agreed to.
func TestThePlatformLaneNeverDerivesTheApex(t *testing.T) {
	for _, host := range OrgPlatformDomain.Hosts(testAnchor) {
		if host == testAnchor {
			t.Fatalf("the platform lane derived the anchor itself (%q) — the customer's own apex", host)
		}
	}
}

// Guards the shape of the return value, not today's behaviour: a cached
// package-level slice would hand every caller the same backing array, and one
// caller's in-place edit would become the next caller's record set.
func TestHostsReturnsAFreshSlice(t *testing.T) {
	first := OrgPlatformDomain.Hosts(testAnchor)
	first[0] = "evil.example.test"
	second := OrgPlatformDomain.Hosts(testAnchor)
	if second[0] != "account.example.com" {
		t.Fatalf("Hosts handed out shared state: second call returned %q", second[0])
	}
}

// ─── GrantLifetime ──────────────────────────────────────────────────────────

func TestGrantLifetime(t *testing.T) {
	cases := []struct {
		lane Lane
		want time.Duration
	}{
		{OrgPlatformDomain, 24 * time.Hour},
		{AppDomain, 24 * time.Hour},
		// Standing, because the records this lane exists to write belong to apps
		// that do not exist yet.
		{OrgAppDomain, Standing},
	}
	for _, tc := range cases {
		if got := tc.lane.GrantLifetime(); got != tc.want {
			t.Fatalf("%q.GrantLifetime() = %v, want %v", tc.lane, got, tc.want)
		}
	}
	if Standing != 0 {
		t.Fatalf("Standing must be the zero duration; the negative-on-unknown rule below depends on it")
	}
}

// 🔴 THE FAIL-OPEN CASE THIS PACKAGE EXISTS TO CLOSE.
//
// Zero means standing. A switch that forgets a case returns zero, so an
// unrecognised lane would otherwise be handed the most permissive answer in the
// package — a credential held forever — by accident. It gets a negative duration
// instead: the standing branch is not taken, and a caller that adds it to now
// computes an expiry in the past.
func TestAnUnknownLaneCannotHoldAStandingGrant(t *testing.T) {
	for _, l := range []Lane{"", "nope", "org_platform", "ORG_APP_DOMAIN"} {
		got := l.GrantLifetime()
		if got == Standing {
			t.Fatalf("Lane(%q).GrantLifetime() == Standing — an unparsed lane must never hold a standing grant", l)
		}
		if got >= 0 {
			t.Fatalf("Lane(%q).GrantLifetime() = %v, want a negative duration so an unchecked expiry lands in the past", l, got)
		}
		if !time.Now().Add(got).Before(time.Now()) {
			t.Fatalf("Lane(%q): now+%v is not in the past", l, got)
		}
	}
}

// ─── ValidateIdentity ───────────────────────────────────────────────────────

const canonicalUUID = "3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f607"

type identityCase struct {
	name  string
	input string
	want  string // "" means the input must be refused
}

func identityCases() []identityCase {
	return []identityCase{
		{"the canonical form", canonicalUUID, canonicalUUID},
		{"uppercase is folded, not refused", strings.ToUpper(canonicalUUID), canonicalUUID},
		{"mixed case is folded", "3F2a1B4c-5D6e-4F70-8A91-b2C3d4E5f607", canonicalUUID},
		// Syntactically canonical and naming nothing. Whether an org exists is
		// api-platform's question; this function settles spelling only.
		{"the nil uuid", "00000000-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000000"},

		{"empty", "", ""},
		{"one byte short", canonicalUUID[:35], ""},
		{"one byte long", canonicalUUID + "0", ""},
		{"unhyphenated, which pgtype would accept", "3f2a1b4c5d6e4f708a91b2c3d4e5f607", ""},
		{"braced, which pgtype would accept", "{" + canonicalUUID + "}", ""},
		{"a urn, which some parsers accept", "urn:uuid:" + canonicalUUID, ""},
		{"36 bytes with a hyphen in the wrong place", "3f2a1b4-c5d6e-4f70-8a91-b2c3d4e5f607", ""},
		{"36 bytes with a space for a hyphen", "3f2a1b4c 5d6e-4f70-8a91-b2c3d4e5f607", ""},
		{"a non-hex letter", "3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f60g", ""},
		{"a trailing space inside the length", "3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f60 ", ""},
		{"a leading space inside the length", " f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f607", ""},
		{"non-ascii", "3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f6ö7", ""},
		{"an oversized value", strings.Repeat("a", 4096), ""},
	}
}

func TestValidateIdentity(t *testing.T) {
	for _, tc := range identityCases() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateIdentity(tc.input)
			if tc.want == "" {
				assertInvalid(t, err, "ValidateIdentity")
				if got != "" {
					t.Fatalf("a refused identity must return the empty string, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateIdentity(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("ValidateIdentity(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ─── ValidateDomain ─────────────────────────────────────────────────────────

func TestValidateDomainAccepts(t *testing.T) {
	long := strings.Repeat("a", 63)
	cases := []struct{ name, input, want string }{
		{"a plain domain", "example.com", "example.com"},
		{"case is folded", "Example.COM", "example.com"},
		{"the root dot is presentation, not identity", "example.com.", "example.com"},
		{"surrounding space", "  example.net  ", "example.net"},
		{"a subdomain anchor", "shop.example.com", "shop.example.com"},
		{"a deep anchor", "a.b.c.example.org", "a.b.c.example.org"},
		{"a 63-byte label", long + ".example.com", long + ".example.com"},
		{"digits and hyphens inside a label", "a-1-b.example.com", "a-1-b.example.com"},
		// An internationalized domain reaches DNS as its A-label. We accept that
		// and never convert one, because a converted domain is a name the customer
		// did not type and will not recognise on a consent screen.
		{"a punycode a-label", "xn--bcher-kva.example.com", "xn--bcher-kva.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateDomain(tc.input, nil)
			if err != nil {
				t.Fatalf("ValidateDomain(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("ValidateDomain(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// 🔴 A RESERVED SUFFIX WRITTEN WITH A LEADING DOT PROTECTED NOTHING.
//
// Suffixes are often WRITTEN with a leading dot, so an operator setting
// MS_RESERVED_DOMAIN_SUFFIXES=".staging.example" is writing what looks like a
// suffix. NormalizeName trims a trailing root dot and not a leading one, so the
// entry survived non-empty, the malformed-list guard did not fire, and Contains
// then tested for a suffix "..staging.example" that no DNS name can end in.
//
// The entry read like protection and enforced none — which is the exact failure
// ValidateDomain's own doc comment says must never happen, one spelling further
// out. Found by fuzzing internal/derive.
func TestAReservedSuffixWithALeadingDotIsRefusedRatherThanIgnored(t *testing.T) {
	// The shape that used to pass silently.
	if _, err := ValidateDomain("sub.staging.example", []string{".staging.example"}); err == nil {
		t.Fatal("a leading-dot reserved entry must be refused, not silently ignored")
	}
	// It must fail LOUDLY for every domain, not only ones that would have matched
	// — a malformed guard is a configuration defect, not a per-name outcome.
	if _, err := ValidateDomain("unrelated.example.net", []string{".staging.example"}); err == nil {
		t.Fatal("a malformed reserved list must refuse every domain")
	}
	// And the correct spelling must still work.
	if _, err := ValidateDomain("sub.staging.example", []string{"staging.example"}); err == nil {
		t.Fatal("a well-formed reserved entry must still refuse names under it")
	}
	if _, err := ValidateDomain("unrelated.example.net", []string{"staging.example"}); err != nil {
		t.Fatalf("a well-formed reserved entry must not refuse unrelated names: %v", err)
	}
}

func TestValidateDomainRefuses(t *testing.T) {
	cases := []struct{ name, input string }{
		{"empty", ""},
		{"blank", "   "},
		{"a bare dot", "."},
		{"a leading dot", ".example.com"},
		{"a doubled dot", "example..com"},
		{"a doubled trailing dot", "example.com.."},
		// A single label is a TLD nobody can own, and an anchor there would make
		// containment meaningless: everything in that TLD would be under it.
		{"a single label", "com"},
		{"another single label", "localhost"},
		{"a 64-byte label", strings.Repeat("a", 64) + ".example.com"},
		{"over the 253-byte limit", strings.Repeat("a.", 130) + "example.com"},
		{"a wildcard", "*.example.com"},
		{"a bare wildcard", "*"},
		{"a wildcard buried in a label", "ex*mple.com"},
		// The validation owners. A domain that could spell one would let a
		// registration aim the whole derived record set at a name that already
		// means something to a certificate authority.
		{"an acme challenge owner", "_acme-challenge.example.com"},
		{"a dmarc owner", "_dmarc.example.com"},
		{"an underscore anywhere in a label", "ex_mple.com"},
		{"a label starting with a hyphen", "-lead.example.com"},
		{"a label ending with a hyphen", "trail-.example.com"},
		{"an embedded space", "exam ple.com"},
		{"a path", "example.com/evil"},
		{"a scheme", "https://example.com"},
		{"a port", "example.com:443"},
		{"non-ascii, which must arrive as an a-label", "exämple.com"},
		// An address wearing a domain's shape. This service publishes no A or AAAA
		// record and has nothing to say about an address.
		{"an ipv4 literal", "192.0.2.1"},
		{"an all-numeric rightmost label", "example.1"},
		{"an oversized value", strings.Repeat("a", 4096)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateDomain(tc.input, nil)
			assertInvalid(t, err, "ValidateDomain")
			if got != "" {
				t.Fatalf("a refused domain must return the empty string, got %q", got)
			}
		})
	}
}

// 🔴 THE LEADING-DOT SUFFIX MATCH.
//
// A reserved "example.com" must refuse example.com and everything under it, and
// must NOT refuse "evilexample.com" — a different domain that merely ends in the
// same letters, owned by someone else, and refusing it would be a bug that reads
// like caution.
func TestValidateDomainAndTheReservedSuffix(t *testing.T) {
	reserved := []string{"example.com"}
	refused := []string{
		"example.com",
		"account.example.com",
		"a.b.example.com",
		"Example.COM.",
	}
	for _, name := range refused {
		t.Run("refused "+name, func(t *testing.T) {
			_, err := ValidateDomain(name, reserved)
			assertInvalid(t, err, "ValidateDomain")
		})
	}
	allowed := []string{
		"evilexample.com",
		"notexample.com",
		"example.net",
		// Above the reserved suffix, not under it. That is a domain somebody could
		// genuinely own, and the ownership proof is what settles whether they do.
		"com.test",
		// Merely contains the reserved string; it lives in someone else's zone.
		"example.com.evil.test",
	}
	for _, name := range allowed {
		t.Run("allowed "+name, func(t *testing.T) {
			if _, err := ValidateDomain(name, reserved); err != nil {
				t.Fatalf("ValidateDomain(%q, %v) must be allowed: %v", name, reserved, err)
			}
		})
	}
}

func TestValidateDomainNormalizesEveryReservedEntry(t *testing.T) {
	// A reserved list is configuration, and configuration arrives spelled however
	// it was typed. A suffix that only protects when it was written in lowercase
	// without a root dot is a suffix that mostly does not protect.
	reserved := []string{"  Example.COM.  ", "EXAMPLE.NET"}
	for _, name := range []string{"account.example.com", "example.com", "blog.example.net"} {
		if _, err := ValidateDomain(name, reserved); err == nil {
			t.Fatalf("ValidateDomain(%q, %v) must be refused", name, reserved)
		}
	}
}

// 🔴 A GUARD THAT PROTECTS NOTHING MUST NOT LOOK LIKE PROTECTION.
//
// An entry that is present but normalizes to nothing means someone intended a
// reserved suffix and it evaporated. Silently matching nothing would leave every
// MirrorStack name registrable while the config still reads as configured, so the
// whole call is refused instead — for any domain, so the defect cannot hide
// behind the names that happened not to match.
func TestValidateDomainRefusesEverythingWhenTheReservedListIsMalformed(t *testing.T) {
	lists := [][]string{
		{""},
		{"   "},
		{"."},
		{"example.com", ""},
		{"", "example.com"},
	}
	for _, reserved := range lists {
		for _, name := range []string{"example.net", "account.example.com"} {
			got, err := ValidateDomain(name, reserved)
			assertInvalid(t, err, "ValidateDomain with a malformed reserved list")
			if got != "" {
				t.Fatalf("want no domain back, got %q", got)
			}
		}
	}
}

// An empty list reserves nothing, and that is a decision a call site makes
// visibly — Hosts is one, and it says so. It is not the same thing as a broken
// list, and must not be treated as one.
func TestAnEmptyReservedListReservesNothing(t *testing.T) {
	for _, reserved := range [][]string{nil, {}} {
		if _, err := ValidateDomain("example.com", reserved); err != nil {
			t.Fatalf("an empty reserved list must reserve nothing: %v", err)
		}
	}
}

// ─── ValidateSlug ───────────────────────────────────────────────────────────

func TestValidateSlugAccepts(t *testing.T) {
	cases := []struct{ name, input, want string }{
		{"a plain slug", "blog", "blog"},
		{"one letter", "a", "a"},
		{"one digit", "0", "0"},
		{"internal hyphens", "my-first-app", "my-first-app"},
		{"digits and letters", "app2", "app2"},
		{"a leading digit", "9lives", "9lives"},
		// DNS is case-insensitive, so folding is not a change of identity — it is
		// the only repair this function performs.
		{"uppercase is folded", "Blog", "blog"},
		{"all caps is folded", "BLOG", "blog"},
		{"a 63-byte label", strings.Repeat("a", 63), strings.Repeat("a", 63)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateSlug(tc.input)
			if err != nil {
				t.Fatalf("ValidateSlug(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("ValidateSlug(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestValidateSlugRefuses(t *testing.T) {
	cases := []struct{ name, input string }{
		{"empty", ""},
		{"the acme challenge owner", "_acme-challenge"},
		{"the cloudflare serving-proof owner", "_cf-custom-hostname"},
		{"the ownership-proof owner", "_mirrorstack-challenge"},
		{"a policy owner", "_dmarc"},
		{"any leading underscore", "_blog"},
		{"an underscore anywhere", "bl_g"},
		{"a wildcard", "*"},
		{"a wildcard with a parent", "*.blog"},
		{"a wildcard inside a label", "bl*g"},
		{"a name rather than a label", "a.b"},
		{"a trailing dot", "blog."},
		{"a leading dot", ".blog"},
		{"nothing but dots", ".."},
		{"a leading hyphen", "-lead"},
		{"a trailing hyphen", "trail-"},
		{"a 64-byte label", strings.Repeat("a", 64)},
		{"an embedded space", "my blog"},
		{"surrounding space, which is not trimmed for us", " blog "},
		{"a slash", "blog/evil"},
		{"non-ascii", "café"},
		{"an oversized value", strings.Repeat("a", 4096)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateSlug(tc.input)
			assertInvalid(t, err, "ValidateSlug")
			if got != "" {
				t.Fatalf("a refused slug must return the empty string, got %q", got)
			}
		})
	}
}

// 🔴 THE REASON THE DOT CHECK CANNOT BE LEFT TO CONTAINMENT.
//
// A dotted slug does not escape the anchor. "a.b" under example.net is
// a.b.example.net, which dnsplan.Contains passes — so no later check objects, and
// the two things that went wrong are both silent: the caller chose the SHAPE of a
// name rather than one label, and `*.example.net` matches exactly one label, so
// the app would be handed a hostname the wildcard does not route and would never
// serve, with no error anywhere.
func TestADottedSlugIsRefusedEvenThoughItStaysInsideTheAnchor(t *testing.T) {
	const nested = "a.b." + testAppRoot
	if !dnsplan.Contains(testAppRoot, nested) {
		t.Fatalf("premise of this test changed: %q is no longer under %q", nested, testAppRoot)
	}
	if _, err := ValidateSlug("a.b"); err == nil {
		t.Fatalf("a dotted slug must be refused here, because containment will not refuse it")
	}
}

// Every slug this package accepts must compose into a hostname the rest of the
// service accepts: one label under the parent, at or under the anchor. This is
// what ties the two validators together — a slug rule that drifted from the
// domain rule would produce names that pass here and are refused at publish.
func TestAnAcceptedSlugAlwaysComposesIntoAContainedHostname(t *testing.T) {
	for _, raw := range []string{"blog", "a", "0", "my-first-app", "BLOG", strings.Repeat("a", 63)} {
		slug, err := ValidateSlug(raw)
		if err != nil {
			t.Fatalf("ValidateSlug(%q): %v", raw, err)
		}
		host := slug + "." + testAppRoot
		if _, err := ValidateDomain(host, nil); err != nil {
			t.Fatalf("slug %q composed %q, which ValidateDomain refuses: %v", slug, host, err)
		}
		if !dnsplan.Contains(testAppRoot, host) {
			t.Fatalf("slug %q composed %q, which is not under %q", slug, host, testAppRoot)
		}
		if strings.Count(host, ".") != strings.Count(testAppRoot, ".")+1 {
			t.Fatalf("slug %q composed %q, which is more than one label under the parent — the wildcard would not route it", slug, host)
		}
	}
}

// allDigits is only ever reached with a non-empty label, because labelReason
// refuses an empty one first. It answers for itself all the same: a helper that
// calls the empty string all-numeric is a trap for whoever reaches for it next.
func TestAllDigits(t *testing.T) {
	for _, label := range []string{"1", "0", "192", "443"} {
		if !allDigits(label) {
			t.Fatalf("allDigits(%q) = false", label)
		}
	}
	for _, label := range []string{"", "a", "1a", "a1", "-", "1-2"} {
		if allDigits(label) {
			t.Fatalf("allDigits(%q) = true", label)
		}
	}
}
