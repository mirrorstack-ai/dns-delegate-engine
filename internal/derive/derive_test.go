package derive

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/proof"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/grantcrypto"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/testsupport"
)

// One fixture domain per lane, so a golden plan can never be read as belonging
// to the wrong one. Only example.com / example.net / example.org appear anywhere
// in this package: a real customer domain in a test is a real customer domain in
// a public repository.
const (
	orgAnchor    = "example.com" // lane 1 — the org's console
	appsAnchor   = "example.net" // lane 2 — the parent every app is routed under
	oneAppAnchor = "example.org" // lane 3 — one domain on one app

	// The production routing targets, written out rather than referenced through
	// the default constants, so that changing a default fails this test and
	// somebody has to look at what a customer's zone would start pointing at.
	testOrgTarget = "connect.mirrorstack.ai"
	testAppTarget = "connect.mirrorstack.app"

	// An obvious placeholder in the shape Cloudflare actually returns: 16
	// hexadecimal characters, NOT a 36-character UUID. See DCVTarget.
	testUUID = "0123456789abcdef"

	testIdentity = "11111111-2222-3333-4444-555555555555"

	// A value shaped like one internal/proof produces. This package never checks
	// the shape — it holds no key — so the only property that matters here is
	// that it is carried through unchanged.
	testProof = "msv1-ts3k2xmx2nzeqtcijntm324m4zf24epx7lyvgqnxs3acbxqymesq"
)

func testConfig() Config {
	return Config{
		OrgRoutingTarget:  testOrgTarget,
		AppRoutingTarget:  testAppTarget,
		DCVDelegationUUID: testUUID,
		ReservedSuffixes:  []string{"mirrorstack.ai", "mirrorstack.app"},
	}
}

// row is one expected record, spelled out in full. Golden plans are written this
// way rather than as a set membership check because the ORDER is part of the
// plan digest a customer authorizes — see Plan.
type row struct {
	typ, name, value string
	purpose          Purpose
	source           Source
	host             string
}

func assertPlan(t *testing.T, got Plan, want []row) {
	t.Helper()
	if len(got.Items) != len(want) {
		t.Fatalf("plan has %d records, want %d:\n%s", len(got.Items), len(want), dump(got))
	}
	for i, w := range want {
		item := got.Items[i]
		record := item.Record
		if record.Type != w.typ || record.Name != w.name || record.Value != w.value {
			t.Fatalf("record %d = %s %s -> %s, want %s %s -> %s",
				i, record.Type, record.Name, record.Value, w.typ, w.name, w.value)
		}
		if item.Purpose != w.purpose || item.Source != w.source || item.Host != w.host {
			t.Fatalf("record %d (%s) = purpose %q source %q host %q, want %q %q %q",
				i, record.Name, item.Purpose, item.Source, item.Host, w.purpose, w.source, w.host)
		}
	}
}

func dump(p Plan) string {
	var b strings.Builder
	for _, item := range p.Items {
		b.WriteString("  " + item.Record.Type + " " + item.Record.Name +
			" -> " + item.Record.Value + "  [" + string(item.Purpose) + "/" + string(item.Source) + "]\n")
	}
	return b.String()
}

func assertRefused(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: want a refusal, got nil", what)
	}
	if !errors.Is(err, ErrDerive) {
		t.Fatalf("%s: every refusal must wrap ErrDerive so one errors.Is covers the package; got %v", what, err)
	}
	if len(err.Error()) > 512 {
		t.Fatalf("%s: refusal is %d bytes — caller input must be bounded before it is quoted", what, len(err.Error()))
	}
}

// everyPlan returns one plan from every entry point, for the properties that
// must hold across all of them. A property asserted on lane 1 alone is a
// property three quarters of this package does not have.
func everyPlan(t *testing.T) map[string]Plan {
	t.Helper()
	c := testConfig()
	out := map[string]Plan{}
	for name, build := range map[string]func() (Plan, error){
		"lane 1 org platform domain": func() (Plan, error) {
			return c.Registration(lane.OrgPlatformDomain, testIdentity, orgAnchor, testProof)
		},
		"lane 2 org app domain": func() (Plan, error) {
			return c.Registration(lane.OrgAppDomain, testIdentity, appsAnchor, testProof)
		},
		"lane 3 app domain": func() (Plan, error) {
			return c.Registration(lane.AppDomain, testIdentity, oneAppAnchor, testProof)
		},
		"lane 2 bind app": func() (Plan, error) {
			return c.BindApp(appsAnchor, "blog")
		},
		"lane 3 on a subdomain anchor": func() (Plan, error) {
			return c.Registration(lane.AppDomain, testIdentity, "shop."+oneAppAnchor, testProof)
		},
	} {
		plan, err := build()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = plan
	}
	return out
}

// ─── golden plans ───────────────────────────────────────────────────────────

// Four sibling hosts from the fixed label table, one routing CNAME each, and a
// certificate pointer for every one of them — cdn included. The cdn asymmetry is
// about record 5 (the AWS validation CNAME, relayed, absent here) and not about
// record 6: cdn is a Cloudflare custom hostname like the other three.
func TestLaneOnePlanIsExactlyThisRecordSet(t *testing.T) {
	plan, err := testConfig().Registration(lane.OrgPlatformDomain, testIdentity, orgAnchor, testProof)
	if err != nil {
		t.Fatalf("Registration: %v", err)
	}
	assertPlan(t, plan, []row{
		{"TXT", "_mirrorstack-challenge.example.com", testProof, PurposeOwnership, SourceDerived, ""},

		{"CNAME", "account.example.com", testOrgTarget, PurposeRouting, SourceDerived, "account.example.com"},
		{"CNAME", "api.example.com", testOrgTarget, PurposeRouting, SourceDerived, "api.example.com"},
		{"CNAME", "apps.example.com", testOrgTarget, PurposeRouting, SourceDerived, "apps.example.com"},
		{"CNAME", "cdn.example.com", testOrgTarget, PurposeRouting, SourceDerived, "cdn.example.com"},

		{"CNAME", "_acme-challenge.account.example.com",
			"account.example.com." + testUUID + ".dcv.cloudflare.com",
			PurposeCertDCV, SourceDerived, "account.example.com"},
		{"CNAME", "_acme-challenge.api.example.com",
			"api.example.com." + testUUID + ".dcv.cloudflare.com",
			PurposeCertDCV, SourceDerived, "api.example.com"},
		{"CNAME", "_acme-challenge.apps.example.com",
			"apps.example.com." + testUUID + ".dcv.cloudflare.com",
			PurposeCertDCV, SourceDerived, "apps.example.com"},
		{"CNAME", "_acme-challenge.cdn.example.com",
			"cdn.example.com." + testUUID + ".dcv.cloudflare.com",
			PurposeCertDCV, SourceDerived, "cdn.example.com"},
	})
	if plan.Anchor != orgAnchor || plan.Lane != lane.OrgPlatformDomain {
		t.Fatalf("plan is %q on lane %q", plan.Anchor, plan.Lane)
	}
	if strings.Join(plan.Hosts, " ") != "account.example.com api.example.com apps.example.com cdn.example.com" {
		t.Fatalf("hosts = %v", plan.Hosts)
	}
	// Nothing is derived at the apex. An org connecting example.com keeps
	// serving its own website there; those four names are the whole footprint.
	for _, item := range plan.Items {
		if item.Record.Name == orgAnchor {
			t.Fatalf("lane 1 derived a record at the apex %q", orgAnchor)
		}
	}
}

// One wildcard, one proof, and NO certificate pointer. There is no host to
// derive one for yet — the apps this parent exists to serve have not been
// deployed — and `_acme-challenge.*.example.net` is not a name anybody can
// publish. Each app's pointer arrives from BindApp, at deploy time.
func TestLaneTwoPlanIsExactlyThisRecordSet(t *testing.T) {
	plan, err := testConfig().Registration(lane.OrgAppDomain, testIdentity, appsAnchor, testProof)
	if err != nil {
		t.Fatalf("Registration: %v", err)
	}
	assertPlan(t, plan, []row{
		{"TXT", "_mirrorstack-challenge.example.net", testProof, PurposeOwnership, SourceDerived, ""},
		{"CNAME", "*.example.net", testAppTarget, PurposeRouting, SourceDerived, "*.example.net"},
	})
	for _, item := range plan.Items {
		if item.Purpose == PurposeCertDCV {
			t.Fatalf("lane 2 registration derived a certificate pointer: %q", item.Record.Name)
		}
	}
}

// The tightest of the three: the anchor IS the hostname, so one routing record
// at the anchor and one pointer beside it, and nothing else in that zone is
// reachable at all.
func TestLaneThreePlanIsExactlyThisRecordSet(t *testing.T) {
	plan, err := testConfig().Registration(lane.AppDomain, testIdentity, oneAppAnchor, testProof)
	if err != nil {
		t.Fatalf("Registration: %v", err)
	}
	assertPlan(t, plan, []row{
		{"TXT", "_mirrorstack-challenge.example.org", testProof, PurposeOwnership, SourceDerived, ""},
		{"CNAME", "example.org", testAppTarget, PurposeRouting, SourceDerived, "example.org"},
		{"CNAME", "_acme-challenge.example.org",
			"example.org." + testUUID + ".dcv.cloudflare.com",
			PurposeCertDCV, SourceDerived, "example.org"},
	})
}

// BindApp derives record 6 and nothing else: no second proof (the parent's
// covers every name beneath it) and no routing record (the wildcard already
// routes this app).
func TestBindAppDerivesTheCertificatePointerAndNothingElse(t *testing.T) {
	plan, err := testConfig().BindApp(appsAnchor, "blog")
	if err != nil {
		t.Fatalf("BindApp: %v", err)
	}
	assertPlan(t, plan, []row{
		{"CNAME", "_acme-challenge.blog.example.net",
			"blog.example.net." + testUUID + ".dcv.cloudflare.com",
			PurposeCertDCV, SourceDerived, "blog.example.net"},
	})
	if plan.Anchor != appsAnchor || plan.Lane != lane.OrgAppDomain {
		t.Fatalf("bind plan is %q on lane %q", plan.Anchor, plan.Lane)
	}
	if len(plan.Hosts) != 1 || plan.Hosts[0] != "blog.example.net" {
		t.Fatalf("hosts = %v", plan.Hosts)
	}
}

// 🔴 THIS IS THE FACT THAT MAKES BindApp EXIST, so it is asserted rather than
// left in a comment. A wildcard matches exactly ONE label: `*.example.net`
// covers `blog.example.net` and stops one label short of
// `_acme-challenge.blog.example.net`. If this ever stopped being true, lane 2
// would not need a per-app call at all — and if the derived name ever moved to
// within one label of the anchor, every app would silently share one validation
// name.
func TestTheWildcardDoesNotCoverTheCertificateName(t *testing.T) {
	plan, err := testConfig().BindApp(appsAnchor, "blog")
	if err != nil {
		t.Fatalf("BindApp: %v", err)
	}
	name := plan.Items[0].Record.Name
	if !dnsplan.Contains(appsAnchor, name) {
		t.Fatalf("%q is not even under the anchor", name)
	}
	under := strings.TrimSuffix(name, "."+appsAnchor)
	if !strings.Contains(under, ".") {
		t.Fatalf("%q is one label under %q, which a wildcard WOULD cover — BindApp would then have no reason to exist",
			name, appsAnchor)
	}
	// And the host the wildcard does route is exactly one label under it.
	if strings.Contains(strings.TrimSuffix(plan.Hosts[0], "."+appsAnchor), ".") {
		t.Fatalf("the routed host %q is more than one label under %q, so the wildcard does not cover it",
			plan.Hosts[0], appsAnchor)
	}
}

// ─── the properties that must hold on every plan ────────────────────────────

// 🔴 THE BOUND ON EVERYTHING. dnsplan.NewSnapshot checks this again before
// anything is published; asserting it here is what turns a derivation bug into a
// named defect instead of a symptom two packages downstream.
func TestEveryDerivedRecordSitsUnderTheAnchor(t *testing.T) {
	for name, plan := range everyPlan(t) {
		for _, item := range plan.Items {
			if !dnsplan.Contains(plan.Anchor, item.Record.Name) {
				t.Fatalf("%s: %q is not at or under the anchor %q", name, item.Record.Name, plan.Anchor)
			}
		}
	}
}

// 🔴 NO A, AAAA, MX, NS OR CAA, EVER. An A record points a customer's hostname at
// an address that outlives any deployment we control; an NS moves authority for a
// name out of their zone; a CAA decides which certificate authority may issue for
// it. None of them is derivable, and the guard is asserted directly as well as
// through the derivation, because "no code path produces one today" is a weaker
// claim than "a code path that did would be refused".
func TestTheRecordVocabularyIsClosed(t *testing.T) {
	for name, plan := range everyPlan(t) {
		for _, item := range plan.Items {
			if item.Record.Type != "CNAME" && item.Record.Type != "TXT" {
				t.Fatalf("%s: derived a %q record at %q", name, item.Record.Type, item.Record.Name)
			}
		}
	}
	for _, forbidden := range []string{"A", "AAAA", "MX", "NS", "CAA", "TXT ", "cname", ""} {
		err := checkItem(orgAnchor, Item{
			Record:  dnsplan.Record{Type: forbidden, Name: "account." + orgAnchor, Value: testOrgTarget},
			Purpose: PurposeRouting, Source: SourceDerived, Explain: "x",
		}, false)
		assertRefused(t, err, "checkItem type "+forbidden)
	}
}

// 🔴 A CUSTOMER-ZONE RECORD IS NEVER PROXIED. Cloudflare accepts `proxied: true`
// on these names with no error and then answers with addresses instead of
// following the delegation, so issuance — or a renewal months later — fails with
// every dashboard on both sides still green. There is no path here that can
// produce one, and checkItem refuses a hand-built one.
func TestNothingDerivedIsProxied(t *testing.T) {
	for name, plan := range everyPlan(t) {
		for _, item := range plan.Items {
			if item.Record.Proxied {
				t.Fatalf("%s: %q is proxied", name, item.Record.Name)
			}
		}
	}
	err := checkItem(orgAnchor, Item{
		Record:  dnsplan.Record{Type: "CNAME", Name: "account." + orgAnchor, Value: testOrgTarget, Proxied: true},
		Purpose: PurposeRouting, Source: SourceDerived, Explain: "x",
	}, false)
	assertRefused(t, err, "checkItem proxied")
}

// 🔴 THE OWNERSHIP ROW IS PUBLISHED BY US NOW, and this test is the record of
// the trade rather than of the old property.
//
// It asserted the opposite — customer-sourced, absent from Publishable(), the
// only entry in Manual() — and that was right while the proof was a GATE: a
// proof satisfied by our own write demonstrates nothing. The gate is gone from
// Authorize, Complete and Advance, and a row nobody writes and nothing reads is
// a manual step for no effect: a two-record plan published one.
//
// So it must be publishable, and Manual() must be EMPTY — a customer who has
// authorized is asked for nothing. Re-arming the gate must restore both halves
// together, or our own write satisfies our own check.
func TestOwnershipIsPublishedWithTheRestOfThePlan(t *testing.T) {
	for name, plan := range everyPlan(t) {
		for _, item := range plan.Items {
			if item.Purpose != PurposeOwnership {
				continue
			}
			if item.Source != SourceDerived {
				t.Fatalf("%s: the ownership proof is sourced %q, want %q", name, item.Source, SourceDerived)
			}
			found := false
			for _, record := range plan.Publishable() {
				if record.Name == item.Record.Name {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s: the ownership record %q must be in Publishable()", name, item.Record.Name)
			}
			if manual := plan.Manual(); len(manual) != 0 {
				t.Fatalf("%s: Manual() = %v, want nothing left for the customer to publish", name, manual)
			}
		}
	}
}

// Publishable and Manual are halves: together they are the plan, and nothing is
// in both. A record that fell out of both would be one nobody is responsible for
// writing, which reads as "done" from every screen.
func TestPublishableAndManualPartitionTheItems(t *testing.T) {
	for name, plan := range everyPlan(t) {
		publishable := plan.Publishable()
		manual := plan.Manual()
		if len(publishable)+len(manual) != len(plan.Items) {
			t.Fatalf("%s: %d publishable + %d manual != %d items",
				name, len(publishable), len(manual), len(plan.Items))
		}
		seen := map[dnsplan.Record]bool{}
		for _, record := range publishable {
			seen[record] = true
		}
		for _, item := range manual {
			if seen[item.Record] {
				t.Fatalf("%s: %q is both publishable and manual", name, item.Record.Name)
			}
		}
		// The returned slices are fresh, so a caller appending relayed records
		// to Publishable() cannot write into the plan it is describing.
		if len(publishable) > 0 {
			publishable[0].Value = "clobbered.example.com"
			if plan.Items[0].Record.Value == "clobbered.example.com" {
				t.Fatalf("%s: Publishable() aliases the plan's own records", name)
			}
		}
	}
}

// Every row a customer is asked to accept carries a purpose, a source and a
// sentence. A blank cell in a consent screen is a row somebody approves without
// knowing what it does.
func TestEveryItemExplainsItself(t *testing.T) {
	for name, plan := range everyPlan(t) {
		for _, item := range plan.Items {
			if item.Purpose == "" || item.Source == "" {
				t.Fatalf("%s: %q has purpose %q source %q", name, item.Record.Name, item.Purpose, item.Source)
			}
			if len(item.Explain) < 40 || !strings.HasSuffix(item.Explain, ".") {
				t.Fatalf("%s: %q explains itself as %q", name, item.Record.Name, item.Explain)
			}
			// The sentence has to name the record's own subject, or it is
			// boilerplate that happens to sit beside a row.
			subject := item.Host
			if subject == "" {
				subject = plan.Anchor
			}
			if !strings.Contains(item.Explain, strings.TrimPrefix(subject, "*.")) {
				t.Fatalf("%s: the explanation for %q never mentions %q: %q",
					name, item.Record.Name, subject, item.Explain)
			}
		}
	}
}

// The item order is inside the plan digest a customer authorizes. A map
// iteration anywhere in this package would tell them, mid-consent, that the plan
// changed.
func TestPlanOrderIsDeterministic(t *testing.T) {
	c := testConfig()
	for i := 0; i < 16; i++ {
		first, err := c.Registration(lane.OrgPlatformDomain, testIdentity, orgAnchor, testProof)
		if err != nil {
			t.Fatalf("Registration: %v", err)
		}
		second, err := c.Registration(lane.OrgPlatformDomain, testIdentity, orgAnchor, testProof)
		if err != nil {
			t.Fatalf("Registration: %v", err)
		}
		if dump(first) != dump(second) {
			t.Fatalf("two derivations of one registration differ:\n%s\n%s", dump(first), dump(second))
		}
	}
}

// ─── the record-6 form ──────────────────────────────────────────────────────

// 🔴 THE HOSTNAME PREFIX IS THE WHOLE POINT. Without it every host delegated to
// one of our zones collides on a single name at Cloudflare, and a certificate
// authority following the pointer reads somebody else's token or nothing at all.
// api-platform's dcvDelegationTarget omits it; this package follows
// docs/DESIGN.md §6 and Cloudflare's documentation. See DCVTarget for what is
// still unverified about it.
func TestDCVTargetCarriesTheHostnamePrefix(t *testing.T) {
	got := DCVTarget("api.example.com", testUUID)
	want := "api.example.com." + testUUID + ".dcv.cloudflare.com"
	if got != want {
		t.Fatalf("DCVTarget = %q, want %q", got, want)
	}
	if !strings.HasPrefix(got, "api.example.com.") {
		t.Fatalf("DCVTarget dropped the hostname prefix: %q", got)
	}
	// Spelling is folded, so one host cannot produce two targets.
	if DCVTarget("API.Example.COM.", strings.ToUpper(testUUID)) != want {
		t.Fatalf("DCVTarget does not normalize its inputs")
	}
}

// A half-formed target is worse than none, because only the empty one fails
// loudly: an empty value reaches a provider as a create nobody can act on, and a
// truncated one resolves somewhere real.
func TestDCVTargetRefusesWhatCannotBeRight(t *testing.T) {
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." +
		strings.Repeat("c", 63) + "." + strings.Repeat("d", 25) + ".example.com"
	if len(long) > dnsplan.MaxDNSName {
		t.Fatalf("fixture host is %d bytes; the test must exercise the TARGET bound, not the host", len(long))
	}
	for name, args := range map[string][2]string{
		"no host":         {"", testUUID},
		"no uuid":         {"api.example.com", ""},
		"blank uuid":      {"api.example.com", "   "},
		"neither":         {"", ""},
		"target too long": {long, testUUID},
	} {
		if got := DCVTarget(args[0], args[1]); got != "" {
			t.Fatalf("%s: DCVTarget = %q, want the empty refusal", name, got)
		}
	}
}

// ─── refusals ───────────────────────────────────────────────────────────────

func TestRegistrationRefusesAMalformedRequest(t *testing.T) {
	c := testConfig()
	cases := []struct {
		name                    string
		l                       lane.Lane
		identity, anchor, value string
	}{
		{"an unknown lane", lane.Lane("org_platform"), testIdentity, orgAnchor, testProof},
		{"an empty lane", lane.Lane(""), testIdentity, orgAnchor, testProof},
		{"the old kind vocabulary", lane.Lane("platform"), testIdentity, orgAnchor, testProof},
		{"an identity that is not a uuid", lane.OrgPlatformDomain, "org-1", orgAnchor, testProof},
		{"an unhyphenated uuid", lane.OrgPlatformDomain, strings.ReplaceAll(testIdentity, "-", ""), orgAnchor, testProof},
		{"no identity", lane.OrgPlatformDomain, "", orgAnchor, testProof},
		{"an empty domain", lane.OrgPlatformDomain, testIdentity, "", testProof},
		{"a single label", lane.OrgPlatformDomain, testIdentity, "example", testProof},
		{"a wildcard the caller spelled", lane.OrgPlatformDomain, testIdentity, "*.example.com", testProof},
		{"an address wearing a domain's shape", lane.OrgPlatformDomain, testIdentity, "192.0.2.1", testProof},
		{"an over-long domain", lane.OrgPlatformDomain, testIdentity, strings.Repeat("a.", 200) + "example.com", testProof},
		{"no ownership proof value", lane.OrgPlatformDomain, testIdentity, orgAnchor, ""},
		{"a blank ownership proof value", lane.OrgPlatformDomain, testIdentity, orgAnchor, "   "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := c.Registration(tc.l, tc.identity, tc.anchor, tc.value)
			assertRefused(t, err, "Registration")
			if len(plan.Items) != 0 {
				t.Fatalf("a refused Registration returned %d records", len(plan.Items))
			}
		})
	}
}

// 🔴 A NAME UNDER A MIRRORSTACK SUFFIX HAS NO CUSTOMER AT THE OTHER END. Its
// ownership proof would be published by us, which is the defect this whole
// rebuild exists to remove, and the customer-grant write path would have become
// a platform-zone editor.
func TestAMirrorStackNameCannotBeConnected(t *testing.T) {
	c := testConfig()
	for _, domain := range []string{
		"mirrorstack.ai",
		"account.mirrorstack.ai",
		"mirrorstack.app",
		"someorg.mirrorstack.app",
		// The routing targets themselves: connecting the exact name a routing
		// CNAME points at would publish a record pointing at itself.
		testOrgTarget,
		testAppTarget,
	} {
		if _, err := c.Registration(lane.OrgPlatformDomain, testIdentity, domain, testProof); err == nil {
			t.Fatalf("%q was accepted as a customer domain", domain)
		}
		if _, err := c.BindApp(domain, "blog"); err == nil {
			t.Fatalf("%q was accepted as a bind parent", domain)
		}
	}
	// One-directional, exactly as lane.ValidateDomain documents: a name that
	// merely ends in the same letters is a different domain and is not refused.
	if _, err := c.Registration(lane.OrgPlatformDomain, testIdentity, "notmirrorstack.ai", testProof); err != nil {
		t.Fatalf("a domain that only ends in the same letters was refused: %v", err)
	}
}

// The slug is the one caller-chosen string anywhere in this design, and a dotted
// one does NOT escape the anchor — which is precisely why it has to be refused
// here. `a.b.example.net` is still under the anchor and no later check objects;
// what goes wrong is that the wildcard matches one label, so the app is handed a
// hostname nothing routes and simply never serves.
func TestBindAppRefusesASlugThatIsNotOneLabel(t *testing.T) {
	c := testConfig()
	for _, slug := range []string{
		"", "a.b", "blog.example.net", "*", "*.blog",
		"_acme-challenge", "_cf-custom-hostname", "_mirrorstack-challenge", "_dmarc",
		"-blog", "blog-", "bl og", "blög", strings.Repeat("a", 64),
	} {
		plan, err := c.BindApp(appsAnchor, slug)
		assertRefused(t, err, "BindApp slug "+slug)
		if len(plan.Items) != 0 {
			t.Fatalf("a refused BindApp returned %d records", len(plan.Items))
		}
	}
}

// Case is folded because DNS is case-insensitive and folding is not a change of
// identity. Nothing else is repaired.
func TestBindAppFoldsCaseAndNothingElse(t *testing.T) {
	plan, err := testConfig().BindApp("Example.NET.", "BLOG")
	if err != nil {
		t.Fatalf("BindApp: %v", err)
	}
	if plan.Items[0].Record.Name != "_acme-challenge.blog.example.net" {
		t.Fatalf("name = %q", plan.Items[0].Record.Name)
	}
	if plan.Anchor != appsAnchor {
		t.Fatalf("anchor = %q", plan.Anchor)
	}
}

// ─── configuration ──────────────────────────────────────────────────────────

func TestConfigValidateAcceptsTheDeployedShape(t *testing.T) {
	if err := testConfig().Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// The delegation identifier is per ZONE, so it is ValidateLane's business
	// rather than Validate's: a deployment may hold the app zone's and not the
	// org zone's and still serve lane 3 perfectly.
	if err := ConfigFromEnv().ValidateLane(lane.OrgPlatformDomain); err == nil {
		t.Fatalf("ConfigFromEnv with no delegation identifier must not validate a lane")
	}
}

// An unconfigured deployment derives nothing at all, rather than deriving a
// record with a hole in it that is caught three packages later.
func TestConfigValidateRefusesAnIncompleteDeployment(t *testing.T) {
	cases := map[string]func(*Config){
		"no org routing target":    func(c *Config) { c.OrgRoutingTarget = "" },
		"blank org routing target": func(c *Config) { c.OrgRoutingTarget = "   " },
		"org target is not a name": func(c *Config) { c.OrgRoutingTarget = "connect" },
		"no app routing target":    func(c *Config) { c.AppRoutingTarget = "" },
		"app target is not a name": func(c *Config) { c.AppRoutingTarget = "*.example.com" },
		"no reserved suffixes":     func(c *Config) { c.ReservedSuffixes = nil },
		"empty reserved suffixes":  func(c *Config) { c.ReservedSuffixes = []string{} },
		"a reserved entry that is nothing": func(c *Config) {
			c.ReservedSuffixes = append(c.ReservedSuffixes, "  .  ")
		},
	}
	for name, break_ := range cases {
		t.Run(name, func(t *testing.T) {
			c := testConfig()
			break_(&c)
			err := c.Validate()
			assertRefused(t, err, "Validate")
			if !errors.Is(err, ErrConfig) {
				t.Fatalf("a configuration refusal must wrap ErrConfig: %v", err)
			}
			// And no entry point derives anything under it.
			if _, err := c.Registration(lane.OrgPlatformDomain, testIdentity, orgAnchor, testProof); err == nil {
				t.Fatalf("Registration derived a plan under an invalid config")
			}
			if _, err := c.BindApp(appsAnchor, "blog"); err == nil {
				t.Fatalf("BindApp derived a plan under an invalid config")
			}
		})
	}
	// The zero Config is the case a caller reaches by forgetting entirely.
	assertRefused(t, Config{}.Validate(), "the zero Config")
}

// The defaults are MirrorStack's production edge names, pinned here so that
// changing one fails a build rather than quietly repointing every customer zone
// derived by this deployment.
func TestConfigFromEnvDefaultsAndOverrides(t *testing.T) {
	for _, key := range []string{orgRoutingTargetEnv, appRoutingTargetEnv,
		dcvDelegationUUIDOrgEnv, dcvDelegationUUIDAppEnv, dcvDelegationUUIDLegacyEnv, reservedSuffixesEnv} {
		t.Setenv(key, "")
		_ = os.Unsetenv(key)
	}
	c := ConfigFromEnv()
	if c.OrgRoutingTarget != testOrgTarget || c.AppRoutingTarget != testAppTarget {
		t.Fatalf("defaults are %q / %q", c.OrgRoutingTarget, c.AppRoutingTarget)
	}
	// No default for the uuid: an empty value is a truthful "not configured",
	// and Validate turns it into a refusal at the first derivation.
	if c.DCVDelegationUUID != "" {
		t.Fatalf("the dcv uuid has a default: %q", c.DCVDelegationUUID)
	}

	t.Setenv(orgRoutingTargetEnv, "edge.example.com")
	t.Setenv(appRoutingTargetEnv, "edge.example.net")
	t.Setenv(dcvDelegationUUIDOrgEnv, "  "+testUUID+"  ")
	t.Setenv(dcvDelegationUUIDAppEnv, "  "+testUUID+"  ")
	t.Setenv(reservedSuffixesEnv, "one.example.org, two.example.org;three.example.org four.example.org")
	c = ConfigFromEnv()
	if c.OrgRoutingTarget != "edge.example.com" || c.AppRoutingTarget != "edge.example.net" {
		t.Fatalf("overrides are %q / %q", c.OrgRoutingTarget, c.AppRoutingTarget)
	}
	if c.DCVDelegationUUID != testUUID {
		t.Fatalf("the dcv uuid is %q", c.DCVDelegationUUID)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("an overridden deployment must validate: %v", err)
	}
	// A comma-separated list must not leave the comma inside an entry, which
	// would be a reserved suffix matching no name at all — protection that reads
	// like protection and is not.
	want := "mirrorstack.ai mirrorstack.app one.example.org two.example.org three.example.org four.example.org"
	if got := strings.Join(c.ReservedSuffixes, " "); got != want {
		t.Fatalf("reserved suffixes = %q, want %q", got, want)
	}
}

// A deployment may add reserved suffixes; it can never remove MirrorStack's own.
func TestConfigFromEnvAlwaysReservesTheMirrorStackSuffixes(t *testing.T) {
	t.Setenv(reservedSuffixesEnv, "")
	c := ConfigFromEnv()
	for _, want := range platformSuffixes {
		found := false
		for _, got := range c.ReservedSuffixes {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("%q is not reserved: %v", want, c.ReservedSuffixes)
		}
	}
}

// ─── cross-package agreement ────────────────────────────────────────────────

// 🔴 TWO PACKAGES BUILD THE OWNERSHIP ROW AND THEY MUST BUILD THE SAME BYTES.
// internal/proof holds the key and mints the value; this package places it in a
// plan. If the two ever disagreed — a different owner name, a different type — a
// customer would be shown one record on a consent screen and verified against
// another, and the domain would sit forever at "waiting for your proof" with a
// correct-looking record already published.
func TestOwnershipRecordMatchesInternalProof(t *testing.T) {
	prover := proof.Prover{Sealer: testSealer(t)}
	for _, tc := range []struct {
		l      lane.Lane
		anchor string
	}{
		{lane.OrgPlatformDomain, orgAnchor},
		{lane.OrgAppDomain, appsAnchor},
		{lane.AppDomain, oneAppAnchor},
	} {
		value, err := prover.Expected(tc.l, testIdentity, tc.anchor)
		if err != nil {
			t.Fatalf("Expected: %v", err)
		}
		want, err := prover.Record(tc.l, testIdentity, tc.anchor)
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
		plan, err := testConfig().Registration(tc.l, testIdentity, tc.anchor, value)
		if err != nil {
			t.Fatalf("Registration: %v", err)
		}
		if plan.Items[0].Record != want {
			t.Fatalf("lane %q: derived %+v, proof produced %+v", tc.l, plan.Items[0].Record, want)
		}
	}
}

func testSealer(t *testing.T) *grantcrypto.Sealer {
	t.Helper()
	return testsupport.SealerWithKey(t, "k1", bytes.Repeat([]byte{0x2a}, grantcrypto.KeySize))
}

// Every plan this package produces is one dnsplan.NewSnapshot accepts. The two
// checks are deliberately duplicated — see newPlan — and a duplicate that
// disagreed would mean a plan derived here is refused at the boundary, which
// looks to a customer like a service that cannot finish what it started.
func TestEveryPlanSurvivesTheSnapshotBoundary(t *testing.T) {
	for name, plan := range everyPlan(t) {
		records := plan.Publishable()
		if len(records) == 0 {
			t.Fatalf("%s: nothing publishable", name)
		}
		kind := dnsplan.KindApp
		if plan.Lane == lane.OrgPlatformDomain {
			kind = dnsplan.KindPlatform
		}
		if _, err := dnsplan.NewSnapshot(kind, testIdentity, plan.Anchor, records); err != nil {
			t.Fatalf("%s: dnsplan refused a derived plan: %v\n%s", name, err, dump(plan))
		}
	}
}

// 🔴 THE GUARDS ARE ASSERTED DIRECTLY, NOT ONLY THROUGH THE DERIVATION.
//
// Nothing this package derives today trips any of these, and that is exactly why
// they need their own test: "no code path produces one" is a claim about the
// code as it stands, while "a code path that did would be refused" is the
// property newPlan exists to provide. Each case below is a real derivation bug
// somebody could introduce in an afternoon — a label table with a blank entry, a
// concatenation that forgot to normalize, a new record kind nobody labelled.
func TestTheGuardsRefuseADerivationBug(t *testing.T) {
	ok := Item{
		Record:  dnsplan.Record{Type: "CNAME", Name: "account." + orgAnchor, Value: testOrgTarget},
		Purpose: PurposeRouting, Source: SourceDerived, Explain: "x",
	}
	if err := checkItem(orgAnchor, ok, false); err != nil {
		t.Fatalf("the well-formed item was refused: %v", err)
	}

	cases := map[string]func(*Item){
		// An empty owner name reaches a provider as a create at the ZONE APEX.
		// It is not a hypothetical: Cloudflare returns its ownership-verification
		// object with empty strings once the proof is no longer required, and an
		// unguarded read of it published exactly that write.
		"an empty name":  func(i *Item) { i.Record.Name = "" },
		"an empty value": func(i *Item) { i.Record.Value = "" },
		"a name over the DNS wire limit": func(i *Item) {
			i.Record.Name = strings.Repeat("a.", 130) + orgAnchor
		},
		// A plan holding two spellings of one name digests differently on the
		// next pass, and the customer is told the plan changed.
		"a name that is not normalized": func(i *Item) { i.Record.Name = "Account." + orgAnchor },
		"a trailing root dot":           func(i *Item) { i.Record.Name = "account." + orgAnchor + "." },
		"a name outside the anchor":     func(i *Item) { i.Record.Name = "account.example.net" },
		"a name that merely ends in the same letters": func(i *Item) {
			i.Record.Name = "notexample.com"
		},
		"an oversized name outside the anchor, quoted back bounded": func(i *Item) {
			i.Record.Name = strings.Repeat("a", 80) + ".example.net"
		},
		"no purpose":     func(i *Item) { i.Purpose = "" },
		"no source":      func(i *Item) { i.Source = "" },
		"no explanation": func(i *Item) { i.Explain = "" },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			item := ok
			breakIt(&item)
			assertRefused(t, checkItem(orgAnchor, item, false), "checkItem")
			// And newPlan refuses the whole plan rather than dropping the row:
			// a silently omitted record is a hostname that never serves, with
			// nothing anywhere saying why.
			plan, err := newPlan(lane.OrgPlatformDomain, orgAnchor, nil, []Item{ok, item}, false)
			assertRefused(t, err, "newPlan")
			if len(plan.Items) != 0 {
				t.Fatalf("a refused newPlan returned %d records", len(plan.Items))
			}
		})
	}
}

// Two depth bounds, and they are the customer's domain rather than anything this
// service chose. The ownership proof sits one 23-byte label above the anchor; a
// certificate pointer hangs the uuid and `.dcv.cloudflare.com` beneath a host. An
// anchor can clear the first and fail the second, which is why both fixtures are
// written out rather than left to be discovered by whoever hits one.
var (
	// deepAnchor: provable, but no pointer fits beneath it.
	deepAnchor = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." +
		strings.Repeat("c", 63) + "." + strings.Repeat("d", 30) + ".com"

	// overDeepAnchor: not even provable — `_mirrorstack-challenge.` plus the
	// anchor is over the DNS wire limit.
	overDeepAnchor = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." +
		strings.Repeat("c", 63) + "." + strings.Repeat("d", 40) + ".com"
)

// Both fixtures must be VALID domains, or every assertion below proves only that
// lane.ValidateDomain works.
func TestTheDepthFixturesAreRealDomains(t *testing.T) {
	for _, anchor := range []string{deepAnchor, overDeepAnchor} {
		if _, err := lane.ValidateDomain(anchor, nil); err != nil {
			t.Fatalf("fixture of %d bytes is not a valid domain: %v", len(anchor), err)
		}
	}
	if len(deepAnchor) >= len(overDeepAnchor) {
		t.Fatalf("the fixtures are the wrong way round: %d and %d", len(deepAnchor), len(overDeepAnchor))
	}
}

// dcvItem turns DCVTarget's empty refusal into a plan-level one, so a pointer
// that cannot exist is a named error rather than a CNAME with no value in it.
// The two causes carry different sentinels because different people can fix
// them: an unset uuid is the operator's, an over-long name is the request's.
func TestDCVItemRefusesAnUnrepresentableTarget(t *testing.T) {
	cases := []struct {
		name, host, uuid string
		config           bool
	}{
		{"no uuid", "api." + orgAnchor, "", true},
		{"a blank uuid", "api." + orgAnchor, "   ", true},
		{"no host", "", testUUID, false},
		{"a target over the DNS wire limit", "account." + deepAnchor, testUUID, false},
	}
	for _, tc := range cases {
		item, err := dcvItem(lane.OrgPlatformDomain, tc.host, tc.uuid)
		assertRefused(t, err, "dcvItem "+tc.name)
		if errors.Is(err, ErrConfig) != tc.config {
			t.Fatalf("%s: wrong audience for the refusal: %v", tc.name, err)
		}
		if item.Record != (dnsplan.Record{}) {
			t.Fatalf("%s: a refused dcvItem returned %+v", tc.name, item.Record)
		}
	}
}

// An anchor deep enough that no certificate pointer fits beneath it refuses the
// WHOLE plan on the lanes that derive one. Publishing the rest would leave a
// hostname routed to MirrorStack with a certificate that can never validate — a
// domain that looks connected and serves an error.
//
// Lane 2 accepts the same anchor, and that is the lanes differing rather than an
// inconsistency: it derives no pointer at registration. Its apps hit the bound
// one at a time, at BindApp, where the refusal names the app.
func TestAnAnchorTooDeepForAPointerRefusesTheWholePlan(t *testing.T) {
	c := testConfig()
	for name, build := range map[string]func() (Plan, error){
		"lane 1": func() (Plan, error) {
			return c.Registration(lane.OrgPlatformDomain, testIdentity, deepAnchor, testProof)
		},
		"lane 3": func() (Plan, error) {
			return c.Registration(lane.AppDomain, testIdentity, deepAnchor, testProof)
		},
		"bind app": func() (Plan, error) { return c.BindApp(deepAnchor, "blog") },
	} {
		plan, err := build()
		assertRefused(t, err, name)
		if errors.Is(err, ErrConfig) {
			t.Fatalf("%s: an anchor the caller chose is not a configuration fault: %v", name, err)
		}
		if len(plan.Items) != 0 {
			t.Fatalf("%s: a refused derivation returned %d records", name, len(plan.Items))
		}
	}
	if _, err := c.Registration(lane.OrgAppDomain, testIdentity, deepAnchor, testProof); err != nil {
		t.Fatalf("lane 2 derives no pointer and must accept the anchor: %v", err)
	}
}

// 🔴 AN ANCHOR THAT CANNOT CARRY THE PROOF IS REFUSED ON EVERY LANE, INCLUDING
// THE ONE WITH NO CERTIFICATE POINTER.
//
// The alternative is the failure mode proof.Name exists to prevent: a record
// with an empty owner name, which a provider creates at the ZONE APEX. Lane 2 is
// the case worth asserting, because it is the lane where nothing else is deep
// enough to object.
func TestAnAnchorThatCannotCarryTheProofIsRefusedOnEveryLane(t *testing.T) {
	c := testConfig()
	for _, l := range []lane.Lane{lane.OrgPlatformDomain, lane.OrgAppDomain, lane.AppDomain} {
		plan, err := c.Registration(l, testIdentity, overDeepAnchor, testProof)
		assertRefused(t, err, "Registration on "+string(l))
		if len(plan.Items) != 0 {
			t.Fatalf("%s: a refused derivation returned %d records", l, len(plan.Items))
		}
		if !strings.Contains(err.Error(), proof.Prefix) {
			t.Fatalf("%s: the refusal does not name the challenge label that does not fit: %v", l, err)
		}
	}
}

// 🔴 THE IDENTIFIER IS PER ZONE, AND ONE VARIABLE FOR BOTH IS A GUESS ABOUT ONE
// OF THEM.
//
// Cloudflare answers GET /zones/{zone_id}/dcv_delegation/uuid per zone. Lane 1
// lives in the org zone and lanes 2 and 3 in the app zone, so a deployment given
// one value has it right for at most one lane — and a wrong identifier aims
// record 6 at a namespace Cloudflare never writes to, which resolves perfectly
// and validates never. That is the same failure the missing hostname label
// caused, one label further along.
func TestTheDelegationIdentifierIsSelectedPerZone(t *testing.T) {
	c := Config{DCVDelegationUUID: "orgzone", DCVDelegationUUIDApp: "appzone"}
	if got := c.DCVUUID(lane.OrgPlatformDomain); got != "orgzone" {
		t.Errorf("lane 1 must use the org zone identifier, got %q", got)
	}
	for _, l := range []lane.Lane{lane.OrgAppDomain, lane.AppDomain} {
		if got := c.DCVUUID(l); got != "appzone" {
			t.Errorf("%s must use the app zone identifier, got %q", l, got)
		}
	}
}

// An unmigrated deployment set only the single variable that used to cover both
// zones. It keeps working — refusing would take connect down on a config change
// nobody made — and dcvUUIDFor warns, because the value is right for at most one
// of the two.
func TestTheLegacySingleVariableStillServesBothZones(t *testing.T) {
	for _, key := range []string{dcvDelegationUUIDOrgEnv, dcvDelegationUUIDAppEnv} {
		t.Setenv(key, "")
		_ = os.Unsetenv(key)
	}
	t.Setenv(dcvDelegationUUIDLegacyEnv, testUUID)
	c := ConfigFromEnv()
	for _, l := range []lane.Lane{lane.OrgPlatformDomain, lane.OrgAppDomain, lane.AppDomain} {
		if got := c.DCVUUID(l); got != testUUID {
			t.Errorf("%s fell back to %q", l, got)
		}
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("an unmigrated deployment must still validate: %v", err)
	}
}

// A deployment that can derive lane 1 and not lane 2 reports success and then
// fails on the lane it was not asked about, so Validate checks both zones and
// names the variable an operator has to set.
func TestValidateRefusesAZoneWithNoIdentifier(t *testing.T) {
	c := Config{
		OrgRoutingTarget: testOrgTarget, AppRoutingTarget: testAppTarget,
		DCVDelegationUUID: testUUID, ReservedSuffixes: platformSuffixes,
	}
	// Both present via fallback: fine.
	if err := c.ValidateLane(lane.OrgAppDomain); err != nil {
		t.Fatalf("the org identifier must serve both until one is set: %v", err)
	}
	// An app identifier that is not a label must be refused BY NAME.
	c.DCVDelegationUUIDApp = "not.a.label"
	err := c.ValidateLane(lane.OrgAppDomain)
	if err == nil {
		t.Fatal("a dotted app identifier must be refused")
	}
	if !strings.Contains(err.Error(), dcvDelegationUUIDAppEnv) {
		t.Fatalf("the refusal must name the variable to fix, got %v", err)
	}
}

// The identifier cases that used to live in Validate's table. They moved with
// the check itself: it is per zone, so it needs the lane.
func TestValidateLaneRefusesAnUnusableIdentifier(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"blank":            "  ",
		"dotted":           "abc.def",
		"with underscore":  "abc_def",
		"a wildcard":       "*",
		"a leading hyphen": "-abc",
	}
	for name, uuid := range cases {
		t.Run(name, func(t *testing.T) {
			c := testConfig()
			c.DCVDelegationUUID = uuid
			c.DCVDelegationUUIDApp = uuid
			err := c.ValidateLane(lane.OrgPlatformDomain)
			assertRefused(t, err, "ValidateLane")
			if !errors.Is(err, ErrConfig) {
				t.Fatalf("a configuration refusal must wrap ErrConfig: %v", err)
			}
			// And no entry point derives anything under it.
			if _, derr := c.Registration(lane.OrgPlatformDomain, testIdentity, orgAnchor, testProof); derr == nil {
				t.Fatal("Registration derived a plan under an unusable identifier")
			}
		})
	}
}

// 🔴 PROXIED IS DECIDED BY THE LANE'S OWN ZONE, AND EVERY WRONG ANSWER IS
// SILENT IN PRODUCTION.
//
// A customer name matched as ours is published orange into THEIR zone, flattened
// at their edge, and fails at a renewal months later with every dashboard green.
// One of ours matched as a customer's is published grey beside a proxied target
// and answers 526.
//
// And the case that actually broke: a CROSS-ZONE name — ours, but in the other
// lane's zone. platform.mirrorstack.app is an app-zone name on the ORG lane; its
// records live in mirrorstack.app while its custom hostnames live in
// mirrorstack.ai, so proxying it in mirrorstack.app reaches an origin that zone
// has no certificate for. Measured live 2026-08-31: 526 orange, 404 grey.
//
// notmirrorstack.ai and mirrorstack.ai.evil.com are the two shapes a
// strings.Contains or a missing dot separator would admit.
func TestProxyRoutingIsDecidedByTheLanesOwnZone(t *testing.T) {
	c := Config{
		ReservedSuffixes: []string{"mirrorstack.ai", "mirrorstack.app"},
		OrgRoutingTarget: testOrgTarget,
		AppRoutingTarget: testAppTarget,
	}
	for _, tc := range []struct {
		lane   lane.Lane
		anchor string
		want   bool
	}{
		// Same zone as the lane's routing target — orange.
		{lane.OrgPlatformDomain, "studio.mirrorstack.ai", true},
		{lane.OrgAppDomain, "studio-tw.mirrorstack.app", true},
		{lane.AppDomain, "app.mirrorstack.app", true},

		// 🔴 CROSS-ZONE: ours, but the OTHER lane's zone. Orange here is the 526.
		{lane.OrgPlatformDomain, "platform.mirrorstack.app", false},
		{lane.OrgAppDomain, "app.mirrorstack.ai", false},

		// Customer domains, and names that merely look like ours.
		{lane.OrgPlatformDomain, "example.com", false},
		{lane.OrgAppDomain, "shop.example.com", false},
		{lane.OrgPlatformDomain, "notmirrorstack.ai", false},
		{lane.OrgPlatformDomain, "mirrorstack.ai.evil.com", false},
		{lane.OrgPlatformDomain, "", false},
	} {
		if got := c.proxyRouting(tc.lane, tc.anchor); got != tc.want {
			t.Errorf("proxyRouting(%s, %q) = %v, want %v", tc.lane, tc.anchor, got, tc.want)
		}
	}
}
