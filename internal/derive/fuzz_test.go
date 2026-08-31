package derive

import (
	"strings"
	"testing"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
)

// Property tests for the claims README.md makes about internal/derive, asserted
// over ARBITRARY input rather than over a table somebody thought of.
//
// 🔴 WHY THESE ARE FUZZ TARGETS AND NOT MORE TABLE TESTS.
//
// This repository is public so that a customer's own developers can settle
// "could MirrorStack break our website?" by reading it. An example-based test
// answers that question for the examples in the table. Each target below states
// one sentence from the README's comparison table and fails when that sentence
// stops being true for ANY input — including the spellings nobody wrote a row
// for. `go test` runs the seed corpus; `go test -fuzz` searches for the rest.
//
// Nothing here reaches a network, a resolver, a database or a Cloudflare
// account, because nothing in internal/derive can: it is a pure function of its
// arguments, holds no key, and the ownership proof's VALUE is passed in. There
// is nothing to fake, no clock to freeze, and every target is deterministic for
// a given input.
//
// Only example.com / example.net / example.org appear as customer domains. A
// real customer domain in a seed corpus is a real customer domain in a public
// repository, and the corpus is a file committed beside the code.

// ─── independent containment ────────────────────────────────────────────────

// fuzzFold is this file's own copy of "how the same DNS name arrives spelled":
// case-insensitive, with the root dot and surrounding space removed.
//
// It is a copy of dnsplan.NormalizeName ON PURPOSE, and it is the only
// duplication in this file that is deliberate. A property test that reaches for
// the production helper to decide whether the production answer is right proves
// only that one function agrees with itself.
func fuzzFold(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// fuzzAtOrUnder is the containment rule spelled out in strings, deliberately NOT
// dnsplan.Contains — the function every assertion below exists to check.
//
// The leading dot is the whole rule: `evilexample.com` ends in the same letters
// as `example.com` and is a different domain, so a bare strings.HasSuffix here
// would accept exactly the escape the anchor exists to prevent.
func fuzzAtOrUnder(anchor, name string) bool {
	a, n := fuzzFold(anchor), fuzzFold(name)
	if a == "" || n == "" {
		return false
	}
	return n == a || strings.HasSuffix(n, "."+a)
}

// fuzzLanes is the closed lane set, indexed by one fuzzed byte. Lane STRINGS are
// already fuzzed by TestRegistrationRefusesAMalformedRequest; what is worth
// searching here is the three lanes that actually derive something, against
// everything else being arbitrary.
var fuzzLanes = []lane.Lane{lane.OrgPlatformDomain, lane.OrgAppDomain, lane.AppDomain}

// fuzzEcho bounds what a failure message quotes back. A fuzzer's counterexample
// can be megabytes, and a test log is somewhere a value gets copied and copied
// again.
func fuzzEcho(s string) string {
	const max = 96
	if len(s) > max {
		return s[:max] + "…(truncated)"
	}
	return s
}

// fuzzValidConfig is the deployed shape, used where a target is fuzzing
// something other than the configuration.
func fuzzValidConfig() Config {
	return Config{
		OrgRoutingTarget:  testOrgTarget,
		AppRoutingTarget:  testAppTarget,
		DCVDelegationUUID: testUUID,
		ReservedSuffixes:  []string{"mirrorstack.ai", "mirrorstack.app"},
	}
}

// ─── the plan-wide safety properties ────────────────────────────────────────

// FuzzEveryDerivedPlanIsSafe asserts, for an arbitrary registration on an
// arbitrary deployment configuration, the five sentences the README answers
// "No." to:
//
//   - "Can it touch a name you didn't see?" — every record sits at or under the
//     anchor, the exact hostname the customer proved they own.
//   - "Can it write an A record or an MX record?" — the vocabulary is CNAME and
//     TXT, and no input produces an A, AAAA, MX, NS or CAA.
//   - A customer-zone record is never proxied. A proxied delegation record is
//     answered with addresses instead of being followed, so issuance — or a
//     renewal months later — fails with every dashboard on both sides green.
//   - "MirrorStack cannot publish this one — a proof we write ourselves proves
//     nothing." The ownership TXT is the customer's, and it is not in the set
//     this service may write.
//   - The set that actually reaches a DNS provider is inside the anchor too,
//     checked separately from the plan, because Publishable() is the list a
//     caller hands onward.
//
// A refused registration asserts nothing: refusing is always safe, and a target
// that demanded success would be a target that pressures the code to accept.
func FuzzEveryDerivedPlanIsSafe(f *testing.F) {
	// The tricky cases the table tests already name, so a plain `go test` run
	// exercises them: one seed per lane, an anchor deep enough to strain the
	// name bounds, the spellings that fold, the reserved names, a wildcard a
	// caller tried to spell, and the empty proof.
	seeds := []struct {
		laneSel                              uint8
		identity, anchor, proofValue         string
		orgTarget, appTarget, uuid, reserved string
	}{
		{0, testIdentity, orgAnchor, testProof, testOrgTarget, testAppTarget, testUUID, ""},
		{1, testIdentity, appsAnchor, testProof, testOrgTarget, testAppTarget, testUUID, ""},
		{2, testIdentity, oneAppAnchor, testProof, testOrgTarget, testAppTarget, testUUID, ""},
		{2, testIdentity, "shop." + oneAppAnchor, testProof, testOrgTarget, testAppTarget, testUUID, ""},
		{0, testIdentity, "EXAMPLE.COM.", testProof, testOrgTarget, testAppTarget, testUUID, ""},
		{0, strings.ToUpper(testIdentity), "  example.com  ", testProof, testOrgTarget, testAppTarget, testUUID, ""},
		// An anchor that can carry a proof but no certificate pointer, and one
		// that can carry neither. Both are refusals; the property is that they
		// are refusals rather than half a plan.
		{0, testIdentity, deepAnchor, testProof, testOrgTarget, testAppTarget, testUUID, ""},
		{1, testIdentity, deepAnchor, testProof, testOrgTarget, testAppTarget, testUUID, ""},
		{0, testIdentity, overDeepAnchor, testProof, testOrgTarget, testAppTarget, testUUID, ""},
		// The names with no customer at the other end.
		{0, testIdentity, "mirrorstack.ai", testProof, testOrgTarget, testAppTarget, testUUID, ""},
		{0, testIdentity, "someorg.mirrorstack.app", testProof, testOrgTarget, testAppTarget, testUUID, ""},
		{0, testIdentity, testOrgTarget, testProof, testOrgTarget, testAppTarget, testUUID, ""},
		// A domain that merely ends in the same letters is somebody else's and
		// is NOT reserved — the one-directional half of the rule.
		{0, testIdentity, "notmirrorstack.ai", testProof, testOrgTarget, testAppTarget, testUUID, ""},
		// Shapes a caller might send instead of a domain.
		{0, testIdentity, "*.example.com", testProof, testOrgTarget, testAppTarget, testUUID, ""},
		{0, testIdentity, "192.0.2.1", testProof, testOrgTarget, testAppTarget, testUUID, ""},
		{0, testIdentity, "example", testProof, testOrgTarget, testAppTarget, testUUID, ""},
		{0, testIdentity, "_acme-challenge.example.com", testProof, testOrgTarget, testAppTarget, testUUID, ""},
		{0, "org-1", orgAnchor, testProof, testOrgTarget, testAppTarget, testUUID, ""},
		{0, testIdentity, orgAnchor, "", testOrgTarget, testAppTarget, testUUID, ""},
		{0, testIdentity, orgAnchor, "   ", testOrgTarget, testAppTarget, testUUID, ""},
		// A proof value the caller chose freely: this package holds no key and
		// checks no shape, so the only property is that it is carried through.
		{0, testIdentity, orgAnchor, "attacker.example", testOrgTarget, testAppTarget, testUUID, ""},
		// Deployments other than production, and the configuration refusals.
		{0, testIdentity, orgAnchor, testProof, "edge.example.net", "edge.example.org", "abcdef0123456789", "staging.example"},
		{0, testIdentity, orgAnchor, testProof, "", testAppTarget, testUUID, ""},
		{0, testIdentity, orgAnchor, testProof, testOrgTarget, testAppTarget, "", ""},
		{0, testIdentity, orgAnchor, testProof, testOrgTarget, testAppTarget, "not a label", ""},
		{0, testIdentity, orgAnchor, testProof, testOrgTarget, testAppTarget, strings.Repeat("a", 64), ""},
		// A staging routing target that is ABOVE the anchor: connecting the very
		// name a routing CNAME points at would publish a loop.
		{0, testIdentity, "sub.example.com", testProof, "example.com", testAppTarget, testUUID, ""},
	}
	for _, s := range seeds {
		f.Add(s.laneSel, s.identity, s.anchor, s.proofValue, s.orgTarget, s.appTarget, s.uuid, s.reserved)
	}

	f.Fuzz(func(t *testing.T, laneSel uint8, identity, anchor, proofValue, orgTarget, appTarget, uuid, reserved string) {
		cfg := Config{
			OrgRoutingTarget:  orgTarget,
			AppRoutingTarget:  appTarget,
			DCVDelegationUUID: uuid,
			ReservedSuffixes: append(append([]string(nil), platformSuffixes...),
				splitSuffixes(reserved)...),
		}
		l := fuzzLanes[int(laneSel)%len(fuzzLanes)]

		plan, err := cfg.Registration(l, identity, anchor, proofValue)
		if err != nil {
			// A refusal must carry nothing with it. Half a plan beside an error
			// is what a caller that logs the error and uses the value writes.
			if len(plan.Items) != 0 {
				t.Fatalf("a refused Registration returned %d records: %v", len(plan.Items), err)
			}
			return
		}

		// The anchor a plan is bounded by is the customer's own name folded, and
		// nothing else. A rewritten anchor would bound the plan against a name
		// the customer never typed and cannot recognise on a consent screen.
		if plan.Anchor != fuzzFold(anchor) {
			t.Fatalf("anchor %q was rewritten to %q", fuzzEcho(anchor), fuzzEcho(plan.Anchor))
		}

		fuzzAssertPlanIsSafe(t, plan)

		// The ownership proof: exactly one, the customer's, and not ours to
		// write. Its absence would be a registration with nothing proving the
		// anchor; a second one would be a proof a console cannot present.
		ownership := 0
		for _, item := range plan.Items {
			if item.Purpose != PurposeOwnership {
				continue
			}
			ownership++
			// The SOURCE is no longer asserted: the row is ours to publish now that it
			// gates nothing (see derive.ownershipItem). That it is derived exactly ONCE
			// still is — two rows at one owner is a conflict no pass can resolve.
			if item.Record.Type != "TXT" {
				t.Fatalf("the ownership proof for %q is a %q record, want TXT",
					fuzzEcho(plan.Anchor), item.Record.Type)
			}
		}
		if ownership != 1 {
			t.Fatalf("%s on %q derived %d ownership proofs, want exactly 1",
				plan.Lane, fuzzEcho(plan.Anchor), ownership)
		}
	})
}

// fuzzAssertPlanIsSafe is every property that must hold of ANY plan this package
// returns, from any entry point. Shared so a property asserted on Registration
// is not a property BindApp quietly lacks.
func fuzzAssertPlanIsSafe(t *testing.T, plan Plan) {
	t.Helper()
	for i, item := range plan.Items {
		record := item.Record

		// "Can it touch a name you didn't see?" — No.
		if !fuzzAtOrUnder(plan.Anchor, record.Name) {
			t.Fatalf("record %d %q is outside the anchor %q", i, fuzzEcho(record.Name), fuzzEcho(plan.Anchor))
		}
		// "Can it write an A record or an MX record?" — No.
		if record.Type != "CNAME" && record.Type != "TXT" {
			t.Fatalf("record %d for %q is a %q, and the vocabulary is CNAME and TXT",
				i, fuzzEcho(record.Name), fuzzEcho(record.Type))
		}
		// A record in a CUSTOMER's zone is never proxied.
		if record.Proxied {
			t.Fatalf("record %d %q is proxied, and a proxied delegation record answers with addresses instead of following the delegation",
				i, fuzzEcho(record.Name))
		}
		// A row with no purpose, no source or no sentence is a row a customer is
		// asked to accept with nothing to accept it on.
		if item.Purpose == "" || item.Source == "" || item.Explain == "" {
			t.Fatalf("record %d %q is unlabelled: purpose %q source %q explain %q",
				i, fuzzEcho(record.Name), item.Purpose, item.Source, fuzzEcho(item.Explain))
		}
	}

	// Publishable() is checked separately, and on its own terms, because it is
	// the set that actually reaches a provider. A caller appends relayed records
	// to it and hands it onward; a containment property that held only over
	// Plan.Items would be a property of a list nobody publishes.
	publishable := plan.Publishable()
	for i, record := range publishable {
		if !fuzzAtOrUnder(plan.Anchor, record.Name) {
			t.Fatalf("publishable record %d %q is outside the anchor %q",
				i, fuzzEcho(record.Name), fuzzEcho(plan.Anchor))
		}
		if record.Type != "CNAME" && record.Type != "TXT" {
			t.Fatalf("publishable record %d for %q is a %q", i, fuzzEcho(record.Name), fuzzEcho(record.Type))
		}
		if record.Proxied {
			t.Fatalf("publishable record %d %q is proxied", i, fuzzEcho(record.Name))
		}
	}

	// 🔴 Nothing the customer publishes is in the set this service may write.
	// Asserted by VALUE rather than by counting, because the defect this guards
	// against is the ownership TXT reappearing in the publish list under a
	// different index, which a count would not see.
	for _, item := range plan.Items {
		if item.Source != SourceCustomer {
			continue
		}
		for _, record := range publishable {
			if record == item.Record {
				t.Fatalf("%s %q is the customer's to publish and is in Publishable()",
					record.Type, fuzzEcho(record.Name))
			}
		}
	}
}

// ─── one app under an already-proven parent ─────────────────────────────────

// FuzzBindAppStaysUnderItsParent asserts what the README promises about
// deploying an app under an org's app domain: the parent's proof already covers
// it, the parent's wildcard already routes it, and the only thing a new app owes
// is the certificate pointer a wildcard cannot supply.
//
// The slug is the ONE caller-chosen string anywhere in this design, so it is the
// one place a caller could try to choose a shape rather than a name. The
// properties are:
//
//   - Every derived name is STRICTLY beneath the parent. Not merely inside it:
//     a record at the parent itself would be a record on a name the org is
//     already being served from.
//   - The certificate name is exactly `_acme-challenge.<slug>.<parent>`. A
//     dropped separator ships `_acme-challengeblog.example.net`, which is a
//     valid name that no certificate authority ever reads.
//   - No routing record. The wildcard already routes this app, and a second
//     CNAME beside a name in use is a record the customer never saw.
func FuzzBindAppStaysUnderItsParent(f *testing.F) {
	for _, seed := range []struct{ parent, slug string }{
		{appsAnchor, "blog"},
		{appsAnchor, "BLOG"},
		{"apps." + appsAnchor, "blog"},
		{appsAnchor, strings.Repeat("a", 63)},
		{appsAnchor, "a"},
		{appsAnchor, "1"},
		{appsAnchor, "a-b-c"},
		// The slugs the table test names: a shape rather than a name, and the
		// owners that already mean something to somebody else.
		{appsAnchor, ""},
		{appsAnchor, "a.b"},
		{appsAnchor, "blog.example.net"},
		{appsAnchor, "*"},
		{appsAnchor, "*.blog"},
		{appsAnchor, "_acme-challenge"},
		{appsAnchor, "_cf-custom-hostname"},
		{appsAnchor, "_mirrorstack-challenge"},
		{appsAnchor, "_dmarc"},
		{appsAnchor, "-blog"},
		{appsAnchor, "blog-"},
		{appsAnchor, "bl og"},
		{appsAnchor, "blög"},
		{appsAnchor, strings.Repeat("a", 64)},
		// Parents: folded spellings, a reserved name, and the depths where the
		// pointer stops fitting in a DNS name.
		{"EXAMPLE.NET.", "blog"},
		{"mirrorstack.app", "blog"},
		{deepAnchor, "blog"},
		{overDeepAnchor, "blog"},
		{"", "blog"},
		{"example", "blog"},
		{"*.example.net", "blog"},
	} {
		f.Add(seed.parent, seed.slug)
	}

	f.Fuzz(func(t *testing.T, parent, slug string) {
		plan, err := fuzzValidConfig().BindApp(parent, slug)
		if err != nil {
			if len(plan.Items) != 0 {
				t.Fatalf("a refused BindApp returned %d records: %v", len(plan.Items), err)
			}
			return
		}

		fuzzAssertPlanIsSafe(t, plan)

		if plan.Anchor != fuzzFold(parent) {
			t.Fatalf("parent %q was rewritten to %q", fuzzEcho(parent), fuzzEcho(plan.Anchor))
		}
		// Case is folded because DNS is case-insensitive, and nothing else is
		// repaired: a trimmed or substituted slug is a hostname nobody typed.
		want := "_acme-challenge." + strings.ToLower(slug) + "." + plan.Anchor
		if len(plan.Items) != 1 {
			t.Fatalf("BindApp derived %d records for %q under %q, want exactly the certificate pointer",
				len(plan.Items), fuzzEcho(slug), fuzzEcho(plan.Anchor))
		}
		item := plan.Items[0]
		if item.Record.Name != want {
			t.Fatalf("certificate pointer is named %q, want %q", fuzzEcho(item.Record.Name), fuzzEcho(want))
		}
		if item.Purpose != PurposeCertDCV {
			t.Fatalf("BindApp derived a %q record; the parent's proof and wildcard already cover this app", item.Purpose)
		}
		// Strictly beneath: inside the parent AND not the parent itself.
		if item.Record.Name == plan.Anchor {
			t.Fatalf("BindApp derived a record AT the parent %q", fuzzEcho(plan.Anchor))
		}
		// The hostname prefix on the delegation target is load-bearing: without
		// it every host delegated to one of our zones collides on one name, and
		// a certificate authority following the pointer reads a token for
		// somebody else's hostname or nothing at all.
		host := strings.ToLower(slug) + "." + plan.Anchor
		if item.Record.Value != host+"."+testUUID+".dcv.cloudflare.com" {
			t.Fatalf("delegation target for %q is %q", fuzzEcho(host), fuzzEcho(item.Record.Value))
		}
	})
}

// ─── configuration is input too ─────────────────────────────────────────────

// FuzzConfigCannotProduceARecordOutsideTheAnchor asserts that the deployment's
// own settings cannot break the one promise the anchor makes.
//
// 🔴 THE ROUTING TARGETS AND THE DCV IDENTIFIER COME FROM CONFIGURATION, NOT
// FROM THE CALLER — AND CONFIGURATION IS STILL INPUT. It arrives from four
// environment variables, and an operator with a typo is a likelier adversary
// than a hostile private half. The property is about NAMES, which is what
// containment bounds: a misconfigured target is a record pointing somewhere
// useless, and that is visible in the customer's own zone. A record OUTSIDE the
// anchor would not be.
//
// It also asserts the other half: a Config that Validate() rejects produces no
// plan from any entry point. An unconfigured deployment must refuse at the
// boundary rather than derive a plan with a hole in it.
func FuzzConfigCannotProduceARecordOutsideTheAnchor(f *testing.F) {
	for _, seed := range []struct{ orgTarget, appTarget, uuid string }{
		{testOrgTarget, testAppTarget, testUUID},
		{"edge.example.net", "edge.example.org", "abcdef0123456789"},
		// Each field emptied in turn: Validate must name the missing one.
		{"", testAppTarget, testUUID},
		{testOrgTarget, "", testUUID},
		{testOrgTarget, testAppTarget, ""},
		{"   ", "   ", "   "},
		// Targets that are not DNS names.
		{"not a domain", testAppTarget, testUUID},
		{"example", testAppTarget, testUUID},
		{"*.example.net", testAppTarget, testUUID},
		{"192.0.2.1", testAppTarget, testUUID},
		{strings.Repeat("a.", 200) + "example.net", testAppTarget, testUUID},
		// Identifiers that are not one DNS label.
		{testOrgTarget, testAppTarget, "a.b"},
		{testOrgTarget, testAppTarget, "_uuid"},
		{testOrgTarget, testAppTarget, "-uuid"},
		{testOrgTarget, testAppTarget, "*"},
		{testOrgTarget, testAppTarget, strings.Repeat("a", 63)},
		{testOrgTarget, testAppTarget, strings.Repeat("a", 64)},
		// A separator smuggled into a value, which is the shape of the bug that
		// builds a name out of two halves and one dot too few or too many.
		{testOrgTarget, testAppTarget, "0123456789abcdef."},
		{"connect.mirrorstack.ai.", "connect.mirrorstack.app.", "0123456789ABCDEF"},
		// Targets at or above a fixture anchor: reserved by construction, so
		// the anchor must be refused rather than pointed at itself.
		{"example.com", testAppTarget, testUUID},
		{testOrgTarget, "example.net", testUUID},
	} {
		f.Add(seed.orgTarget, seed.appTarget, seed.uuid)
	}

	f.Fuzz(func(t *testing.T, orgTarget, appTarget, uuid string) {
		cfg := Config{
			OrgRoutingTarget:  orgTarget,
			AppRoutingTarget:  appTarget,
			DCVDelegationUUID: uuid,
			ReservedSuffixes:  []string{"mirrorstack.ai", "mirrorstack.app"},
		}
		valid := cfg.Validate() == nil

		type attempt struct {
			what string
			run  func() (Plan, error)
		}
		attempts := []attempt{
			{"lane 1", func() (Plan, error) {
				return cfg.Registration(lane.OrgPlatformDomain, testIdentity, orgAnchor, testProof)
			}},
			{"lane 2", func() (Plan, error) {
				return cfg.Registration(lane.OrgAppDomain, testIdentity, appsAnchor, testProof)
			}},
			{"lane 3", func() (Plan, error) {
				return cfg.Registration(lane.AppDomain, testIdentity, oneAppAnchor, testProof)
			}},
			{"bind app", func() (Plan, error) { return cfg.BindApp(appsAnchor, "blog") }},
		}
		for _, a := range attempts {
			plan, err := a.run()
			if err != nil {
				if len(plan.Items) != 0 {
					t.Fatalf("%s: a refused derivation returned %d records", a.what, len(plan.Items))
				}
				continue
			}
			if !valid {
				t.Fatalf("%s: a Config that Validate() rejects produced a %d-record plan",
					a.what, len(plan.Items))
			}
			fuzzAssertPlanIsSafe(t, plan)
		}
	})
}

// ─── MirrorStack's own names are not connectable ────────────────────────────

// FuzzReservedSuffixesAreNeverDerivable asserts the refusal that keeps the
// ownership proof meaningful: this service will not publish into a MirrorStack
// name at all.
//
// 🔴 A NAME UNDER ONE OF THESE HAS NO CUSTOMER AT THE OTHER END. Its ownership
// proof would be published by us, which is the exact defect the rebuild exists
// to remove, and the customer-grant write path would have become a platform-zone
// editor. The two MirrorStack suffixes are hardcoded, so a deployment can add to
// the list and cannot remove them; both routing targets are folded in, because
// connecting the very name a routing CNAME points at would publish a loop.
//
// The refusal must hold for every SPELLING of the same name, not merely for the
// one somebody wrote a table row for: trailing root dot, uppercase, mixed case,
// surrounding space, and the A-label a customer supplies for an
// internationalized domain. So the anchor is fuzzed freely and the property is
// checked with this file's own suffix rule.
func FuzzReservedSuffixesAreNeverDerivable(f *testing.F) {
	for _, seed := range []struct {
		laneSel        uint8
		anchor, extras string
	}{
		{0, "mirrorstack.ai", ""},
		{0, "MirrorStack.AI", ""},
		{0, "mirrorstack.ai.", ""},
		{0, "  MIRRORSTACK.AI.  ", ""},
		{0, "account.mirrorstack.ai", ""},
		{1, "apps.mirrorstack.app", ""},
		{2, "someorg.mirrorstack.app", ""},
		{0, "a.b.c.account.MirrorStack.Ai.", ""},
		{0, testOrgTarget, ""},
		{0, testAppTarget, ""},
		// The one-directional half: a name that merely ends in the same letters
		// is somebody else's domain and must NOT be refused.
		{0, "notmirrorstack.ai", ""},
		{0, "mirrorstack.ai.example.com", ""},
		// An A-label, which is the only spelling of an internationalized domain
		// this service accepts.
		{0, "xn--fiqs8s.example.com", ""},
		{0, "xn--mirrorstack-0j3f.ai", ""},
		// Deployment-added suffixes, in the separators an operator writes.
		{0, "staging.example", "staging.example"},
		{0, "a.staging.example", "staging.example, other.example"},
		{0, "other.example", "staging.example;other.example"},
		{0, "OTHER.EXAMPLE.", "staging.example  other.example"},
		{0, orgAnchor, "example.com"},
		{0, "sub." + orgAnchor, "EXAMPLE.COM."},
		// A list entry that evaporates: present, so somebody intended
		// protection, and normalizing to nothing. It must refuse the config
		// rather than silently protect none.
		{0, orgAnchor, "."},
		{0, orgAnchor, ".."},
		// The unremarkable case, so the target does not only ever see refusals.
		{0, orgAnchor, ""},
		{1, appsAnchor, ""},
		{2, oneAppAnchor, ""},
	} {
		f.Add(seed.laneSel, seed.anchor, seed.extras)
	}

	f.Fuzz(func(t *testing.T, laneSel uint8, anchor, extras string) {
		cfg := fuzzValidConfig()
		cfg.ReservedSuffixes = append(append([]string(nil), platformSuffixes...),
			splitSuffixes(extras)...)
		l := fuzzLanes[int(laneSel)%len(fuzzLanes)]

		plan, err := cfg.Registration(l, testIdentity, anchor, testProof)
		bound, bindErr := cfg.BindApp(anchor, "blog")

		for _, got := range []struct {
			what string
			plan Plan
			err  error
		}{{"Registration", plan, err}, {"BindApp", bound, bindErr}} {
			if got.err != nil {
				continue
			}
			// The effective list, including both routing targets. Nothing that
			// derived successfully may be at or under any of them.
			for _, suffix := range cfg.reserved() {
				if fuzzAtOrUnder(suffix, got.plan.Anchor) {
					t.Fatalf("%s accepted %q, which is at or under the reserved suffix %q",
						got.what, fuzzEcho(got.plan.Anchor), fuzzEcho(suffix))
				}
			}
			// Nothing DERIVED may be either — the anchor bounds the names, but
			// a suffix could still sit between the anchor and a derived name if
			// a record were ever derived outside it.
			for _, item := range got.plan.Items {
				for _, suffix := range cfg.reserved() {
					if fuzzAtOrUnder(suffix, item.Record.Name) {
						t.Fatalf("%s derived %q, which is at or under the reserved suffix %q",
							got.what, fuzzEcho(item.Record.Name), fuzzEcho(suffix))
					}
				}
			}
		}
	})
}
