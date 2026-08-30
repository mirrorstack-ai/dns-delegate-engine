package consent

import (
	"errors"
	"html/template"
	"strings"
	"testing"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/derive"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/proof"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/relay"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/grantcrypto"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/testsupport"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/testsupport/derivefixture"
)

const (
	fixtureAnchor   = "example.net"
	fixtureIdentity = "11111111-2222-3333-4444-555555555555"
	fixtureNonce    = "0123456789abcdef0123456789abcdef"

	// fixtureProof is a value of the shape internal/proof produces. Its bytes
	// are arbitrary — derive deliberately does not check the shape of a proof
	// value, because checking it would be that package asserting an encoding it
	// holds no key to verify.
	fixtureProof = "msv1-aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggg"
)

// 🔴 testsupport.GoldenKeyset is the SAME key internal/proof's golden vectors
// use, which is what makes TestAnOwnershipProofIsNotAnAcknowledgement a test of
// the HKDF domain separation rather than of two different keys.

// lane2Plan is a real registration plan from internal/derive, not a hand-built
// one. Every test that asks what the page SAYS runs against a plan the service
// would actually produce; only the tests that ask what the page REFUSES build
// their own, because the plans they need are ones derive will not construct.
func lane2Plan(t *testing.T, anchor string) derive.Plan {
	t.Helper()
	plan, err := derivefixture.Config().Registration(lane.OrgAppDomain, fixtureIdentity, anchor, fixtureProof)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func renderedPage(t *testing.T, plan derive.Plan, nonce string) string {
	t.Helper()
	html, err := Page(plan, nonce)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	return html
}

// ───────────────────────────── Required ─────────────────────────────

// 🔴 NO KNOWN LANE DEMANDS AN ACKNOWLEDGEMENT (owner's decision, 2026-08-30).
//
// org_app_domain did until it was measured in production: the private half has
// no call that obtains a Token, so every authorize on the wildcard lane was
// refused and the lane could not be completed by anyone. See Required's comment.
func TestNoKnownLaneDemandsAnAcknowledgement(t *testing.T) {
	for _, l := range []lane.Lane{lane.OrgPlatformDomain, lane.OrgAppDomain, lane.AppDomain} {
		if Required(l) {
			t.Errorf("Required(%q) = true, want false", l)
		}
	}
}

// 🔴 THE WILDCARD LANE KEEPS ITS PAGE, AND THAT IS THE POINT OF THE SPLIT.
//
// Dropping the requirement must not take the disclosure with it: the page is the
// only rendering of what a standing wildcard grant is, it is what re-arming
// would MAC over, and Offer/Redeem are useless without it. A change that made
// Required return false everywhere AND deleted the page would pass the test
// above and lose the thing worth keeping.
func TestOnlyTheWildcardLaneHasAPage(t *testing.T) {
	for _, tc := range []struct {
		lane lane.Lane
		want bool
	}{
		{lane.OrgPlatformDomain, false},
		{lane.OrgAppDomain, true},
		{lane.AppDomain, false},
	} {
		if got := HasPage(tc.lane); got != tc.want {
			t.Errorf("HasPage(%q) = %v, want %v", tc.lane, got, tc.want)
		}
	}
}

// 🔴 AN UNRECOGNISED LANE HAS NO PAGE AND IS STILL REQUIRED, SO IT IS BLOCKED.
//
// That pairing is the fail-closed property, and it only reads as deliberate if
// both halves are asserted together: it cannot obtain an acknowledgement it
// cannot be shown, so a new lane is refused rather than quietly waved through
// or — worse — shown the wildcard page, which would tell its customer their
// grant is standing when nobody has decided that.
func TestAnUnrecognisedLaneIsBlockedRatherThanDescribedWrongly(t *testing.T) {
	const unknown = lane.Lane("org_something_new")
	if !Required(unknown) {
		t.Error("an unrecognised lane must still demand an acknowledgement")
	}
	if HasPage(unknown) {
		t.Error("an unrecognised lane must not be given the wildcard lane's page")
	}
}

// 🔴 A LANE THIS PACKAGE DOES NOT RECOGNISE MUST BE ASKED FOR A PAGE, NOT
// EXCUSED FROM ONE. Required is an allow-list of the two lanes whose record sets
// are closed and listable; a fourth lane added to package lane inherits the
// requirement rather than skipping it, because "broader than a list" is the
// property a new lane is most likely to share with the wildcard one. Rewriting
// the switch as `l == OrgAppDomain` passes every other test in this file.
func TestRequiredDemandsAPageForALaneItDoesNotRecognise(t *testing.T) {
	for _, unknown := range []lane.Lane{"", "lane_4", "ORG_APP_DOMAIN", "org_app_domain ", "org_platform"} {
		if !Required(unknown) {
			t.Errorf("Required(%q) = false; an unrecognised lane must be required to have a page", unknown)
		}
	}
}

// The asymmetry between Required and Page is deliberate and is pinned here so it
// cannot be "tidied up" into agreement: Required fails closed toward DEMANDING a
// page, Page fails closed toward refusing to render one whose sentences it
// cannot vouch for. Together they block an unrecognised lane instead of
// describing it wrongly.
func TestAnUnknownLaneIsRequiredToHaveAPageAndCannotBeGivenOne(t *testing.T) {
	unknown := lane.Lane("lane_4")
	if !Required(unknown) {
		t.Fatalf("Required(%q) = false", unknown)
	}
	plan := lane2Plan(t, fixtureAnchor)
	plan.Lane = unknown
	if _, err := Page(plan, fixtureNonce); !errors.Is(err, ErrConsent) {
		t.Fatalf("Page for lane %q = %v, want ErrConsent", unknown, err)
	}
}

// ──────────────────────── Token and Verify ────────────────────────

func TestTokenAndVerifyRoundTrip(t *testing.T) {
	sealer := testsupport.SealerFrom(t, testsupport.GoldenKeyset(t))
	token, err := Token(sealer, fixtureNonce, fixtureAnchor)
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if !strings.HasPrefix(token, valuePrefix) {
		t.Errorf("token %q does not carry the %q prefix", token, valuePrefix)
	}
	if !Verify(sealer, fixtureNonce, fixtureAnchor, token) {
		t.Fatal("Verify rejected the token Token just minted")
	}
}

func TestVerifyRefusesATokenForADifferentReferenceOrAnchor(t *testing.T) {
	sealer := testsupport.SealerFrom(t, testsupport.GoldenKeyset(t))
	token, err := Token(sealer, fixtureNonce, fixtureAnchor)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		nonce  string
		anchor string
	}{
		{"another reference", "ffffffffffffffffffffffffffffffff", fixtureAnchor},
		{"one character of the reference", fixtureNonce[:len(fixtureNonce)-1] + "0", fixtureAnchor},
		{"another anchor", fixtureNonce, "example.org"},
		{"a subdomain of the anchor", fixtureNonce, "apps." + fixtureAnchor},
		{"a parent of the anchor", fixtureNonce, "net"},
		{"both", "ffffffffffffffffffffffffffffffff", "example.org"},
	} {
		if Verify(sealer, tc.nonce, tc.anchor, token) {
			t.Errorf("%s: Verify accepted a token minted for (%q, %q)", tc.name, fixtureNonce, fixtureAnchor)
		}
	}
}

// 🔴 ROTATION MUST NOT INVALIDATE AN ACKNOWLEDGEMENT ALREADY GIVEN. A key
// rotated between serving the page and completing the authorization would
// otherwise send a customer back round the consent flow with nothing to tell
// them why.
func TestVerifyAcceptsATokenMintedUnderARetiredKey(t *testing.T) {
	old := testsupport.SealerFrom(t, testsupport.Keyset(t, "v1"))
	token, err := Token(old, fixtureNonce, fixtureAnchor)
	if err != nil {
		t.Fatal(err)
	}
	// v2 is now active and v1 is retained: the token still verifies.
	rotated := testsupport.SealerFrom(t, testsupport.Keyset(t, "v2", "v1"))
	if !Verify(rotated, fixtureNonce, fixtureAnchor, token) {
		t.Fatal("Verify rejected a token minted under a retired-but-present key")
	}
	// Minting under the rotated keyset uses the ACTIVE key, so the two tokens
	// differ — and both are accepted while both keys are present.
	fresh, err := Token(rotated, fixtureNonce, fixtureAnchor)
	if err != nil {
		t.Fatal(err)
	}
	if fresh == token {
		t.Fatal("rotating the active key did not change the minted token")
	}
	if !Verify(rotated, fixtureNonce, fixtureAnchor, fresh) {
		t.Fatal("Verify rejected a token minted under the active key")
	}
	// Dropping v1 from the keyset is what actually invalidates it — a deliberate
	// act with a customer-visible consequence, not a cleanup.
	dropped := testsupport.SealerFrom(t, testsupport.Keyset(t, "v2"))
	if Verify(dropped, fixtureNonce, fixtureAnchor, token) {
		t.Fatal("Verify accepted a token under a key that is no longer in the keyset")
	}
}

func TestVerifyFailsClosed(t *testing.T) {
	sealer := testsupport.SealerFrom(t, testsupport.GoldenKeyset(t))
	token, err := Token(sealer, fixtureNonce, fixtureAnchor)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		sealer *grantcrypto.Sealer
		nonce  string
		anchor string
		token  string
	}{
		{"no keyset", nil, fixtureNonce, fixtureAnchor, token},
		{"another deployment's keyset", testsupport.SealerFrom(t, testsupport.Keyset(t, "elsewhere")), fixtureNonce, fixtureAnchor, token},
		{"no token", sealer, fixtureNonce, fixtureAnchor, ""},
		{"whitespace token", sealer, fixtureNonce, fixtureAnchor, "   "},
		{"a token that is not ours", sealer, fixtureNonce, fixtureAnchor, "msack1-notatoken"},
		{"the prefix alone", sealer, fixtureNonce, fixtureAnchor, valuePrefix},
		{"the token without its prefix", sealer, fixtureNonce, fixtureAnchor, strings.TrimPrefix(token, valuePrefix)},
		{"a truncated token", sealer, fixtureNonce, fixtureAnchor, token[:len(token)-1]},
		{"no reference", sealer, "", fixtureAnchor, token},
		{"no anchor", sealer, fixtureNonce, "", token},
		{"a reference carrying the separator", sealer, "abc\x00" + fixtureAnchor, "", token},
		{"an over-long reference", sealer, strings.Repeat("a", maxNonce+1), fixtureAnchor, token},
		{"an over-long anchor", sealer, fixtureNonce, strings.Repeat("a.", 200) + "example.net", token},
	} {
		if Verify(tc.sealer, tc.nonce, tc.anchor, tc.token) {
			t.Errorf("%s: Verify returned true", tc.name)
		}
	}
}

func TestTokenRefusesWhatItCannotBind(t *testing.T) {
	sealer := testsupport.SealerFrom(t, testsupport.GoldenKeyset(t))
	for _, tc := range []struct {
		name   string
		sealer *grantcrypto.Sealer
		nonce  string
		anchor string
	}{
		{"no keyset", nil, fixtureNonce, fixtureAnchor},
		{"no reference", sealer, "", fixtureAnchor},
		{"whitespace reference", sealer, "  \t ", fixtureAnchor},
		{"no anchor", sealer, fixtureNonce, ""},
		{"anchor that is only a root dot", sealer, fixtureNonce, "."},
		{"a separator in the reference", sealer, "abc\x00def", fixtureAnchor},
		{"a separator in the anchor", sealer, fixtureNonce, "example\x00.net"},
		{"an over-long reference", sealer, strings.Repeat("a", maxNonce+1), fixtureAnchor},
		{"an over-long anchor", sealer, fixtureNonce, strings.Repeat("a.", 200) + "example.net"},
	} {
		got, err := Token(tc.sealer, tc.nonce, tc.anchor)
		if !errors.Is(err, ErrConsent) {
			t.Errorf("%s: Token error = %v, want ErrConsent", tc.name, err)
		}
		if got != "" {
			t.Errorf("%s: Token returned %q alongside a refusal", tc.name, got)
		}
	}
	// A missing keyset is the one cause a caller may genuinely need to tell apart
	// — it is a deployment fault rather than a bad request — so it stays
	// distinguishable through the wrapped sentinel.
	if _, err := Token(nil, fixtureNonce, fixtureAnchor); !errors.Is(err, grantcrypto.ErrNoKeyset) {
		t.Errorf("Token with no keyset = %v, want it to wrap ErrNoKeyset", err)
	}
}

// The anchor is folded and the reference is only trimmed, and both halves of
// that matter. An anchor arrives spelled several legitimate ways; a reference is
// a value this service minted, so a spelling we never issued is not one to
// accept.
func TestTokenFoldsTheAnchorAndOnlyTrimsTheReference(t *testing.T) {
	sealer := testsupport.SealerFrom(t, testsupport.GoldenKeyset(t))
	token, err := Token(sealer, fixtureNonce, fixtureAnchor)
	if err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{"EXAMPLE.NET", "example.net.", " Example.Net. ", "eXaMpLe.NeT"} {
		if !Verify(sealer, fixtureNonce, spelling, token) {
			t.Errorf("Verify rejected the anchor spelled %q", spelling)
		}
	}
	if !Verify(sealer, " "+fixtureNonce+"\n", fixtureAnchor, token) {
		t.Error("Verify rejected a reference with surrounding whitespace")
	}
	if Verify(sealer, strings.ToUpper(fixtureNonce), fixtureAnchor, token) {
		t.Error("Verify accepted a reference case-folded into a spelling this service never issued")
	}
	// The token itself folds, because base32 is case-insensitive by construction
	// and a value copied between two systems may come back in either case.
	if !Verify(sealer, fixtureNonce, fixtureAnchor, strings.ToUpper(token)) {
		t.Error("Verify rejected its own token in upper case")
	}
}

// 🔴 THE GOLDEN ACKNOWLEDGEMENT.
//
// Key 0x00…0x1f, reference 0123456789abcdef0123456789abcdef, anchor example.net.
// Reproducible without a Go toolchain:
//
//	subkey  = HKDF-SHA256(ikm=key, salt="", info=hkdfInfo, L=32)
//	mac     = HMAC-SHA256(subkey, "ms-dns-consent/v1\x00" + nonce + "\x00" + anchor)
//	token   = "msack1-" + lowercase(base32(mac) without padding)
//
// This value was recomputed independently in Python from that recipe and matched
// byte for byte. A change here invalidates every acknowledgement in flight —
// small next to internal/proof's equivalent, which is exactly why it is worth
// pinning: the temptation to treat this one as editable is the difference.
func TestGoldenAcknowledgement(t *testing.T) {
	const want = "msack1-p5ge5dpa7quiyd3vr5hjbln7iruahqbnrqspj3l656pbri3okuja"
	got, err := Token(testsupport.SealerFrom(t, testsupport.GoldenKeyset(t)), fixtureNonce, fixtureAnchor)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("the acknowledgement format moved:\n got  %s\n want %s", got, want)
	}
	if len(got) != len(valuePrefix)+52 {
		t.Errorf("token is %d characters, want %d", len(got), len(valuePrefix)+52)
	}
}

// 🔴 AN OWNERSHIP PROOF IS PUBLISHED IN PUBLIC DNS FOR ANYONE TO READ. If it
// could be replayed as a consent acknowledgement, "the customer agreed to a
// standing wildcard" would be established by a value we hand out deliberately.
// The HKDF info is what separates them; this test is what notices if the two
// ever share one.
func TestAnOwnershipProofIsNotAnAcknowledgement(t *testing.T) {
	keyset := testsupport.GoldenKeyset(t)
	sealer := testsupport.SealerFrom(t, keyset)
	prover := proof.Prover{Sealer: sealer}
	published, err := prover.Expected(lane.OrgAppDomain, fixtureIdentity, fixtureAnchor)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(sealer, fixtureNonce, fixtureAnchor, published) {
		t.Fatal("an ownership proof verified as a consent acknowledgement")
	}
	// And the reverse: an acknowledgement must not pass as an ownership proof.
	token, err := Token(sealer, fixtureNonce, fixtureAnchor)
	if err != nil {
		t.Fatal(err)
	}
	matched, err := prover.Matches(lane.OrgAppDomain, fixtureIdentity, fixtureAnchor, []string{token})
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Fatal("a consent acknowledgement matched as an ownership proof")
	}
}

// ─────────────────────────────── Page ───────────────────────────────

// The two things this page exists to say. A description of a standing wildcard
// grant that names neither the wildcard nor the word is not the disclosure it
// claims to be, however well it reads.
func TestPageNamesTheWildcardAndSaysStanding(t *testing.T) {
	html := renderedPage(t, lane2Plan(t, fixtureAnchor), fixtureNonce)
	for _, want := range []string{
		"*." + fixtureAnchor,      // the wildcard itself
		"standing",                // the word, in the customer's language
		"no expiry",               // and what it means, spelled out
		"connect.mirrorstack.app", // what the wildcard points at
		fixtureNonce,              // the reference the acknowledgement binds
		proof.Prefix + fixtureAnchor,
		fixtureProof,
		"re-create a record you delete",
		`leave this one name alone`,
		"revoking the whole grant",
		"Revoke at your DNS provider",
		"24 hours",
		"CNAME",
		"TXT",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the page does not contain %q", want)
		}
	}
	// The per-app records, which are the point of a standing grant: names that
	// do not exist yet.
	for _, want := range []string{
		template.HTMLEscapeString(derive.DCVPrefix + slugPlaceholder + "." + fixtureAnchor),
		template.HTMLEscapeString(relay.ServingProofPrefix + slugPlaceholder + "." + fixtureAnchor),
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the page does not describe the per-app record %q", want)
		}
	}
}

// A disclosure that silently omits a row is worse than no disclosure: the
// customer is told they have seen everything.
func TestPageShowsEveryRecordInThePlan(t *testing.T) {
	plan := lane2Plan(t, fixtureAnchor)
	html := renderedPage(t, plan, fixtureNonce)
	if len(plan.Items) == 0 {
		t.Fatal("the fixture plan has no records")
	}
	for _, item := range plan.Items {
		for _, want := range []string{item.Record.Name, item.Record.Value, item.Record.Type, item.Explain} {
			if !strings.Contains(html, template.HTMLEscapeString(want)) {
				t.Errorf("the page omits %q from the row for %q", want, item.Record.Name)
			}
		}
		if !strings.Contains(html, writerWord(item.Source)) {
			t.Errorf("the page does not say who writes %q", item.Record.Name)
		}
	}
}

// 🔴 THE ESCAPING IS THE CONTROL, AND IT MUST NOT DEPEND ON A VALIDATOR UPSTREAM.
//
// The plan below could never have come out of internal/derive — lane.ValidateDomain
// refuses that anchor several times over. It is fed in here on purpose: the day
// somebody reorders the checks in authorize, or adds a call site that builds a
// plan by hand, contextual escaping is the only thing left, and this test is what
// says it is enough on its own.
func TestPageEscapesEveryValueItRenders(t *testing.T) {
	const (
		hostileAnchor  = `evil"><script>alert('x')</script>.example.net`
		hostileValue   = `"><img src=x onerror=alert('x')>`
		hostileExplain = `deleting <this> breaks "everything" & more`
	)
	anchor := dnsplan.NormalizeName(hostileAnchor)
	plan := derive.Plan{
		Lane:   lane.OrgAppDomain,
		Anchor: anchor,
		Hosts:  []string{"*." + anchor},
		Items: []derive.Item{
			{
				Record:  dnsplan.Record{Type: "TXT", Name: proof.Prefix + anchor, Value: hostileValue},
				Purpose: derive.PurposeOwnership,
				Source:  derive.SourceCustomer,
				Explain: hostileExplain,
			},
			{
				Record:  dnsplan.Record{Type: "CNAME", Name: "*." + anchor, Value: hostileValue},
				Purpose: derive.PurposeRouting,
				Source:  derive.SourceDerived,
				Host:    "*." + anchor,
				Explain: hostileExplain,
			},
		},
	}
	html := renderedPage(t, plan, fixtureNonce)

	// Nothing hostile survives as markup. The list is markup rather than
	// substrings: `onerror=` and `src=x` are still in the output, as TEXT inside a
	// table cell, and asserting their absence would be asserting the wrong thing —
	// what makes them inert is that the `<` that would have opened a tag is a
	// `&lt;`. That is the property under test, so that is what is tested.
	lowered := strings.ToLower(html)
	for _, forbidden := range []string{"<script", "</script", "<img", "<iframe", "<svg", "<style", "<link"} {
		// <style> is in the page's own head, so count rather than forbid: one
		// occurrence is ours, a second came from a value.
		if want := strings.Count(strings.ToLower(pageMarkup), forbidden); strings.Count(lowered, forbidden) > want {
			t.Errorf("the page contains %q beyond the %d in its own markup", forbidden, want)
		}
	}
	for _, raw := range []string{hostileAnchor, hostileValue, hostileExplain, `alert('x')`, `"everything"`} {
		if strings.Contains(html, raw) {
			t.Errorf("the page contains the unescaped value %q", raw)
		}
	}
	// And every one of them is still SHOWN — escaped, not dropped. A page that
	// silently discarded a value it could not render safely would be a disclosure
	// missing exactly the row somebody needed to see.
	for _, shown := range []string{hostileAnchor, hostileValue, hostileExplain} {
		if !strings.Contains(html, template.HTMLEscapeString(shown)) {
			t.Errorf("the page dropped %q instead of escaping it", shown)
		}
	}
}

// 🔴 THE PAGE MAKES NO REQUEST, AND THAT IS CHECKABLE RATHER THAN CLAIMED. A
// consent screen that fetched a font while asking for consent would be answering
// the customer's question the wrong way, and the absence of `src` and `href`
// anywhere in the source is how a reader confirms it in one search.
func TestPageLoadsNothingAndPostsNowhere(t *testing.T) {
	html := strings.ToLower(renderedPage(t, lane2Plan(t, fixtureAnchor), fixtureNonce))
	for _, forbidden := range []string{
		"<script", "src=", "href=", "<form", "<iframe", "<link", "<img",
		"javascript:", "http://", "https://", "@import", "url(", "onclick", "onload",
	} {
		if strings.Contains(html, forbidden) {
			t.Errorf("the page contains %q; it must load nothing and post nowhere", forbidden)
		}
	}
}

// Two renders of one registration must be the same bytes. A page that differed
// between the screen a customer read and the screen a support engineer reads
// back would make the acknowledgement unauditable.
func TestPageIsDeterministic(t *testing.T) {
	plan := lane2Plan(t, fixtureAnchor)
	first := renderedPage(t, plan, fixtureNonce)
	for i := 0; i < 4; i++ {
		if again := renderedPage(t, plan, fixtureNonce); again != first {
			t.Fatal("two renders of one plan produced different pages")
		}
	}
}

// 🔴 EVERY PAGE THIS FUNCTION SERVES CAN BE ACKNOWLEDGED. Page validates the
// reference through Token's own validator, so the two can never disagree about
// what a usable (reference, anchor) pair is — a page nobody can acknowledge is a
// dead end a customer reaches after reading the whole thing.
func TestEveryPageServedCanBeAcknowledged(t *testing.T) {
	sealer := testsupport.SealerFrom(t, testsupport.GoldenKeyset(t))
	plan := lane2Plan(t, fixtureAnchor)
	for _, nonce := range []string{
		fixtureNonce,
		"a",
		strings.Repeat("a", maxNonce),
		"  " + fixtureNonce + "  ",
	} {
		html, err := Page(plan, nonce)
		if err != nil {
			t.Errorf("Page refused the reference %q: %v", nonce, err)
			continue
		}
		token, err := Token(sealer, nonce, plan.Anchor)
		if err != nil {
			t.Errorf("Page served a reference %q that Token refuses: %v", nonce, err)
			continue
		}
		if !Verify(sealer, nonce, plan.Anchor, token) {
			t.Errorf("the acknowledgement for reference %q does not verify", nonce)
		}
		if !strings.Contains(html, template.HTMLEscapeString(strings.TrimSpace(nonce))) {
			t.Errorf("the page for reference %q does not print it", nonce)
		}
	}
	// And the refusals agree in the other direction too.
	for _, nonce := range []string{"", "   ", "abc\x00def", strings.Repeat("a", maxNonce+1)} {
		if _, err := Page(plan, nonce); !errors.Is(err, ErrConsent) {
			t.Errorf("Page accepted the reference %q that Token refuses", nonce)
		}
		if _, err := Token(sealer, nonce, plan.Anchor); !errors.Is(err, ErrConsent) {
			t.Errorf("Token accepted the reference %q that Page refuses", nonce)
		}
	}
}

func TestPageRefusesEveryLaneButTheWildcardOne(t *testing.T) {
	for _, l := range []lane.Lane{lane.OrgPlatformDomain, lane.AppDomain} {
		plan, err := derivefixture.Config().Registration(l, fixtureIdentity, "example.com", fixtureProof)
		if err != nil {
			t.Fatal(err)
		}
		html, err := Page(plan, fixtureNonce)
		if !errors.Is(err, ErrConsent) {
			t.Errorf("Page for lane %q = %v, want ErrConsent", l, err)
		}
		if html != "" {
			t.Errorf("Page for lane %q returned a page alongside its refusal", l)
		}
	}
}

// A bind plan is derived per app at deploy time and is not a plan anybody
// authorizes. It reaches this refusal twice over — no wildcard and no ownership
// proof — and either one alone would be enough.
func TestPageRefusesAPerAppBindPlan(t *testing.T) {
	plan, err := derivefixture.Config().BindApp(fixtureAnchor, "blog")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Lane != lane.OrgAppDomain {
		t.Fatalf("the fixture is not a lane-2 plan: %q", plan.Lane)
	}
	if _, err := Page(plan, fixtureNonce); !errors.Is(err, ErrConsent) {
		t.Fatalf("Page accepted a per-app bind plan: %v", err)
	}
}

// 🔴 BOTH SENTINELS. A caller keeps one answer, and an operator grepping this
// service for every containment failure it has ever refused finds this one too.
func TestPageRefusesAPlanThatEscapesItsAnchor(t *testing.T) {
	plan := lane2Plan(t, fixtureAnchor)
	plan.Items = append(plan.Items, derive.Item{
		Record:  dnsplan.Record{Type: "CNAME", Name: "www.example.org", Value: "elsewhere.example"},
		Purpose: derive.PurposeCertDCV,
		Source:  derive.SourceDerived,
		Host:    "www.example.org",
		Explain: "a record in somebody else's zone",
	})
	_, err := Page(plan, fixtureNonce)
	if !errors.Is(err, ErrConsent) {
		t.Errorf("error = %v, want ErrConsent", err)
	}
	if !errors.Is(err, dnsplan.ErrAnchorEscape) {
		t.Errorf("error = %v, want it to wrap dnsplan.ErrAnchorEscape", err)
	}
}

func TestPageRefusesRowsItCannotHonestlyShow(t *testing.T) {
	ownership := func() derive.Item {
		return derive.Item{
			Record:  dnsplan.Record{Type: "TXT", Name: proof.Prefix + fixtureAnchor, Value: fixtureProof},
			Purpose: derive.PurposeOwnership,
			Source:  derive.SourceCustomer,
			Explain: "proves you control the domain",
		}
	}
	routing := func() derive.Item {
		return derive.Item{
			Record:  dnsplan.Record{Type: "CNAME", Name: "*." + fixtureAnchor, Value: "connect.mirrorstack.app"},
			Purpose: derive.PurposeRouting,
			Source:  derive.SourceDerived,
			Host:    "*." + fixtureAnchor,
			Explain: "routes every app you deploy",
		}
	}
	mutate := func(f func(items []derive.Item) []derive.Item) derive.Plan {
		items := f([]derive.Item{ownership(), routing()})
		return derive.Plan{
			Lane: lane.OrgAppDomain, Anchor: fixtureAnchor,
			Hosts: []string{"*." + fixtureAnchor}, Items: items,
		}
	}
	crowd := make([]derive.Item, 0, dnsplan.MaxRecords+1)
	for i := 0; i <= dnsplan.MaxRecords; i++ {
		crowd = append(crowd, ownership())
	}

	for _, tc := range []struct {
		name string
		plan derive.Plan
	}{
		{"no records at all", mutate(func([]derive.Item) []derive.Item { return nil })},
		{"more records than the publish boundary accepts", mutate(func([]derive.Item) []derive.Item { return crowd })},
		{"no ownership proof to name as the stop control", mutate(func(i []derive.Item) []derive.Item { return i[1:] })},
		{"no wildcard, so no standing grant to describe", mutate(func(i []derive.Item) []derive.Item { return i[:1] })},
		{"two ownership proofs", mutate(func(i []derive.Item) []derive.Item { return append(i, ownership()) })},
		{"two routing records", mutate(func(i []derive.Item) []derive.Item { return append(i, routing()) })},
		{"an ownership proof this service would publish", mutate(func(i []derive.Item) []derive.Item {
			i[0].Source = derive.SourceDerived
			return i
		})},
		{"a wildcard the customer publishes", mutate(func(i []derive.Item) []derive.Item {
			i[1].Source = derive.SourceCustomer
			return i
		})},
		{"a routing record that is not the wildcard", mutate(func(i []derive.Item) []derive.Item {
			i[1].Record.Name = "apps." + fixtureAnchor
			i[1].Host = "apps." + fixtureAnchor
			return i
		})},
		{"a wildcard at another anchor", mutate(func(i []derive.Item) []derive.Item {
			i[1].Record.Name = "*.example.org"
			return i
		})},
		{"a record type outside the vocabulary", mutate(func(i []derive.Item) []derive.Item {
			i[1].Record.Type = "A"
			i[1].Record.Value = "192.0.2.1"
			return i
		})},
		{"a proxied record", mutate(func(i []derive.Item) []derive.Item {
			i[1].Record.Proxied = true
			return i
		})},
		{"a record with no value", mutate(func(i []derive.Item) []derive.Item {
			i[0].Record.Value = ""
			return i
		})},
		{"a record with no name", mutate(func(i []derive.Item) []derive.Item {
			i[0].Record.Name = ""
			return i
		})},
		{"a row with no explanation", mutate(func(i []derive.Item) []derive.Item {
			i[0].Explain = ""
			return i
		})},
		{"a row with no source", mutate(func(i []derive.Item) []derive.Item {
			i[1].Source = ""
			return i
		})},
		{"a row with no purpose", mutate(func(i []derive.Item) []derive.Item {
			i[1].Purpose = ""
			return i
		})},
		{"no anchor", mutate(func(i []derive.Item) []derive.Item { return i })},
	} {
		plan := tc.plan
		if tc.name == "no anchor" {
			plan.Anchor = ""
		}
		html, err := Page(plan, fixtureNonce)
		if !errors.Is(err, ErrConsent) {
			t.Errorf("%s: error = %v, want ErrConsent", tc.name, err)
		}
		if html != "" {
			t.Errorf("%s: a page came back alongside the refusal", tc.name)
		}
	}

	// The same two items, unmutated, must render — otherwise every row above
	// proves only that the fixture is broken.
	if _, err := Page(mutate(func(i []derive.Item) []derive.Item { return i }), fixtureNonce); err != nil {
		t.Fatalf("the unmutated fixture does not render: %v", err)
	}
}

// The whole point of the page is that a customer can read it. This is not a
// styling assertion — it checks the document is complete, since a template that
// stopped rendering halfway would still return a string.
func TestPageIsAWholeDocument(t *testing.T) {
	html := renderedPage(t, lane2Plan(t, fixtureAnchor), fixtureNonce)
	if !strings.HasPrefix(html, "<!doctype html>") {
		t.Error("the page does not start with a doctype")
	}
	if !strings.HasSuffix(strings.TrimSpace(html), "</html>") {
		t.Error("the page does not end with </html>")
	}
	for _, section := range []string{
		"Why this screen is not part of the console",
		"The grant is standing",
		"What the credential can reach",
		"What lands in your zone now",
		"What you can stop, and how",
		"What we have not solved",
	} {
		if !strings.Contains(html, section) {
			t.Errorf("the page is missing the section %q", section)
		}
	}
}

// "Nobody" is never the true answer to "who put this record in my zone", so the
// column must not be able to render blank. A derive.Source added later renders
// as itself — visibly unfamiliar to whoever is reading their own zone — rather
// than as an empty cell that reads as if no one wrote the row.
func TestTheWriterColumnIsNeverBlank(t *testing.T) {
	for source, want := range map[derive.Source]string{
		derive.SourceCustomer:  "you, by hand",
		derive.SourceDerived:   "MirrorStack",
		derive.SourceRelayed:   "MirrorStack, relayed from AWS or Cloudflare",
		derive.Source("later"): "later",
	} {
		if got := writerWord(source); got != want {
			t.Errorf("writerWord(%q) = %q, want %q", source, got, want)
		}
		if writerWord(source) == "" {
			t.Errorf("writerWord(%q) is blank", source)
		}
	}
	// A relayed row reaches the page for real: internal/relay's records are
	// merged into a plan before it is published, so the page has to be able to
	// show one that internal/derive never constructed.
	plan := lane2Plan(t, fixtureAnchor)
	plan.Items = append(plan.Items, derive.Item{
		Record: dnsplan.Record{
			Type:  "TXT",
			Name:  relay.ServingProofPrefix + "blog." + fixtureAnchor,
			Value: "a proof Cloudflare minted",
		},
		Purpose: derive.PurposeServing,
		Source:  derive.SourceRelayed,
		Host:    "blog." + fixtureAnchor,
		Explain: "Cloudflare asks for this before it will serve the hostname.",
	})
	html := renderedPage(t, plan, fixtureNonce)
	if !strings.Contains(html, writerWord(derive.SourceRelayed)) {
		t.Error("the page does not say who writes a relayed record")
	}
}

// A refusal is somewhere a value gets copied, logged, and copied again, so what
// it quotes back at the caller is bounded — the same rule lane and derive apply
// to theirs.
func TestARefusalDoesNotQuoteBackAnUnboundedValue(t *testing.T) {
	plan := lane2Plan(t, fixtureAnchor)
	if len(plan.Items) != 2 {
		t.Fatalf("the fixture plan holds %d records, want 2", len(plan.Items))
	}
	long := strings.Repeat("a", 200) + "." + fixtureAnchor
	plan.Items[1].Record.Name = long
	plan.Items[1].Host = long
	_, err := Page(plan, fixtureNonce)
	if !errors.Is(err, ErrConsent) {
		t.Fatalf("error = %v, want ErrConsent", err)
	}
	if strings.Contains(err.Error(), long) {
		t.Error("the refusal quotes the whole value back")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("the refusal does not say it truncated: %v", err)
	}
}
