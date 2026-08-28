package proof

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/grantcrypto"
)

const (
	laneOrgPlatform = lane.OrgPlatformDomain
	laneOrgApp      = lane.OrgAppDomain
	laneApp         = lane.AppDomain
)

const (
	fixtureIdentity = "11111111-2222-3333-4444-555555555555"
	fixtureAnchor   = "example.com"
)

// goldenKeyset is 32 bytes 0x00…0x1f under one key id. Written out rather than
// randomized so a reader can regenerate every vector in this file with any
// HKDF/HMAC tool and check for themselves that the value we ask a customer to
// publish is the value this code computes.
func goldenKeyset(t *testing.T) string {
	t.Helper()
	raw := make([]byte, grantcrypto.KeySize)
	for i := range raw {
		raw[i] = byte(i)
	}
	return `{"active":"golden","keys":{"golden":"` + base64.StdEncoding.EncodeToString(raw) + `"}}`
}

// keysetOf builds a keyset whose material is derived from each key id, never
// from its position — so a rotation fixture can reorder the ids and the only
// thing that moves is which key is active.
func keysetOf(t *testing.T, ids ...string) string {
	t.Helper()
	encoded := make([]string, 0, len(ids))
	for _, id := range ids {
		raw := make([]byte, grantcrypto.KeySize)
		for j := range raw {
			raw[j] = id[j%len(id)] ^ byte(j)
		}
		encoded = append(encoded, `"`+id+`":"`+base64.StdEncoding.EncodeToString(raw)+`"`)
	}
	return `{"active":"` + ids[0] + `","keys":{` + strings.Join(encoded, ",") + `}}`
}

func proverFrom(t *testing.T, keyset string) Prover {
	t.Helper()
	keys, err := grantcrypto.ParseKeyset(keyset)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := grantcrypto.NewSealer(keys)
	if err != nil {
		t.Fatal(err)
	}
	return Prover{Sealer: sealer}
}

func expected(t *testing.T, p Prover, l lane.Lane, identity, anchor string) string {
	t.Helper()
	value, err := p.Expected(l, identity, anchor)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// 🔴 A LANE'S WIRE STRING IS PART OF EVERY PROOF PUBLISHED UNDER IT. Renaming
// the Go constant is free; changing its VALUE re-mints every proof on that lane
// and strands every customer already serving on it. The two are easy to confuse
// in one edit, so the bytes are pinned here, next to the vector that depends on
// them, rather than only where they are declared.
func TestTheLaneWireStringsArePinned(t *testing.T) {
	for want, got := range map[string]lane.Lane{
		"org_platform_domain": laneOrgPlatform,
		"org_app_domain":      laneOrgApp,
		"app_domain":          laneApp,
	} {
		if string(got) != want {
			t.Fatalf("a lane's wire string moved to %q, want %q", got, want)
		}
	}
}

// 🔴 THE PROOF VALUE IS A CUSTOMER-FACING CONSTANT. It is published in somebody
// else's zone, by hand, and it is re-checked on every pass for as long as the
// domain lives. Change the message format, the HKDF info, the derivation or the
// encoding and every one of those records silently stops matching: the customer
// sees a correct-looking TXT in their panel and a domain that no longer
// advances, with nothing anywhere to tell them why.
//
// This vector is what makes that change cost a failing build instead of a
// support queue. If it fails, the question is not "what is the new constant" —
// it is whether you meant to invalidate every proof in production, and if you
// did, what tells the affected customers to republish.
//
// It is reproducible without Go, on purpose — the derivation is not something
// you have to take this repository's word for:
//
//	key     = 0x00 0x01 … 0x1f                       (32 bytes)
//	subkey  = HKDF-SHA256(ikm=key, salt="",
//	          info="github.com/mirrorstack-ai/dns-delegate-engine/internal/proof:ownership/v1",
//	          len=32)
//	message = "ms-dns-ownership/v1\x00org_platform_domain\x00"
//	          "11111111-2222-3333-4444-555555555555\x00example.com"
//	value   = "msv1-" + lower(base32(HMAC-SHA256(subkey, message)), no padding)
func TestGoldenValue(t *testing.T) {
	const want = "msv1-ts3k2xmx2nzeqtcijntm324m4zf24epx7lyvgqnxs3acbxqymesq"

	got := expected(t, proverFrom(t, goldenKeyset(t)), laneOrgPlatform, fixtureIdentity, fixtureAnchor)
	if got != want {
		t.Fatalf("golden proof value = %q, want %q", got, want)
	}
}

// 🔴 THE LANE IS INSIDE THE MAC. A console proof does not authorize an
// app-domain wildcard, and neither authorizes a domain on a single app. If these
// three collapsed to one value, a customer who proved `example.com` to put their
// console on it would have simultaneously proved it for `*.example.com` — every
// name under their domain, including the ones they have not thought of.
func TestTheLaneChangesTheValue(t *testing.T) {
	p := proverFrom(t, goldenKeyset(t))
	seen := map[string]lane.Lane{}
	for _, l := range []lane.Lane{laneOrgPlatform, laneOrgApp, laneApp} {
		value := expected(t, p, l, fixtureIdentity, fixtureAnchor)
		if other, ok := seen[value]; ok {
			t.Fatalf("lanes %q and %q share one proof value", other, l)
		}
		seen[value] = l
	}
}

// Two orgs connecting the same domain must not be able to publish each other's
// proof — otherwise the first to register hands the second a working claim.
func TestTheIdentityChangesTheValue(t *testing.T) {
	p := proverFrom(t, goldenKeyset(t))
	one := expected(t, p, laneOrgPlatform, fixtureIdentity, fixtureAnchor)
	two := expected(t, p, laneOrgPlatform, "99999999-8888-7777-6666-555555555555", fixtureAnchor)
	if one == two {
		t.Fatal("two identities share one proof value")
	}
}

// A proof published at one domain must not satisfy another. Without the anchor
// in the MAC, one record in a zone the customer does control would prove every
// domain they ever register.
func TestTheAnchorChangesTheValue(t *testing.T) {
	p := proverFrom(t, goldenKeyset(t))
	one := expected(t, p, laneOrgPlatform, fixtureIdentity, fixtureAnchor)
	two := expected(t, p, laneOrgPlatform, fixtureIdentity, "example.net")
	if one == two {
		t.Fatal("two anchors share one proof value")
	}
}

// The value lives in somebody else's zone for months. A call site that spells
// the anchor with a trailing root dot, or the id in upper case, must not mint a
// second proof and silently invalidate the record already published.
func TestSpellingDoesNotChangeTheValue(t *testing.T) {
	p := proverFrom(t, goldenKeyset(t))
	want := expected(t, p, laneOrgPlatform, fixtureIdentity, fixtureAnchor)
	for _, variant := range []struct{ identity, anchor string }{
		{fixtureIdentity, "EXAMPLE.COM"},
		{fixtureIdentity, "example.com."},
		{fixtureIdentity, "  example.com  "},
		{strings.ToUpper(fixtureIdentity), fixtureAnchor},
	} {
		if got := expected(t, p, laneOrgPlatform, variant.identity, variant.anchor); got != want {
			t.Fatalf("identity %q anchor %q produced %q, want %q",
				variant.identity, variant.anchor, got, want)
		}
	}
}

// Accepted is what a verifier walks; Expected is what we hand out. The second
// must always be in the first, or we would be telling customers to publish a
// value we then refuse.
func TestAcceptedContainsExpected(t *testing.T) {
	p := proverFrom(t, goldenKeyset(t))
	want := expected(t, p, laneOrgPlatform, fixtureIdentity, fixtureAnchor)
	accepted, err := p.Accepted(laneOrgPlatform, fixtureIdentity, fixtureAnchor)
	if err != nil {
		t.Fatal(err)
	}
	if len(accepted) != 1 {
		t.Fatalf("a one-key keyset accepted %d values", len(accepted))
	}
	if accepted[0] != want {
		t.Fatalf("accepted %q, hand out %q", accepted[0], want)
	}
}

// 🔴 ROTATION MUST NOT BREAK A PUBLISHED PROOF. A customer who published the
// value we gave them yesterday must still verify today, under a key they never
// saw. One accepted value per key is what buys that; the day the set is one
// entry wide again, every proof published under the retired key is dead and
// those customers have to edit their own zone before their domain advances.
func TestRotationKeepsAPublishedProofValid(t *testing.T) {
	before := proverFrom(t, keysetOf(t, "k1", "k2"))
	published := expected(t, before, laneOrgApp, fixtureIdentity, "example.net")

	after := proverFrom(t, keysetOf(t, "k2", "k1")) // same material, k2 now active
	if handedOutNow := expected(t, after, laneOrgApp, fixtureIdentity, "example.net"); handedOutNow == published {
		t.Fatal("the value handed out did not move when the active key did")
	}
	accepted, err := after.Accepted(laneOrgApp, fixtureIdentity, "example.net")
	if err != nil {
		t.Fatal(err)
	}
	if len(accepted) != 2 {
		t.Fatalf("a two-key keyset accepted %d values, want 2", len(accepted))
	}
	found := false
	for _, value := range accepted {
		if value == published {
			found = true
		}
	}
	if !found {
		t.Fatal("a proof published before the rotation is no longer accepted")
	}
}

// Accepted must be deterministic: it is rendered into logs and support answers,
// and a set that reordered itself between two calls would make two identical
// registrations look different.
func TestAcceptedIsDeterministic(t *testing.T) {
	p := proverFrom(t, keysetOf(t, "kb", "ka", "kc"))
	first, err := p.Accepted(laneApp, fixtureIdentity, "app.example.org")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 16; i++ {
		again, err := p.Accepted(laneApp, fixtureIdentity, "app.example.org")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(again, ",") != strings.Join(first, ",") {
			t.Fatalf("call %d returned a different accepted set", i)
		}
	}
}

func TestRecordIsTheOwnershipTXT(t *testing.T) {
	p := proverFrom(t, goldenKeyset(t))
	record, err := p.Record(laneOrgPlatform, fixtureIdentity, fixtureAnchor)
	if err != nil {
		t.Fatal(err)
	}
	if record.Name != "_mirrorstack-challenge."+fixtureAnchor {
		t.Fatalf("record name = %q", record.Name)
	}
	if record.Type != "TXT" {
		t.Fatalf("record type = %q", record.Type)
	}
	if record.Value != expected(t, p, laneOrgPlatform, fixtureIdentity, fixtureAnchor) {
		t.Fatalf("record value = %q, does not match Expected", record.Value)
	}
	if record.Proxied {
		t.Fatal("the ownership record is proxied")
	}
}

// 🔴 A NAME THAT CANNOT BE RIGHT MUST NOT BE HALF-RIGHT. `Prefix + ""` is a name
// at the zone apex, and a caller that handed it to a provider would create a
// record there. Only the empty answer fails loudly.
func TestNameFailsClosed(t *testing.T) {
	for name, anchor := range map[string]string{
		"empty":      "",
		"whitespace": "   ",
		"root dot":   ".",
		"too long":   strings.Repeat("a.", 120) + "example.com",
	} {
		if got := Name(anchor); got != "" {
			t.Fatalf("%s: Name(%q) = %q, want the empty refusal", name, anchor, got)
		}
	}
	if got := Name(" EXAMPLE.com. "); got != "_mirrorstack-challenge.example.com" {
		t.Fatalf("Name did not normalize its anchor: %q", got)
	}
	// Record refuses what Name refuses, rather than publishing a bare prefix.
	// The long anchor is the case worth having: it is a legal anchor, so the MAC
	// is computed fine and only the derived NAME is out of bounds.
	p := proverFrom(t, goldenKeyset(t))
	for name, anchor := range map[string]string{
		"empty":    "",
		"too long": strings.Repeat("a.", 120) + "example.com",
	} {
		if _, err := p.Record(laneOrgPlatform, fixtureIdentity, anchor); err == nil {
			t.Fatalf("%s: Record produced a row with no usable name", name)
		}
	}
}

// 🔴 THE SEPARATOR MAY NOT APPEAR IN A COMPONENT, or the concatenation stops
// being injective: (lane, "x\x00example.com", "") and (lane, "x", "example.com")
// would be the same bytes, and one proof would authorize two registrations.
func TestExpectedRefusesInputItCannotEncode(t *testing.T) {
	p := proverFrom(t, goldenKeyset(t))
	for name, input := range map[string]struct {
		lane             lane.Lane
		identity, anchor string
	}{
		"empty lane":        {"", fixtureIdentity, fixtureAnchor},
		"empty identity":    {laneOrgPlatform, "", fixtureAnchor},
		"empty anchor":      {laneOrgPlatform, fixtureIdentity, ""},
		"blank identity":    {laneOrgPlatform, "   ", fixtureAnchor},
		"separator in lane": {lane.Lane("org\x00app"), fixtureIdentity, fixtureAnchor},
		"separator in id":   {laneOrgPlatform, "x\x00example.com", ""},
		"separator in anchor": {
			laneOrgPlatform, fixtureIdentity, "example.com\x00extra",
		},
	} {
		if _, err := p.Expected(input.lane, input.identity, input.anchor); err == nil {
			t.Fatalf("%s: Expected produced a proof", name)
		}
		if _, err := p.Accepted(input.lane, input.identity, input.anchor); err == nil {
			t.Fatalf("%s: Accepted produced a set", name)
		}
	}
}

// 🔴 A PROVER WITH NO KEYSET MUST REFUSE, NOT COMPUTE. A proof derived from an
// absent key is one constant, identical for every customer of the deployment —
// which any of them could then publish at any anchor.
func TestZeroProverFailsClosed(t *testing.T) {
	var p Prover
	if _, err := p.Expected(laneOrgPlatform, fixtureIdentity, fixtureAnchor); err == nil {
		t.Fatal("a Prover with no sealer produced a proof")
	}
	if _, err := p.Accepted(laneOrgPlatform, fixtureIdentity, fixtureAnchor); err == nil {
		t.Fatal("a Prover with no sealer produced an accepted set")
	}
	if _, err := p.Record(laneOrgPlatform, fixtureIdentity, fixtureAnchor); err == nil {
		t.Fatal("a Prover with no sealer produced a record")
	}
	if ok, err := p.Matches(laneOrgPlatform, fixtureIdentity, fixtureAnchor, []string{"anything"}); ok || err == nil {
		t.Fatal("a Prover with no sealer matched a value")
	}
}

// The value is typed into somebody else's web form and read back out of public
// DNS. It has to fit one TXT character-string and contain nothing a zone file's
// quoting, or a form that trims and splits on whitespace, can mangle.
func TestValueSurvivesADNSControlPanel(t *testing.T) {
	value := expected(t, proverFrom(t, goldenKeyset(t)), laneOrgPlatform, fixtureIdentity, fixtureAnchor)
	if len(value) >= 255 {
		t.Fatalf("value is %d bytes: one TXT character-string holds 255", len(value))
	}
	if !strings.HasPrefix(value, "msv1-") {
		t.Fatalf("value is not self-identifying: %q", value)
	}
	for _, c := range value[len("msv1-"):] {
		if (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7') {
			continue
		}
		t.Fatalf("value contains %q, which is outside lowercase base32: %q", c, value)
	}
}

// A panel that echoes the value back upper-cased or wrapped in the zone file's
// quotes must still verify — that tolerance is the entire reason the encoding is
// case-insensitive base32 rather than base64.
func TestMatchesFoldsWhatAPanelDoesToAValue(t *testing.T) {
	p := proverFrom(t, goldenKeyset(t))
	value := expected(t, p, laneOrgPlatform, fixtureIdentity, fixtureAnchor)

	for name, observed := range map[string][]string{
		"as issued":       {value},
		"upper cased":     {strings.ToUpper(value)},
		"quoted":          {`"` + value + `"`},
		"padded":          {"  " + value + "  "},
		"among strangers": {"v=spf1 -all", "", "google-site-verification=x", value},
	} {
		ok, err := p.Matches(laneOrgPlatform, fixtureIdentity, fixtureAnchor, observed)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !ok {
			t.Fatalf("%s: a published proof was not matched", name)
		}
	}

	// And it is still a proof: another lane's value, another org's value, and a
	// near miss are all refused.
	for name, observed := range map[string][]string{
		"empty":        nil,
		"empty string": {""},
		"unrelated":    {"v=spf1 -all"},
		"truncated":    {value[:len(value)-1]},
		"other lane":   {expected(t, p, laneOrgApp, fixtureIdentity, fixtureAnchor)},
		"other org":    {expected(t, p, laneOrgPlatform, "99999999-8888-7777-6666-555555555555", fixtureAnchor)},
		"other domain": {expected(t, p, laneOrgPlatform, fixtureIdentity, "example.net")},
	} {
		ok, err := p.Matches(laneOrgPlatform, fixtureIdentity, fixtureAnchor, observed)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if ok {
			t.Fatalf("%s: accepted a value that is not this registration's proof", name)
		}
	}
}
