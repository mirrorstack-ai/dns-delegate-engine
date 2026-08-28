package sealed

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/grantcrypto"
)

// The fixtures. Every one of them is a documentation domain (RFC 2606) or a
// synthetic uuid: no test in this repository may name a real customer, reach a
// network, open a database, or need a Cloudflare account.
const (
	testAnchor    = "example.com"
	testIdentity  = "3f2b7c1e-9d4a-4f6b-8c2d-1a5e7b9d0c34"
	otherIdentity = "b41d9e02-6c53-4a1f-9b7e-2d8c4f6a0e15"
	testIssuedAt  = int64(1756000000)
	testNonce     = "00112233445566778899aabbccddeeff"
	testReference = "ffeeddccbbaa99887766554433221100"
	testKeyID     = "test-k1"
)

// laneWireValues are the three lanes spelled the way they actually land inside
// an envelope, which is the spelling docs/DESIGN.md §4 pins.
//
// Fixtures name a lane by its WIRE value rather than by the Go constant on
// purpose. Renaming a constant is a refactor; changing one of these strings
// strands every stored registration in production, and this is the file where
// that has to show up as a failure.
var laneWireValues = []string{"org_platform_domain", "org_app_domain", "app_domain"}

func testSealer(t *testing.T) *grantcrypto.Sealer {
	t.Helper()
	key := make([]byte, grantcrypto.KeySize)
	for i := range key {
		key[i] = byte(i*7 + 1)
	}
	// The same JSON shape the deployed secret has, built inline: a keyset
	// fixture that reads a file or a secret store is a test that can fail for a
	// reason that has nothing to do with sealing.
	raw := fmt.Sprintf(`{"active":%q,"keys":{%q:%q}}`,
		testKeyID, testKeyID, base64.StdEncoding.EncodeToString(key))
	keys, err := grantcrypto.ParseKeyset(raw)
	if err != nil {
		t.Fatalf("parse test keyset: %v", err)
	}
	sealer, err := grantcrypto.NewSealer(keys)
	if err != nil {
		t.Fatalf("new test sealer: %v", err)
	}
	return sealer
}

func wireLane(t *testing.T, wire string) lane.Lane {
	t.Helper()
	parsed, err := lane.Parse(wire)
	if err != nil {
		t.Fatalf("lane %q does not parse: %v", wire, err)
	}
	return parsed
}

func testRegistration(t *testing.T, wire string) Registration {
	t.Helper()
	return Registration{
		Version:  Version,
		Lane:     wireLane(t, wire),
		Identity: testIdentity,
		Anchor:   testAnchor,
		IssuedAt: testIssuedAt,
	}
}

func testAuthState(t *testing.T, wire string) AuthState {
	t.Helper()
	return AuthState{
		Version:  Version,
		Lane:     wireLane(t, wire),
		Identity: testIdentity,
		Anchor:   testAnchor,
		Nonce:    testNonce,
		IssuedAt: time.Now().Unix(),
	}
}

func TestRegistrationRoundTripsOnEveryLane(t *testing.T) {
	sealer := testSealer(t)
	for _, wire := range laneWireValues {
		t.Run(wire, func(t *testing.T) {
			want := testRegistration(t, wire)
			// The consent reference rides along on the lane that has a page, and
			// it is the value an acknowledgement is a MAC over — a round trip
			// that dropped it would leave every wildcard authorization refusing
			// a token the customer genuinely gave.
			if wire == "org_app_domain" {
				want.ConsentNonce = testReference
			}
			envelope, keyID, err := SealRegistration(sealer, want)
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			if keyID != testKeyID {
				// The private half stores this beside the ciphertext; without
				// it a retired key can never be proven unused.
				t.Fatalf("key id = %q, want %q", keyID, testKeyID)
			}
			got, err := OpenRegistration(sealer, envelope)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if got != want {
				t.Fatalf("round trip = %+v, want %+v", got, want)
			}
		})
	}
}

func TestAuthStateRoundTripsAndCarriesTheAcknowledgement(t *testing.T) {
	sealer := testSealer(t)
	for _, acknowledged := range []bool{false, true} {
		t.Run(fmt.Sprintf("consentAck=%v", acknowledged), func(t *testing.T) {
			want := testAuthState(t, "org_app_domain")
			want.ConsentAck = acknowledged
			envelope, err := SealAuthState(sealer, want)
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			got, err := OpenAuthState(sealer, envelope)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if got != want {
				t.Fatalf("round trip = %+v, want %+v", got, want)
			}
			// The bit is the whole reason the wildcard lane has a consent page.
			// It surviving the seal is what makes it un-addable afterwards.
			if got.ConsentAck != acknowledged {
				t.Fatalf("consentAck = %v, want %v", got.ConsentAck, acknowledged)
			}
		})
	}
}

// 🔴 THE TWO ENVELOPE TYPES ARE NOT INTERCHANGEABLE, AND THIS IS THE TEST THAT
// SAYS SO.
//
// Both plaintexts carry a lane, an identity and an anchor under the same keys,
// so every field check they share would pass on the wrong one. Only the AAD
// separates them. If a registration ever opened as an auth state, the ten
// minute window would be bypassed by an envelope that never had one — and if a
// state ever opened as a registration, a ten-minute value would become the
// permanent identity of a customer's domain.
func TestOneEnvelopeTypeCannotBePresentedAsTheOther(t *testing.T) {
	sealer := testSealer(t)

	registration, _, err := SealRegistration(sealer, testRegistration(t, "org_platform_domain"))
	if err != nil {
		t.Fatalf("seal registration: %v", err)
	}
	state, err := SealAuthState(sealer, testAuthState(t, "org_platform_domain"))
	if err != nil {
		t.Fatalf("seal auth state: %v", err)
	}

	if _, err := OpenAuthState(sealer, registration); err == nil {
		t.Fatal("a registration opened as an auth state")
	} else if !errors.Is(err, ErrInvalidEnvelope) || !errors.Is(err, grantcrypto.ErrMalformed) {
		// It must fail at the AEAD, not at a field check further in. A field
		// check is a rule someone can relax; the AAD is arithmetic.
		t.Fatalf("registration-as-state failed for the wrong reason: %v", err)
	}

	if _, err := OpenRegistration(sealer, state); err == nil {
		t.Fatal("an auth state opened as a registration")
	} else if !errors.Is(err, ErrInvalidEnvelope) || !errors.Is(err, grantcrypto.ErrMalformed) {
		t.Fatalf("state-as-registration failed for the wrong reason: %v", err)
	}
}

// The window is bounded in both directions: behind because that is the window,
// ahead because a forward-dated envelope lives as long as its date is wrong and
// the date is sealed where no later check can reach it.
func TestOpenAuthStateEnforcesItsWindow(t *testing.T) {
	sealer := testSealer(t)
	now := time.Now()
	for _, tc := range []struct {
		name     string
		issuedAt time.Time
		expired  bool
	}{
		{"fresh", now, false},
		{"just inside the window", now.Add(-AuthStateTTL + time.Minute), false},
		{"one tick past the window", now.Add(-AuthStateTTL - time.Minute), true},
		{"long expired", now.Add(-30 * 24 * time.Hour), true},
		{"a clock skew ahead is tolerated", now.Add(time.Minute), false},
		{"far in the future is not", now.Add(AuthStateTTL + time.Minute), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := testAuthState(t, "app_domain")
			state.IssuedAt = tc.issuedAt.Unix()
			envelope, err := SealAuthState(sealer, state)
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			_, err = OpenAuthState(sealer, envelope)
			switch {
			case tc.expired && !errors.Is(err, ErrExpired):
				t.Fatalf("want ErrExpired, got %v", err)
			case !tc.expired && err != nil:
				t.Fatalf("want the state accepted, got %v", err)
			}
		})
	}
}

// Flipping one bit of ciphertext must fail as authentication, not decode as
// something almost right. This is the property that lets a stateless service
// treat a value handed back by the private half as its own.
func TestATamperedCiphertextIsRefused(t *testing.T) {
	sealer := testSealer(t)
	envelope, _, err := SealRegistration(sealer, testRegistration(t, "org_platform_domain"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	parts := strings.Split(envelope, ".")
	if len(parts) != 4 {
		t.Fatalf("envelope has %d parts, want 4", len(parts))
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(ciphertext) == 0 {
		t.Fatalf("decode ciphertext: %v", err)
	}
	// Re-encoded properly, so the refusal comes from the GCM tag rather than
	// from a base64 parse that never reached the cipher.
	ciphertext[0] ^= 0x01
	parts[3] = base64.RawStdEncoding.EncodeToString(ciphertext)
	if _, err := OpenRegistration(sealer, strings.Join(parts, ".")); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("a tampered envelope opened: %v", err)
	}
}

func TestNewNonceIsFreshOnEveryCall(t *testing.T) {
	seen := make(map[string]struct{}, 64)
	for range 64 {
		nonce, err := NewNonce()
		if err != nil {
			t.Fatalf("nonce: %v", err)
		}
		if len(nonce) != 2*nonceBytes {
			t.Fatalf("nonce %q is %d chars, want %d", nonce, len(nonce), 2*nonceBytes)
		}
		if _, repeat := seen[nonce]; repeat {
			t.Fatalf("nonce %q repeated", nonce)
		}
		seen[nonce] = struct{}{}
	}
}

// Seal refuses exactly what Open refuses. An envelope that seals and cannot be
// opened fails days later, on the pass that needed it.
func TestSealRefusesEveryValueOpenWouldRefuse(t *testing.T) {
	sealer := testSealer(t)
	valid := testRegistration(t, "org_platform_domain")
	for _, tc := range []struct {
		name   string
		mutate func(*Registration)
	}{
		{"an unparseable lane", func(r *Registration) { r.Lane = lane.Lane("no_such_lane") }},
		{"an empty lane", func(r *Registration) { r.Lane = lane.Lane("") }},
		{"an identity that is not a uuid", func(r *Registration) { r.Identity = "not-a-uuid" }},
		{"an empty identity", func(r *Registration) { r.Identity = "" }},
		{"an empty anchor", func(r *Registration) { r.Anchor = "" }},
		{"an anchor past the DNS wire limit", func(r *Registration) {
			r.Anchor = strings.Repeat("a.", 140) + "example.com"
		}},
		{"no issue time", func(r *Registration) { r.IssuedAt = 0 }},
		{"a negative issue time", func(r *Registration) { r.IssuedAt = -1 }},
		// Absent is legitimate — two lanes have no consent page. Present and
		// malformed is not: it would be MACed into an acknowledgement over a
		// value this service never issued.
		{"a short consent reference", func(r *Registration) { r.ConsentNonce = "abcd" }},
		{"a consent reference that is not hex", func(r *Registration) {
			r.ConsentNonce = strings.Repeat("z", 2*nonceBytes)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			broken := valid
			tc.mutate(&broken)
			if _, _, err := SealRegistration(sealer, broken); !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("sealed %s: %v", tc.name, err)
			}
		})
	}

	validState := testAuthState(t, "org_app_domain")
	for _, tc := range []struct {
		name   string
		mutate func(*AuthState)
	}{
		{"no nonce", func(a *AuthState) { a.Nonce = "" }},
		{"a short nonce", func(a *AuthState) { a.Nonce = "abcd" }},
		{"a nonce that is not hex", func(a *AuthState) { a.Nonce = strings.Repeat("z", 2*nonceBytes) }},
		{"an unparseable lane", func(a *AuthState) { a.Lane = lane.Lane("no_such_lane") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			broken := validState
			tc.mutate(&broken)
			if _, err := SealAuthState(sealer, broken); !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("sealed %s: %v", tc.name, err)
			}
		})
	}
}

// 🔴 A STORED ENVELOPE IS UNTRUSTED INPUT EVEN AFTER IT DECRYPTS. These
// plaintexts are sealed by this keyset, so they decrypt perfectly. They must
// still be refused: an envelope written by an older build, under rules since
// tightened, arrives from a store this service does not own.
func TestOpenRefusesADecryptableEnvelopeThatNoLongerValidates(t *testing.T) {
	sealer := testSealer(t)
	for _, tc := range []struct {
		name      string
		plaintext string
	}{
		{"a version this build does not know", `{"version":2,"lane":"org_platform_domain","identity":"` + testIdentity + `","anchor":"example.com","issuedAt":1756000000}`},
		{"a lane that no longer exists", `{"version":1,"lane":"org_legacy_domain","identity":"` + testIdentity + `","anchor":"example.com","issuedAt":1756000000}`},
		{"an identity that is not a uuid", `{"version":1,"lane":"org_platform_domain","identity":"org-42","anchor":"example.com","issuedAt":1756000000}`},
		{"an anchor that is not normalized", `{"version":1,"lane":"org_platform_domain","identity":"` + testIdentity + `","anchor":"EXAMPLE.com.","issuedAt":1756000000}`},
		{"an identity that is not in its canonical spelling", `{"version":1,"lane":"org_platform_domain","identity":"` + strings.ToUpper(testIdentity) + `","anchor":"example.com","issuedAt":1756000000}`},
		// DESIGN §5: there is no stage, no cursor and no expiry anywhere in
		// this API. A field this build does not recognise is refused rather
		// than dropped, so adding one without bumping Version fails loudly.
		{"a field this build does not know", `{"version":1,"lane":"org_platform_domain","identity":"` + testIdentity + `","anchor":"example.com","issuedAt":1756000000,"stage":"published"}`},
		{"a malformed consent reference", `{"version":1,"lane":"org_app_domain","identity":"` + testIdentity + `","anchor":"example.com","consentNonce":"not-hex","issuedAt":1756000000}`},
		{"two values in one plaintext", `{"version":1,"lane":"org_platform_domain","identity":"` + testIdentity + `","anchor":"example.com","issuedAt":1756000000}{"version":1}`},
		{"not JSON at all", `example.com`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			envelope, _, err := sealer.Seal(tc.plaintext, registrationAAD)
			if err != nil {
				t.Fatalf("seal fixture: %v", err)
			}
			if _, err := OpenRegistration(sealer, envelope); !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("opened %s: %v", tc.name, err)
			}
		})
	}
}

// 🔴 THE SEALED PLAINTEXT IS A CROSS-BUILD CONTRACT, PINNED HERE.
//
// A registration outlives the build that sealed it: a domain connected today is
// advanced by whatever is deployed next month. A renamed tag, a reordered
// field, or a lane whose wire spelling moved strands every stored envelope at
// once, and the symptom in production is every customer domain refusing to
// advance. This test is where that becomes a build failure instead.
//
// If it fails, do not regenerate the constant. Bump Version deliberately and
// accept that every in-flight registration is invalidated.
func TestGoldenEnvelopePlaintext(t *testing.T) {
	sealer := testSealer(t)

	registration := testRegistration(t, "org_platform_domain")
	envelope, _, err := SealRegistration(sealer, registration)
	if err != nil {
		t.Fatalf("seal registration: %v", err)
	}
	got, err := sealer.Open(envelope, registrationAAD)
	if err != nil {
		t.Fatalf("open registration plaintext: %v", err)
	}
	want := `{"version":1,"lane":"org_platform_domain","identity":"` + testIdentity +
		`","anchor":"example.com","issuedAt":1756000000}`
	if got != want {
		t.Fatalf("registration plaintext\n got: %s\nwant: %s", got, want)
	}

	state := testAuthState(t, "org_app_domain")
	state.IssuedAt = testIssuedAt
	state.ConsentAck = true
	stateEnvelope, err := SealAuthState(sealer, state)
	if err != nil {
		t.Fatalf("seal auth state: %v", err)
	}
	got, err = sealer.Open(stateEnvelope, authStateAAD)
	if err != nil {
		t.Fatalf("open auth state plaintext: %v", err)
	}
	want = `{"version":1,"lane":"org_app_domain","identity":"` + testIdentity +
		`","anchor":"example.com","nonce":"` + testNonce +
		`","issuedAt":1756000000,"consentAck":true}`
	if got != want {
		t.Fatalf("auth state plaintext\n got: %s\nwant: %s", got, want)
	}

	// A wildcard registration carries one more field, and its position in the
	// plaintext is part of the same contract. It is `omitempty` on purpose: the
	// two lanes that owe no acknowledgement seal exactly the bytes above, so
	// adding this control did not restate every stored registration.
	withConsent := testRegistration(t, "org_app_domain")
	withConsent.ConsentNonce = testReference
	consentEnvelope, _, err := SealRegistration(sealer, withConsent)
	if err != nil {
		t.Fatalf("seal registration with a consent reference: %v", err)
	}
	got, err = sealer.Open(consentEnvelope, registrationAAD)
	if err != nil {
		t.Fatalf("open registration plaintext: %v", err)
	}
	want = `{"version":1,"lane":"org_app_domain","identity":"` + testIdentity +
		`","anchor":"example.com","consentNonce":"` + testReference + `","issuedAt":1756000000}`
	if got != want {
		t.Fatalf("registration plaintext\n got: %s\nwant: %s", got, want)
	}

	// The wire lane values are half of that contract, so pin them too: the Go
	// constants may be renamed, these strings may not.
	for _, wire := range laneWireValues {
		if _, err := lane.Parse(wire); err != nil {
			t.Fatalf("lane wire value %q no longer parses: %v", wire, err)
		}
	}
}

// A deployment with no keyset has a nil sealer. That is a real state, not a
// programming error, so it must be a refusal a caller can map onto an outcome
// rather than a panic inside a Lambda.
func TestANilSealerIsRefusedRatherThanPanicking(t *testing.T) {
	if _, _, err := SealRegistration(nil, testRegistration(t, "app_domain")); !errors.Is(err, grantcrypto.ErrNoKeyset) {
		t.Fatalf("SealRegistration(nil) = %v", err)
	}
	if _, err := SealAuthState(nil, testAuthState(t, "app_domain")); !errors.Is(err, grantcrypto.ErrNoKeyset) {
		t.Fatalf("SealAuthState(nil) = %v", err)
	}
	if _, err := OpenRegistration(nil, "v1.k.aa.bb"); !errors.Is(err, grantcrypto.ErrNoKeyset) {
		t.Fatalf("OpenRegistration(nil) = %v", err)
	}
	if _, err := OpenAuthState(nil, "v1.k.aa.bb"); !errors.Is(err, grantcrypto.ErrNoKeyset) {
		t.Fatalf("OpenAuthState(nil) = %v", err)
	}
}

// A corrupt or hostile stored row must not turn an Open into an allocation.
func TestOpenRefusesAnEmptyOrOversizedEnvelope(t *testing.T) {
	sealer := testSealer(t)
	for _, envelope := range []string{"", strings.Repeat("x", maxEnvelope+1)} {
		if _, err := OpenRegistration(sealer, envelope); !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("opened a %d-byte envelope: %v", len(envelope), err)
		}
		if _, err := OpenAuthState(sealer, envelope); !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("opened a %d-byte envelope: %v", len(envelope), err)
		}
	}
}

// Both proof inputs are canonicalized on the way in and required canonical on
// the way out, the same way dnsplan.NewSnapshot and Snapshot.Validate treat an
// anchor. The ownership proof is HMAC(K, lane‖identity‖anchor), so a caller that
// spells a domain with a trailing dot or an id in capitals must not end up with
// a second registration for one domain and a proof the customer's published TXT
// will never match.
func TestTheProofInputsAreCanonicalizedWhenTheyAreSealed(t *testing.T) {
	sealer := testSealer(t)
	registration := testRegistration(t, "org_platform_domain")
	registration.Anchor = "  EXAMPLE.Com.  "
	registration.Identity = strings.ToUpper(testIdentity)
	envelope, _, err := SealRegistration(sealer, registration)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := OpenRegistration(sealer, envelope)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got.Anchor != testAnchor {
		t.Fatalf("anchor = %q, want %q", got.Anchor, testAnchor)
	}
	if got.Identity != testIdentity {
		t.Fatalf("identity = %q, want %q", got.Identity, testIdentity)
	}
}

// Two registrations that differ only in the identity must not be
// interchangeable, and neither must two that differ only in the anchor. The
// ownership proof is HMAC(K, lane‖identity‖anchor), so a swapped field is a
// swapped proof.
func TestTheSealedFieldsAreNotInterchangeable(t *testing.T) {
	sealer := testSealer(t)
	first := testRegistration(t, "org_platform_domain")
	second := first
	second.Identity = otherIdentity

	firstEnvelope, _, err := SealRegistration(sealer, first)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	opened, err := OpenRegistration(sealer, firstEnvelope)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if opened.Identity != first.Identity {
		t.Fatalf("identity = %q, want %q", opened.Identity, first.Identity)
	}
	if opened == second {
		t.Fatal("two registrations with different identities compared equal")
	}

	// And the envelope is not a place a field can be edited: the plaintext is
	// authenticated, so a re-marshalled body under the same key is a different
	// ciphertext, never a patched one.
	body, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	forged, _, err := sealer.Seal(string(body), registrationAAD)
	if err != nil {
		t.Fatalf("seal forged: %v", err)
	}
	if forged == firstEnvelope {
		t.Fatal("two different registrations produced one envelope")
	}
}
