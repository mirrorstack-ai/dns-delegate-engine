// Package sealed holds the two envelopes this service issues: a REGISTRATION,
// which is a connected domain's identity, and an AUTH STATE, which is one
// authorization in progress.
//
// 🔴 THESE ARE HOW A SERVICE WITH NO DATABASE REMEMBERS ANYTHING.
//
// This service owns no table, opens no connection and ships no migration (see
// CLAUDE.md, and docs/DESIGN.md §7). Every fact that has to survive between two
// calls — which lane a domain is on, whose it is, which hostname the customer
// proved — travels as ciphertext that MirrorStack's private half stores and
// hands back. It can keep an envelope and it can withhold one. It cannot
// author, edit or reorder one.
//
// Neither envelope holds a secret. They are sealed for INTEGRITY, not
// confidentiality: the private half already knows the org id and the domain it
// sent us. The property being bought is that it cannot retype them.
//
// This is a deliberately different arrangement from internal/grant's sealed
// refresh token. There the ciphertext is a value stored BESIDE a row identity,
// so the AAD has to name that row (see grant.GrantAAD) or a database write
// alone could move the credential to another one. Here the ciphertext CARRIES
// the identity, so there is no second copy to disagree with it, and nothing to
// bind it to except its own type — which is what the two domain separators
// below are for.
//
// 🔴 REPLAY: BOTH ENVELOPES ARE MONOTONE-SAFE, AND THAT IS A TRADE, NOT A FIX.
//
// Neither carries a counter, a stage or a published-record cursor — DESIGN §7
// deletes those from the model and re-reads them from AWS, from Cloudflare and
// from the customer's own zone on every pass. So presenting an OLD envelope
// grants nothing a newer one did not already carry: there is no earlier version
// of a registration that authorizes more, and no way to roll one back into a
// state where a check has not been done yet. That is what makes a stateless
// design safe here at all.
//
// What it costs: a replayed envelope is indistinguishable from the original, so
// the private half cannot revoke a registration by discarding its copy. Nothing
// MirrorStack stores can stop this service acting on a registration that is
// still valid on its own terms. The two things that can are the customer's, and
// both live outside every envelope — delete the ownership proof, which is
// re-checked on every pass, or revoke at the provider (DESIGN §8).
package sealed

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/grantcrypto"
)

// Version is the envelope version both types carry.
//
// It is checked EXACTLY, never as a floor. An envelope written by a build this
// one does not know is refused rather than guessed at, for grantcrypto's
// reason: the failure mode of guessing is acting on a domain under a rule that
// was not the one the customer agreed to. Bumping it invalidates every stored
// registration at once, so it is bumped deliberately or not at all.
const Version = int16(1)

// AuthStateTTL bounds how long one authorization may stay in flight. See
// OpenAuthState for what that bound is actually protecting.
const AuthStateTTL = 10 * time.Minute

const (
	// nonceBytes is 128 bits, hex-encoded on the wire. Hex rather than base64
	// so the encoded form is fixed-length and has no padding or alphabet
	// question to get wrong when it is validated on the way back in.
	nonceBytes = 16

	// maxEnvelope bounds an envelope this package will even attempt to open. A
	// stored envelope is untrusted input BEFORE it decrypts as well as after,
	// and a corrupt or hostile row must not turn an Open into an allocation.
	// dnsplan bounds a stored identity string for the same reason. A sealed
	// registration is a few hundred bytes; this is generous by an order of
	// magnitude and still finite.
	maxEnvelope = 4096
)

// The additional authenticated data each envelope type is sealed under.
//
// 🔴 THE TWO MUST DIFFER, AND NOTHING MAY EVER MAKE THEM EQUAL.
//
// Both plaintexts carry a lane, an identity and an anchor under the same JSON
// keys, so a registration decoded as an auth state would satisfy every field
// they share. The difference that matters is the clock: a registration is
// STANDING — it is the row's identity and never expires — while an auth state
// is refused after AuthStateTTL. Present a registration where a state is
// expected and the ten-minute bound is not broken, it is simply never reached,
// because the envelope that arrived never had one. The reverse substitution is
// as bad in the other direction: a ten-minute value would become the permanent
// identity of a customer's domain.
//
// The AAD is what makes "this ciphertext is a state" a fact AES-GCM enforces,
// rather than a convention about which parameter it happened to arrive in.
const (
	registrationAAD = "ms-dns-registration/v1"
	authStateAAD    = "ms-dns-authstate/v1"
)

var (
	// ErrInvalidEnvelope is every "this value is not usable here" answer: an
	// unknown key, the wrong envelope type, a tampered ciphertext, or a
	// plaintext that does not validate.
	//
	// Deliberately ONE error, for grantcrypto.Open's reason — telling a caller
	// which half of a value was wrong tells an attacker the same thing. The
	// specific cause is wrapped for logs and tests, not for a decision.
	ErrInvalidEnvelope = errors.New("sealed: envelope is not usable here")

	// ErrExpired is the one refusal that IS distinguished, because it is the
	// only one that is NORMAL. A customer who left the provider's consent
	// screen open over lunch should be told to start the connect again, not
	// shown the same message as a corrupt envelope. It leaks nothing an
	// attacker could use: reaching it at all requires an envelope this service
	// sealed and this deployment can still open.
	ErrExpired = errors.New("sealed: auth state is past its window")
)

// Registration is what an intent returns and every lifecycle function takes.
//
// It IS the row identity: the lane, whose it is, and the anchor the customer
// proved. There is no records field in it and no target in it, because there is
// no records field and no target anywhere in this API (DESIGN §5) — what gets
// written is derived here, from these three facts and nothing else.
//
// 🔴 THE JSON TAGS AND FIELD TYPES ARE THE STORED SHAPE, NOT AN IMPLEMENTATION
// DETAIL. A registration outlives the build that sealed it: a domain connected
// today is advanced by whatever is deployed next month. Renaming a tag or
// changing a type strands every stored envelope at once, and the symptom is
// every customer domain refusing to advance rather than a failing unit test.
// The field ORDER fixes the bytes this package emits, which TestGoldenEnvelope
// pins so that a drift is a build failure instead of an outage. Change either
// only by bumping Version, and expect that invalidation.
type Registration struct {
	Version int16     `json:"version"`
	Lane    lane.Lane `json:"lane"`

	// Identity is an org id on lanes 1 and 2, and an APP id on lane 3 — where
	// the owner may be a person and there is no organization anywhere in the
	// request (DESIGN §2). That is why this field is not called OrgID.
	//
	// 🔴 ITS SPELLING IS LOAD-BEARING. The ownership proof the customer
	// publishes is HMAC(K, lane‖identity‖anchor), so two spellings of one id
	// are two different TXT values, and the second would tell a customer their
	// correctly-published record is absent. lane.ValidateIdentity owns the one
	// canonical rule; this package does not add a second one. It stamps the
	// canonical form when an envelope is sealed and requires it when one is
	// opened, exactly as it does with the anchor below.
	Identity string `json:"identity"`

	// Anchor is the name every derived record must sit at or under. It is
	// normalized when the envelope is sealed and required normalized when it is
	// opened, exactly as dnsplan.NewSnapshot and dnsplan.Snapshot.Validate do
	// it, so the two agree on what "the same anchor" means.
	Anchor string `json:"anchor"`

	// IssuedAt records when the domain was registered, in unix seconds. It
	// bounds nothing: a registration is standing by design, so unlike an auth
	// state there is no clock for it to fail. It is here to be read by a person
	// holding a support ticket, and it is validated only for being present.
	IssuedAt int64 `json:"issuedAt"`
}

// AuthState is the OAuth `state`, minted HERE rather than by the caller.
//
// 🔴 THIS IS WHAT MAKES authorize AND complete ONE ACT. complete() takes no
// identity, no lane and no domain: all three come out of this envelope. Two
// requests whose fields are checked against each other can be made to disagree,
// because a check is only as strong as the code path that reaches it and there
// are always more paths than checks. One sealed envelope cannot disagree with
// itself.
type AuthState struct {
	Version  int16     `json:"version"`
	Lane     lane.Lane `json:"lane"`
	Identity string    `json:"identity"`
	Anchor   string    `json:"anchor"`

	// Nonce makes two authorizations of one registration two different values.
	// Without it every state minted for a domain would have an identical
	// plaintext, and a state scraped out of a browser history or a proxy log
	// would be indistinguishable from the attempt actually in flight.
	//
	// The honest limit: this service stores nothing, so it cannot enforce that
	// a state is used once. It can only make each one distinct and short-lived.
	// Single use lives one layer down, at the provider, on the authorization
	// CODE — which the first exchange spends.
	Nonce string `json:"nonce"`

	IssuedAt int64 `json:"issuedAt"`

	// ConsentAck records that this service's own consent page was served and
	// acknowledged. It is required on the org_app_domain lane only, where the
	// grant is a wildcard whose scope a customer cannot enumerate for
	// themselves (DESIGN §4).
	//
	// 🔴 IT IS INSIDE THE SEAL BECAUSE THAT IS THE ONLY PLACE IT MEANS
	// ANYTHING. A boolean travelling beside the state is a boolean the caller
	// sets. Sealed together with the lane and the anchor it was acknowledged
	// for, it is a fact about that same act. Which lanes owe an acknowledgement
	// is internal/consent's rule to enforce, not this package's — sealed only
	// guarantees that the answer cannot be added afterwards.
	//
	// NOT `omitempty`: "not acknowledged" is exactly the false case, and
	// omitting it would make an absent field indistinguishable from it. Same
	// reason as dnsplan.Record.Proxied.
	ConsentAck bool `json:"consentAck"`
}

// SealRegistration seals a registration and returns the envelope together with
// the key id it was sealed under.
//
// The key id comes back because the private half stores it beside the
// ciphertext: that is what lets an operator answer "is the retired key still
// needed?" with a SELECT DISTINCT rather than by decrypting every row. This
// service holds no row to answer it from.
//
// It validates BEFORE it seals. An envelope that seals and cannot be opened is
// a failure that surfaces days later, on the pass that needed it, long after
// the caller that could have fixed it has gone.
func SealRegistration(s *grantcrypto.Sealer, r Registration) (envelope, keyID string, err error) {
	if s == nil {
		return "", "", noSealer()
	}
	// The version describes the ENVELOPE, not the registration, so it is
	// stamped here rather than taken from the caller. A caller that could
	// choose it could seal something this build cannot open.
	r.Version = Version
	canonicalize(&r.Identity, &r.Anchor)
	if err := r.validate(); err != nil {
		return "", "", err
	}
	payload, err := json.Marshal(r)
	if err != nil {
		return "", "", fmt.Errorf("%w: marshal registration: %w", ErrInvalidEnvelope, err)
	}
	return s.Seal(string(payload), registrationAAD)
}

// OpenRegistration opens a registration envelope and re-validates it.
//
// 🔴 A STORED ENVELOPE IS UNTRUSTED INPUT EVEN AFTER IT DECRYPTS. Decryption
// proves this service sealed the bytes; it does not prove the bytes still
// describe something this build is willing to act on. The value may have been
// written by an older build, under rules that have since been tightened, and it
// arrives from a store this service does not own.
func OpenRegistration(s *grantcrypto.Sealer, envelope string) (Registration, error) {
	payload, err := open(s, envelope, registrationAAD)
	if err != nil {
		return Registration{}, err
	}
	var r Registration
	if err := decode(payload, &r); err != nil {
		return Registration{}, err
	}
	if err := r.validate(); err != nil {
		return Registration{}, err
	}
	return r, nil
}

// SealAuthState seals one authorization in progress.
//
// It does NOT check IssuedAt against the clock, and Open does. A window is a
// property of the moment a value is USED, not of the value, and the moment of
// use is the only one where the authority is being granted. Putting the clock
// where the authority is also keeps the expiry path reachable in a test without
// a clock seam this package would otherwise have to carry forever.
//
// No key id is returned: an auth state lives ten minutes, so it cannot outlive
// a key rotation and there is nothing for an operator to reconcile later.
func SealAuthState(s *grantcrypto.Sealer, a AuthState) (envelope string, err error) {
	if s == nil {
		return "", noSealer()
	}
	a.Version = Version
	canonicalize(&a.Identity, &a.Anchor)
	if err := a.validate(); err != nil {
		return "", err
	}
	payload, err := json.Marshal(a)
	if err != nil {
		return "", fmt.Errorf("%w: marshal auth state: %w", ErrInvalidEnvelope, err)
	}
	sealedValue, _, err := s.Seal(string(payload), authStateAAD)
	return sealedValue, err
}

// OpenAuthState opens an auth state and refuses one outside its window.
//
// 🔴 WHAT THE SHORT TTL BOUNDS IS THE AGE OF A PROOF, NOT THE LIFE OF A TOKEN.
//
// authorize() refuses unless verify() passes RIGHT NOW, and this envelope is
// the receipt of that check: complete() publishes on its word. A state that
// stayed valid for a week would let a publish act on an ownership proof that
// was true a week ago — and deleting that proof is the customer's first control
// (DESIGN §8), worth something only if we are never operating on a stale
// reading of it. Ten minutes is a consent screen, not a policy.
//
// What a short TTL does NOT protect against, and nothing in this service does:
// an envelope that is simply WITHHELD. The private half can always decline to
// complete an authorization, or to advance a domain afterwards. That is the
// honest limit in DESIGN §7. What it cannot do is advance one FURTHER than the
// customer proved.
//
// Nor does the TTL make a state single-use — a service that stores nothing
// cannot count. Within the window a state can be presented twice; the
// authorization code presented with it cannot be spent twice, and that is where
// single use actually lives.
func OpenAuthState(s *grantcrypto.Sealer, envelope string) (AuthState, error) {
	payload, err := open(s, envelope, authStateAAD)
	if err != nil {
		return AuthState{}, err
	}
	var a AuthState
	if err := decode(payload, &a); err != nil {
		return AuthState{}, err
	}
	if err := a.validate(); err != nil {
		return AuthState{}, err
	}
	// Bounded in BOTH directions. Behind, because that is the window. Ahead,
	// because a forward-dated envelope would otherwise live as long as its date
	// is wrong, and the date is inside the seal where no later check can catch
	// it. It is not refused outright because clocks across instances do
	// disagree by seconds, and refusing every future timestamp would break
	// authorize→complete for real customers on a skew nobody caused. One TTL of
	// tolerance keeps the worst case at two TTLs rather than at unbounded.
	age := time.Since(time.Unix(a.IssuedAt, 0))
	if age > AuthStateTTL || age < -AuthStateTTL {
		return AuthState{}, fmt.Errorf("%w: minted %s from now", ErrExpired, age.Round(time.Second))
	}
	return a, nil
}

// NewNonce returns a fresh 128-bit nonce.
//
// There is no fallback to a weaker source and no "good enough" path. A
// predictable nonce is not a nonce, and an authorization that succeeded with
// one would be worse than an authorization that failed and was retried.
func NewNonce() (string, error) {
	buf := make([]byte, nonceBytes)
	// crypto/rand.Read does not report a failure on any platform this service
	// runs on — it panics instead. The error is still handled rather than
	// dropped, because the alternative is a call site that would silently do
	// the wrong thing if that ever changed.
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("sealed: nonce: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func (r Registration) validate() error {
	return validateSubject(r.Version, r.Lane, r.Identity, r.Anchor, r.IssuedAt)
}

func (a AuthState) validate() error {
	if err := validateSubject(a.Version, a.Lane, a.Identity, a.Anchor, a.IssuedAt); err != nil {
		return err
	}
	// The nonce is checked for shape because an envelope carrying an empty one
	// would open, validate on every other field, and quietly have lost the only
	// property the nonce exists to provide.
	if len(a.Nonce) != hex.EncodedLen(nonceBytes) {
		return fmt.Errorf("%w: nonce length", ErrInvalidEnvelope)
	}
	if _, err := hex.DecodeString(a.Nonce); err != nil {
		return fmt.Errorf("%w: nonce encoding", ErrInvalidEnvelope)
	}
	return nil
}

// validateSubject is the part both envelopes share.
//
// Every rule here is a SHAPE rule. Whether a domain is one MirrorStack is
// willing to serve at all — at least two LDH labels, no wildcard, and the
// refusal at or under a MirrorStack suffix in DESIGN §5 — is
// lane.ValidateDomain's question, asked once by the intent that mints a
// registration and deliberately not re-litigated here. Two implementations of
// one policy drift, and the looser of the two is the one that decides. This is
// the looser one on purpose: nothing reaches it that was not minted after the
// stricter check, and a second copy of that check would be a second rule to
// keep in step, sitting in the package least likely to be edited when the first
// one moves.
func validateSubject(version int16, l lane.Lane, identity, anchor string, issuedAt int64) error {
	if version != Version {
		return fmt.Errorf("%w: envelope version %d", ErrInvalidEnvelope, version)
	}
	if _, err := lane.Parse(string(l)); err != nil {
		return fmt.Errorf("%w: lane: %w", ErrInvalidEnvelope, err)
	}
	canonical, err := lane.ValidateIdentity(identity)
	if err != nil {
		return fmt.Errorf("%w: identity: %w", ErrInvalidEnvelope, err)
	}
	// Required in its canonical spelling on the way out, not merely valid: the
	// same rule the anchor gets, for the same reason. An envelope carrying one
	// of two spellings of an id carries one of two ownership proofs with it.
	if canonical != identity {
		return fmt.Errorf("%w: identity is not in its canonical spelling", ErrInvalidEnvelope)
	}
	if anchor == "" || anchor != dnsplan.NormalizeName(anchor) || len(anchor) > dnsplan.MaxDNSName {
		return fmt.Errorf("%w: anchor is not a normalized DNS name", ErrInvalidEnvelope)
	}
	// Not a clock check — see Registration.IssuedAt. An absent timestamp is a
	// malformed envelope, and zero is what an absent JSON field decodes to.
	if issuedAt <= 0 {
		return fmt.Errorf("%w: issuedAt is not set", ErrInvalidEnvelope)
	}
	return nil
}

// canonicalize rewrites the two fields whose SPELLING is load-bearing into the
// single form the ownership proof is computed over.
//
// It runs on the way IN, so a caller that types a domain in capitals or an id
// in mixed case does not end up with a second registration for one domain,
// carrying a proof value the customer's published TXT can never match. It is
// the same shape as dnsplan.NewSnapshot normalizing an anchor on write while
// Snapshot.Validate requires it normalized on read.
//
// A value that does not canonicalize at all is left exactly as it arrived, so
// validateSubject reports it rather than this function hiding a bad id behind a
// partial rewrite.
func canonicalize(identity, anchor *string) {
	*anchor = dnsplan.NormalizeName(*anchor)
	if canonical, err := lane.ValidateIdentity(*identity); err == nil {
		*identity = canonical
	}
}

// open decrypts under exactly one AAD. The nil-sealer and length guards live
// here rather than at each call site because they protect against the same
// thing on every path, and the call site that forgot one would be the one that
// mattered.
func open(s *grantcrypto.Sealer, envelope, aad string) (string, error) {
	if s == nil {
		return "", noSealer()
	}
	if envelope == "" || len(envelope) > maxEnvelope {
		return "", fmt.Errorf("%w: envelope length %d", ErrInvalidEnvelope, len(envelope))
	}
	payload, err := s.Open(envelope, aad)
	if err != nil {
		// Wrapped both ways: a caller matching the boundary still gets one
		// opaque answer, while an operator can distinguish
		// grantcrypto.ErrUnknownKey — the single cause with a different fix,
		// which is to restore the key rather than to re-register the domain.
		return "", fmt.Errorf("%w: %w", ErrInvalidEnvelope, err)
	}
	return payload, nil
}

// decode refuses a field this build does not know rather than dropping it.
// Version already refuses an envelope that announced a new shape; this catches
// the change that forgot to announce itself, which is the one nobody is
// watching for.
func decode(payload string, into any) error {
	dec := json.NewDecoder(strings.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEnvelope, err)
	}
	// A second JSON value behind the first would mean the plaintext is not the
	// one thing it claims to be.
	if dec.More() {
		return fmt.Errorf("%w: trailing content in envelope", ErrInvalidEnvelope)
	}
	return nil
}

// noSealer is the answer when this deployment holds no keyset. A deployment can
// legitimately be in that state (see grant.Service), so it is a refusal a
// caller can map onto a real outcome rather than a panic inside a Lambda. The
// grantcrypto sentinel is carried through so the caller can tell "no keyset
// here" apart from "this envelope is wrong".
func noSealer() error {
	return fmt.Errorf("%w: %w", ErrInvalidEnvelope, grantcrypto.ErrNoKeyset)
}
