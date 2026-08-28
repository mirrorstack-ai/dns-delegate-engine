package intent

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/consent"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/derive"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsprovider"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/observe"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/proof"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/reconcile"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/relay"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/schedule"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/sealed"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/cfoauth"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/grantcrypto"
)

// oauthLoader and keyLoader are the two credential sources, as interfaces so a
// test drives them without AWS. They are per-request: the loaders re-read their
// secret on a TTL, so a credential filled in or rotated after this Lambda started
// is picked up without a redeploy.
type oauthLoader interface {
	Config(ctx context.Context) *cfoauth.Config
}

type keyLoader interface {
	Sealer(ctx context.Context) *grantcrypto.Sealer
}

// ReachProbe measures whether the wired Resolver's vantage points can be
// reached. An interface, like Resolver, so no test in this package needs a
// network to check what the answer is published as.
//
// 🔴 CAPABILITIES IS ITS ONLY CALLER. A reachability reading never reaches a
// lookup, a verification or a write — it cannot narrow a quorum it is not read
// by. See observe.Probe.
type ReachProbe interface {
	Reach(ctx context.Context) observe.Reach
}

// zoneReader is the READ-ONLY view of a DNS provider that Orphans is given.
//
// 🔴 "A REPORT, NEVER A MUTATION" IS A PROPERTY OF THIS TYPE, NOT A PROMISE IN A
// COMMENT. dnsprovider.Provider also has CreateRecord and PatchRecord; this
// interface does not, so no future edit to Orphans can reach a write without
// first widening a type declaration that says, in its name, that it must not be.
type zoneReader interface {
	FindZone(ctx context.Context, token, name string) (zoneID string, err error)
	ListRecordsAt(ctx context.Context, token, zoneID, name string) ([]dnsprovider.LiveRecord, error)
	SameValue(recordType, live, desired string) bool
}

// Service is the intent RPC implementation.
//
// Everything external is behind an interface: the OAuth client, the keyset, the
// DNS provider, the public resolver, and both upstream relays. That is what lets
// every safety property this repository claims be tested — by us or by a
// customer's own developers — without a network, a database or a Cloudflare
// account.
type Service struct {
	OAuth     oauthLoader
	Keys      keyLoader
	Publisher reconcile.Publisher

	// Derive is this deployment's routing configuration: the two CNAME targets and
	// the DCV delegation identifier. Data rather than an interface, because a seam
	// here is one a caller could substitute a permissive derivation into.
	Derive derive.Config

	// Resolver reads PUBLIC DNS, and there is deliberately no default: a nil
	// Resolver is reported as ErrUnavailable rather than quietly replaced with
	// observe.NetResolver{}, because a default would let a test that forgot its
	// fake silently resolve real names. A binary wires the real one explicitly.
	Resolver observe.Resolver

	// Reach measures whether Resolver's vantage points can be reached from where
	// this runs, so a deployment wired for a quorum it has no egress to SAYS SO
	// instead of refusing every authorization with `unknown`. Nil leaves the
	// reading unmeasured, which Capabilities reports as absent rather than as
	// nothing being reachable.
	Reach ReachProbe

	// Certificates and Edge are the two OPTIONAL upstream relays: AWS ACM for
	// record 5 and Cloudflare for SaaS for record 7. Both are read with
	// MIRRORSTACK's own credentials and never with the customer's grant — the
	// custom hostname and the certificate are ours, and sending a customer's token
	// to them would widen that grant beyond what the consent screen described.
	//
	// Nil means "not wired": a lane that never had those records, or a deployment
	// not configured for them. Never an error — a lane must still publish what it
	// CAN derive.
	//
	// Edge reads a DIFFERENT MirrorStack zone per lane (relay.EdgeZones), which is
	// why it takes the lane rather than the hostname alone. Capabilities publishes
	// those ids when this one can report them, so a lane pointed at the wrong zone
	// is visible from outside rather than only as hosts that never start serving.
	Certificates relay.CertificateAuthority
	Edge         relay.EdgeHostnames

	// HTTPClient is used for token exchange, refresh and revocation. Nil means a
	// 10-second default.
	HTTPClient *http.Client
}

func (s *Service) httpClient() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (s *Service) oauthConfig(ctx context.Context) *cfoauth.Config {
	if s.OAuth == nil {
		return nil
	}
	return s.OAuth.Config(ctx)
}

// reach is the deployment's own egress measurement; the zero Reach is
// "unmeasured".
func (s *Service) reach(ctx context.Context) observe.Reach {
	if s.Reach == nil {
		return observe.Reach{}
	}
	return s.Reach.Reach(ctx)
}

func (s *Service) sealer(ctx context.Context) *grantcrypto.Sealer {
	if s.Keys == nil {
		return nil
	}
	return s.Keys.Sealer(ctx)
}

// prover computes ownership proofs under this deployment's keyset. A deployment
// with no keyset must say so rather than derive a plan whose ownership row is
// empty.
func (s *Service) prover(ctx context.Context) (proof.Prover, error) {
	sealer := s.sealer(ctx)
	if sealer == nil {
		return proof.Prover{}, fmt.Errorf(
			"%w: this deployment holds no keyset, so no ownership proof can be computed", ErrUnavailable)
	}
	return proof.Prover{Sealer: sealer}, nil
}

// ─── capabilities ───────────────────────────────────────────────────────────

// Capabilities reports what this deployment can offer and what it would put in a
// zone. It writes nothing, takes no registration, and touches no credential.
//
// The routing targets and the DCV delegation identifier are published on
// purpose: none is a secret, and each ends up in a customer's own zone as the
// VALUE of a record we ask them to accept. See CapabilitiesResponse.
func (s *Service) Capabilities(ctx context.Context) CapabilitiesResponse {
	out := CapabilitiesResponse{
		Provider:          s.providerName(),
		OrgRoutingTarget:  s.Derive.OrgRoutingTarget,
		AppRoutingTarget:  s.Derive.AppRoutingTarget,
		DCVDelegationUUID: s.Derive.DCVDelegationUUID,
		Lanes:             laneCapabilities(s.edgeZones()),
	}
	// The declared clock, so DESIGN §8's promise — that what runs, and when, is
	// public — is answerable from this API, not only from a source file.
	cadence := schedule.Declared()
	out.IntervalSeconds = int64(cadence.Interval / time.Second)
	out.JitterSeconds = int64(cadence.Jitter / time.Second)
	out.MinIntervalSeconds = int64(cadence.MinInterval / time.Second)

	// Read off the wired resolver, never a constant: a claim about vantage points
	// that the binary's wiring cannot contradict. The probe beside it turns the
	// rule from a declaration into a measurement — the threshold published here
	// is worthless if this deployment cannot reach the resolvers it names.
	if s.Resolver != nil {
		policy := observe.PolicyOf(s.Resolver)
		out.Resolution = ResolutionCapability{
			Vantages:      policy.Vantages,
			Threshold:     policy.Threshold,
			Authoritative: policy.Authoritative,
			Reachability:  reachabilityView(s.reach(ctx)),
		}
	}

	if err := s.Derive.Validate(); err != nil {
		// Reported rather than swallowed: an unconfigured deployment and a
		// MISCONFIGURED one otherwise look identical from outside — the trap
		// cfoauth.FromEnv documents.
		out.ConfigError = err.Error()
	}
	cfg := s.oauthConfig(ctx)
	if cfg == nil {
		return out
	}
	out.Available = true
	out.Scopes = cfg.Scopes
	out.CanHold = s.sealer(ctx) != nil
	return out
}

// edgeZones names the MirrorStack zones record 7 is read from, per lane, or the
// zero table when nothing is wired.
//
// Asserted rather than stored, so what Capabilities publishes is the table the
// reader ACTUALLY uses; a second field holding a second copy of the same
// environment variables is the copy that goes stale, and it would go stale in the
// direction of claiming a configuration that is not in force.
func (s *Service) edgeZones() relay.EdgeZones {
	reporter, ok := s.Edge.(relay.EdgeZoneReporter)
	if !ok {
		return relay.EdgeZones{}
	}
	return reporter.EdgeZones()
}

func (s *Service) providerName() string {
	if s.Publisher.Provider == nil {
		return ""
	}
	return s.Publisher.Provider.Name()
}

// laneCapabilities describes the three lanes in the terms a customer decides on:
// what is anchored, what is derived beneath it, how long a credential lives, and
// which MirrorStack zone this deployment reads that lane's serving proof from.
func laneCapabilities(zones relay.EdgeZones) []LaneCapability {
	out := make([]LaneCapability, 0, 3)
	for _, l := range []lane.Lane{lane.OrgPlatformDomain, lane.OrgAppDomain, lane.AppDomain} {
		description := ""
		switch l {
		case lane.OrgPlatformDomain:
			description = strings.Join(lane.PlatformLabels, " ") + " under the domain you connect"
		case lane.OrgAppDomain:
			description = "one wildcard, routing every app you deploy at <app>.<domain>"
		case lane.AppDomain:
			description = "the hostname itself, and nothing beneath it"
		}
		// An unconfigured lane reports the empty string rather than a refusal:
		// this is a description of the deployment, and "no zone" is the truth
		// about one whose edge relay is not wired.
		zoneID, _ := zones.ForLane(l)
		out = append(out, LaneCapability{
			Lane:         string(l),
			Hosts:        description,
			Anchor:       "the domain you connect, and every record sits at or under it",
			GrantSeconds: grantSeconds(l),
			ConsentPage:  consent.Required(l),
			EdgeZone:     zoneID,
		})
	}
	return out
}

// ─── the four intents ───────────────────────────────────────────────────────
//
// 🔴 THE LANE IS CHOSEN BY THE ENTRY POINT, NEVER BY A REQUEST FIELD.
//
// DESIGN §5 admits a `lane` field; each intent being its own function makes it a
// constant at the call site instead. The lane is inside the ownership HMAC — two
// lanes are two different proofs, and a proof for one authorizes nothing on
// another — so a lane a caller could mistype is a proof a customer could publish
// and have rejected.

// AddOrgPlatformDomain registers an org's console domain, and writes nothing.
func (s *Service) AddOrgPlatformDomain(ctx context.Context, req AddOrgPlatformDomainRequest) (RegisteredResponse, error) {
	return s.register(ctx, lane.OrgPlatformDomain, req.OrgID, req.Domain)
}

// AddOrgAppDomain registers the parent under which an org's apps are
// auto-routed, and writes nothing.
func (s *Service) AddOrgAppDomain(ctx context.Context, req AddOrgAppDomainRequest) (RegisteredResponse, error) {
	return s.register(ctx, lane.OrgAppDomain, req.OrgID, req.Domain)
}

// AddAppDomain registers one arbitrary domain against one app, and writes
// nothing. The identity is an APP: this lane has to work when there is no
// organization in the request.
func (s *Service) AddAppDomain(ctx context.Context, req AddAppDomainRequest) (RegisteredResponse, error) {
	return s.register(ctx, lane.AppDomain, req.AppID, req.Hostname)
}

// register is the whole of all three intents.
//
// 🔴 IT TOUCHES NO CREDENTIAL AND WRITES NOTHING. It computes the proof the
// customer must publish, derives the records, seals the registration and returns
// the digest. Because the ownership proof is the customer's to publish, nothing
// CAN be asked of a provider until they act.
func (s *Service) register(ctx context.Context, l lane.Lane, identity, domain string) (RegisteredResponse, error) {
	prover, err := s.prover(ctx)
	if err != nil {
		return RegisteredResponse{}, err
	}
	canonical, err := lane.ValidateIdentity(identity)
	if err != nil {
		return RegisteredResponse{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	// The anchor's SPELLING is settled here; its ADMISSION by derive below, which
	// holds the reserved-suffix list. The proof is computed over the canonical
	// anchor, so it must be canonical before the proof exists.
	anchor, err := lane.ValidateDomain(domain, nil)
	if err != nil {
		return RegisteredResponse{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	proofValue, err := prover.Expected(l, canonical, anchor)
	if err != nil {
		return RegisteredResponse{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	plan, err := s.Derive.Registration(l, canonical, anchor, proofValue)
	if err != nil {
		return RegisteredResponse{}, deriveError(err)
	}
	// A fail-closed guard, not a formality. The proof value was computed over
	// `anchor`; the plan hangs it at `_mirrorstack-challenge.<plan.Anchor>`. If
	// those disagreed, the customer would publish a correct value at a name we
	// never check and the domain would sit unverifiable with a record that looks
	// right on their screen.
	if plan.Anchor != anchor {
		return RegisteredResponse{}, fmt.Errorf(
			"%w: the derived anchor %q is not the validated anchor %q", ErrInvalidRequest, plan.Anchor, anchor)
	}

	// 🔴 THE CONSENT REFERENCE IS MINTED HERE, AND SEALED IN. The acknowledgement
	// is a MAC over (reference, anchor); minting the reference at registration is
	// what makes it a value THIS service issued for THIS domain, rather than one
	// half of a MAC the caller chose (AuthorizeRequest.ConsentToken). Lanes are
	// selected by consent.Required, the single rule for which lanes have a page,
	// so an unrecognised lane gets a reference rather than silently getting none.
	consentNonce := ""
	if consent.Required(l) {
		consentNonce, err = sealed.NewNonce()
		if err != nil {
			return RegisteredResponse{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
	}

	sealer := s.sealer(ctx)
	envelope, keyID, err := sealed.SealRegistration(sealer, sealed.Registration{
		Lane: l, Identity: canonical, Anchor: anchor,
		ConsentNonce: consentNonce, IssuedAt: time.Now().Unix(),
	})
	if err != nil {
		return RegisteredResponse{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	snapshot, err := reviewSnapshot(l, canonical, plan)
	if err != nil {
		return RegisteredResponse{}, err
	}

	out := RegisteredResponse{
		Registration: envelope,
		KeyID:        keyID,
		Lane:         string(l),
		Anchor:       anchor,
		Hosts:        plan.Hosts,
		Records:      recordViews(plan.Items),
		Digest:       hex.EncodeToString(snapshot.Digest()),
		GrantSeconds: grantSeconds(l),
	}
	for _, item := range plan.Items {
		if item.Purpose == derive.PurposeOwnership {
			out.Proof = recordView(item)
		}
	}
	// Fail closed rather than returning a registration with an empty proof: a
	// caller cannot tell an absent proof from one it failed to render, and a
	// registration nobody can verify sits at "waiting for your DNS record"
	// forever, with no record to wait for.
	if out.Proof.Name == "" || out.Proof.Value == "" {
		return RegisteredResponse{}, fmt.Errorf(
			"%w: the derived plan carries no ownership proof for %q", ErrUnavailable, anchor)
	}
	return out, nil
}

// BindAppToOrgAppDomain mints what ONE app owes under an org app domain, at
// deploy time.
//
// It has two outcomes, and the second is not a failure:
//
//	grant live                   → the records are published    → "published"
//	grant absent/expired/revoked → NOTHING is written            → "manual",
//	                               carrying the exact records to add by hand
//
// 🔴 THE PRIVATE HALF DOES NOT CHOOSE BETWEEN THEM AND CANNOT ASK FOR THE FIRST.
// Whether a usable credential exists is a fact THIS service establishes, by
// opening the sealed grant and refreshing it: there is no "publish for me" flag
// and no way to assert a grant one does not hold. Advance degrades identically on
// every lane, through the same code.
func (s *Service) BindAppToOrgAppDomain(ctx context.Context, req BindAppRequest) (PassResponse, error) {
	reg, err := s.openRegistration(ctx, req.Registration)
	if err != nil {
		return PassResponse{}, err
	}
	// Binding is defined only under an org app domain. On the other two lanes the
	// anchor is the served hostname itself or a fixed table of four, so there is
	// no name for a slug to select and accepting one would invent authority the
	// design does not grant.
	if reg.Lane != lane.OrgAppDomain {
		return PassResponse{}, fmt.Errorf(
			"%w: an app is bound under an org app domain, not under %s", ErrInvalidRequest, reg.Lane)
	}
	plan, err := s.Derive.BindApp(reg.Anchor, req.Slug)
	if err != nil {
		return PassResponse{}, deriveError(err)
	}
	// The same body Advance runs, with the parent's grant: one implementation is
	// what keeps "advance degrades the same way on every lane" true.
	return s.pass(ctx, reg, plan, req.SealedToken)
}

// ─── the seven lifecycle functions ──────────────────────────────────────────

// Verify resolves the ownership proof in PUBLIC DNS and reports whether it is
// present.
//
// 🔴 THE CALLER CANNOT SAY WHAT TO LOOK FOR AND CANNOT SUPPLY A VALUE THAT MAKES
// IT PASS. The name comes from the sealed registration's anchor and the accepted
// values are recomputed from that registration under this deployment's keyset.
// The previous design's proof was a record WE published, checked by a public
// lookup of that same record — a sentence with no fact behind it.
func (s *Service) Verify(ctx context.Context, req VerifyRequest) (VerifyResponse, error) {
	reg, err := s.openRegistration(ctx, req.Registration)
	if err != nil {
		return VerifyResponse{}, err
	}
	check, err := s.checkProof(ctx, reg)
	out := VerifyResponse{
		Verified: check.published,
		Name:     check.name,
		Expected: check.expected,
		Proof: RecordView{
			Type:    "TXT",
			Name:    check.name,
			Value:   check.expected,
			Purpose: string(derive.PurposeOwnership),
			Source:  string(derive.SourceCustomer),
			State:   string(check.observation.State),
			Found:   check.observation.Found,
			Explain: check.observation.Explain,

			// What the reading is worth. Verify is the one call whose whole answer
			// is a boolean, so the number of vantage points behind it has to travel
			// with it.
			Agreement: agreementView(check.observation),
		},
	}
	// 🔴 A LOOKUP THAT DID NOT COMPLETE IS NOT A NEGATIVE — AND IT IS NOT AN RPC
	// ERROR EITHER. Reporting it as "not verified" would make a resolver blip
	// indistinguishable from a customer who never published, and the two have
	// opposite remedies. Returning it as an error throws the observation away at
	// the transport, answering with `{"ok":false,"code":"internal"}`: the name,
	// the value to publish and what was seen all discarded, and a fault implied
	// when neither side was at fault.
	//
	// So the RPC succeeds, Verified stays FALSE, and Unresolved says why — set
	// together, in that order, because this path must never report a proof as
	// present on an answer that never arrived.
	if lookupFailed(err) {
		out.Verified, out.Unresolved = false, true
		return out, nil
	}
	return out, err
}

// ConsentPage renders this service's own consent page for a registration. It
// writes nothing, touches no credential, and mints no acknowledgement.
//
// 🔴 IT DERIVES THE PLAN THROUGH derivedPlan, THE SAME FUNCTION Complete AND
// Advance PUBLISH FROM. The page's claim is that the customer was shown what
// will be written; a second derivation anywhere — the serving binary, a console,
// a proxy — could drift from the writer's by one record, and the acknowledgement
// would then assert agreement to something nobody was shown. So the page and the
// writer read one function, or the page is not rendered at all.
//
// It returns no acknowledgement token: being shown the page and agreeing to it
// are two events, and consent.Token belongs to the second. If rendering minted
// one, everybody who could fetch the page — the private half included — would
// hold a customer's agreement to a standing wildcard, unread.
//
// It takes no reference either: the one printed comes out of the sealed
// registration, the value Authorize checks the acknowledgement against. Any other
// reference collects an agreement that could never be verified; a caller-chosen
// one collects an agreement that verifies against nothing this service issued.
func (s *Service) ConsentPage(ctx context.Context, registration string) (string, error) {
	reg, err := s.openRegistration(ctx, registration)
	if err != nil {
		return "", err
	}
	// consent.Page refuses the other lanes too, in its own terms. This refusal
	// names the REQUEST as what was wrong, so a caller asking for the wrong lane's
	// screen is not told instead that its plan is malformed.
	if !consent.Required(reg.Lane) {
		return "", fmt.Errorf("%w: %s publishes a closed, listable record set and has no consent page",
			ErrInvalidRequest, reg.Lane)
	}
	// Fail closed rather than rendering a page nobody could act on. A lane-2
	// registration with no sealed reference was minted by a build without this
	// control; serving it would take the customer's agreement and then refuse the
	// acknowledgement at Authorize with no way to tell why. Re-registering mints
	// one.
	if reg.ConsentNonce == "" {
		return "", fmt.Errorf(
			"%w: this registration carries no consent reference, so no acknowledgement for it could ever be verified",
			ErrInvalidRequest)
	}
	plan, err := s.derivedPlan(ctx, reg)
	if err != nil {
		return "", err
	}
	// consent.ErrConsent travels intact rather than folded into one of this
	// package's sentinels: its causes have different audiences — a reference this
	// deployment did not mint is the caller's, a plan shape the page cannot
	// describe is ours — and flattening them reports a derivation fault as a bad
	// request.
	return consent.Page(plan, reg.ConsentNonce)
}

// Authorize returns the provider's consent URL, and mints the OAuth state itself.
//
// 🔴 IT REFUSES UNLESS Verify PASSES RIGHT NOW — not "was verified once", not "a
// row somewhere says verified". Without a live check the proof is a fact about
// the past, and the customer's first stop control (delete the TXT) would not
// bound the authority about to be granted. Anything short of a resolution at this
// moment is refused, including a lookup that merely failed; checkProof has the
// asymmetry.
//
// 🔴 IT MINTS THE STATE AND DOES NOT ACCEPT ONE, unlike the legacy
// grant.Authorize, which took `state` as a request field — a string the caller
// can also mint for a registration it is not holding. A state sealed here carries
// the lane, the identity, the anchor and a nonce, so Complete needs none of them
// as fields and no pair of requests can be made to disagree.
func (s *Service) Authorize(ctx context.Context, req AuthorizeRequest) (AuthorizeResponse, error) {
	cfg := s.oauthConfig(ctx)
	if cfg == nil {
		return AuthorizeResponse{}, ErrUnavailable
	}
	sealer := s.sealer(ctx)
	if sealer == nil {
		return AuthorizeResponse{}, fmt.Errorf(
			"%w: this deployment holds no keyset, so no authorization state can be sealed", ErrUnavailable)
	}
	reg, err := s.openRegistration(ctx, req.Registration)
	if err != nil {
		return AuthorizeResponse{}, err
	}
	if strings.TrimSpace(req.CodeChallenge) == "" {
		return AuthorizeResponse{}, fmt.Errorf("%w: codeChallenge is required", ErrInvalidRequest)
	}

	check, err := s.checkProof(ctx, reg)
	if err != nil {
		return AuthorizeResponse{}, err
	}
	if !check.published {
		return AuthorizeResponse{}, fmt.Errorf("%w: publish %s IN TXT %q and try again",
			ErrNotProven, check.name, check.expected)
	}

	// The wildcard lane also needs this service's own consent page, because its
	// scope is the one a customer cannot enumerate (see ErrConsentRequired).
	//
	// 🔴 BOTH SIDES OF THE COMPARISON COME OUT OF THE SEAL. The reference is the
	// registration's, minted at register() and never a request field, so the
	// caller supplies one half of a MAC and never both. A registration carrying no
	// reference — sealed by a build without this control — refuses here too,
	// because consent.Verify rejects an empty component rather than MACing over
	// one; the alternative is a wildcard authorized against a value nobody
	// issued.
	acknowledged := false
	if consent.Required(reg.Lane) {
		if !consent.Verify(sealer, reg.ConsentNonce, reg.Anchor, req.ConsentToken) {
			return AuthorizeResponse{}, fmt.Errorf(
				"%w: %s requires this service's consent page to have been served and acknowledged for %q",
				ErrConsentRequired, reg.Lane, reg.Anchor)
		}
		acknowledged = true
	}

	nonce, err := sealed.NewNonce()
	if err != nil {
		return AuthorizeResponse{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	state, err := sealed.SealAuthState(sealer, sealed.AuthState{
		Lane: reg.Lane, Identity: reg.Identity, Anchor: reg.Anchor,
		Nonce: nonce, IssuedAt: time.Now().Unix(), ConsentAck: acknowledged,
	})
	if err != nil {
		return AuthorizeResponse{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return AuthorizeResponse{
		AuthorizationURL: cfg.AuthCodeURL(state,
			oauth2.SetAuthURLParam("code_challenge", req.CodeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		),
		State: state,
	}, nil
}

// Complete exchanges the authorization code, seals the credential, and publishes
// what is knowable at this moment.
//
// 🔴 IT TAKES NO IDENTITY, NO LANE AND NO DOMAIN. All three come out of the
// sealed state, which is what makes Authorize and Complete cryptographically one
// act rather than two requests whose fields are checked against each other.
//
// 🔴 ExpectDigest IS REQUIRED AND AN EMPTY VALUE IS REFUSED, where the legacy
// PublishRequest skips the check when it is absent. It does NOT make the digest a
// bound on the private half — both sides are derived here and the caller was
// handed the value. See the comparison below, and docs/DESIGN.md §4.
func (s *Service) Complete(ctx context.Context, req CompleteRequest) (PassResponse, error) {
	cfg := s.oauthConfig(ctx)
	if cfg == nil {
		return PassResponse{}, ErrUnavailable
	}
	sealer := s.sealer(ctx)
	if sealer == nil {
		return PassResponse{}, fmt.Errorf(
			"%w: this deployment holds no keyset, so no authorization state can be opened", ErrUnavailable)
	}
	if strings.TrimSpace(req.ExpectDigest) == "" {
		return PassResponse{}, fmt.Errorf(
			"%w: expectDigest is required — an integrity check that can be omitted is not one", ErrInvalidRequest)
	}
	want, err := hex.DecodeString(strings.TrimSpace(req.ExpectDigest))
	if err != nil {
		return PassResponse{}, fmt.Errorf("%w: expectDigest is not hex", ErrInvalidRequest)
	}
	if strings.TrimSpace(req.Code) == "" || strings.TrimSpace(req.CodeVerifier) == "" {
		return PassResponse{}, fmt.Errorf("%w: code and codeVerifier are required", ErrInvalidRequest)
	}
	state, err := sealed.OpenAuthState(sealer, req.State)
	if err != nil {
		// sealed.ErrExpired travels intact: "your consent screen went stale, start
		// again" and "this envelope is not ours" need different screens, and only
		// the expired case is NORMAL.
		return PassResponse{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	reg := sealed.Registration{
		Lane: state.Lane, Identity: state.Identity, Anchor: state.Anchor, IssuedAt: state.IssuedAt,
	}
	// Re-checked here as well as in Authorize: a state minted by a build without
	// the consent gate would otherwise still complete, and the acknowledgement is
	// inside the seal so a later check can rely on it.
	if consent.Required(reg.Lane) && !state.ConsentAck {
		return PassResponse{}, fmt.Errorf(
			"%w: this authorization was minted without an acknowledged consent page", ErrConsentRequired)
	}

	plan, err := s.derivedPlan(ctx, reg)
	if err != nil {
		return PassResponse{}, err
	}
	review, err := reviewSnapshot(reg.Lane, reg.Identity, plan)
	if err != nil {
		return PassResponse{}, err
	}
	// 🔴 THIS RUNS BEFORE THE EXCHANGE: a plan that does not reproduce what the
	// customer reviewed is refused while the authorization code is still unspent
	// and no credential exists.
	//
	// 🔴 AND IT IS NOT THE CROSS-BOUNDARY CONTROL IT LOOKS LIKE. Both sides are
	// derived here from the sealed registration, and the caller was HANDED the
	// digest it sends back — this is derive(reg) against derive(reg). It catches a
	// plan that drifted between registration and completion, and a bug in the
	// private half; it does not bound the private half, because nothing the
	// customer signed enters it. docs/DESIGN.md §4 says the same at more length.
	//
	// It is two checks and two different screens. Validate is asked against the
	// snapshot's OWN digest, so all it can refuse is the snapshot itself — a
	// record outside the anchor, an unnormalized row, a broken envelope — which is
	// plan_invalid: a bug, where retrying cannot help. A well-formed plan whose
	// digest no longer matches the reviewed one is the opposite answer, and the
	// remedy is to re-render and ask again. Reporting that as plan_invalid tells a
	// caller a stale screen is a defect, and a caller that believes it may give up
	// on the domain permanently.
	digest := review.Digest()
	if err := review.Validate(digest); err != nil {
		slog.Error("intent: refusing a plan that does not describe a publishable set",
			"lane", reg.Lane, "anchor", reg.Anchor, "error", err)
		return PassResponse{}, err
	}
	if !bytes.Equal(digest, want) {
		slog.Warn("intent: the reviewed digest no longer reproduces",
			"lane", reg.Lane, "anchor", reg.Anchor,
			"reviewed", hex.EncodeToString(want), "derived", hex.EncodeToString(digest))
		return PassResponse{}, fmt.Errorf(
			"%w: the plan derived now does not reproduce the digest the customer reviewed; re-render the plan and authorize again",
			dnsplan.ErrPlanChanged)
	}

	out := PassResponse{
		Records:      recordViews(plan.Items),
		Digest:       hex.EncodeToString(digest),
		GrantSeconds: grantSeconds(reg.Lane),
	}
	// The ownership proof is re-checked here too, not only at Authorize: the state
	// is a ten-minute receipt of that check (see sealed.OpenAuthState), and
	// DESIGN §8 promises no window in which we are still writing and the customer
	// has already said no. Ten minutes is such a window; this closes it.
	check, warning, err := s.proofBeforeWriting(ctx, reg)
	if err != nil {
		return PassResponse{}, err
	}
	if warning != "" {
		out.Warnings = append(out.Warnings, warning)
	}
	if check.withdrawn {
		return stopped(out, check), nil
	}

	merged, warnings := s.relayInto(ctx, plan)
	out.Warnings = append(out.Warnings, warnings...)
	out.Records = recordViews(merged.Items)
	write, failure, err := writeSnapshot(reg, review, merged)
	if err != nil {
		return PassResponse{}, err
	}
	if failure != nil {
		out.Result, out.Failure = ResultDeferred, failure
		return out, nil
	}

	token, err := s.exchange(ctx, cfg, req.Code, req.CodeVerifier)
	if err != nil {
		// The code is single-use and now spent, but no token was ever issued, so
		// there is nothing to persist and nothing to revoke. This is the one
		// post-boundary case that stays an RPC error, as in internal/grant.
		return PassResponse{}, fmt.Errorf("%w: exchange authorization code: %w", ErrUnavailable, err)
	}
	s.write(ctx, cfg, reg, token, false, write, &out)
	return out, nil
}

// Advance is one pass of the loop, and the only function that writes after the
// first publish: it re-derives the record set, re-checks the ownership proof,
// asks AWS and Cloudflare whether the records they owe have appeared, and
// publishes whatever is missing.
//
// 🔴 IF THE PROOF IS GONE IT WRITES NOTHING AND SAYS SO. That is the customer's
// stop control (DESIGN §8): effective within ONE pass, with nothing needing to
// reach MirrorStack — no API call, no support ticket, no console visit. The grant
// is not even opened, so the pass does not touch their provider at all.
func (s *Service) Advance(ctx context.Context, req AdvanceRequest) (PassResponse, error) {
	reg, err := s.openRegistration(ctx, req.Registration)
	if err != nil {
		return PassResponse{}, err
	}
	plan, err := s.derivedPlan(ctx, reg)
	if err != nil {
		return PassResponse{}, err
	}
	return s.pass(ctx, reg, plan, req.SealedToken)
}

// pass is the whole of Advance and of BindApp's published/manual split. The order
// is deliberate: every step before the credential is a refusal that consumes
// nothing.
//
//	proof → relay → containment and digest → credential → seal → publish
func (s *Service) pass(
	ctx context.Context, reg sealed.Registration, plan derive.Plan, sealedToken string,
) (PassResponse, error) {
	cfg := s.oauthConfig(ctx)
	if cfg == nil {
		return PassResponse{}, ErrUnavailable
	}
	review, err := reviewSnapshot(reg.Lane, reg.Identity, plan)
	if err != nil {
		return PassResponse{}, err
	}
	out := PassResponse{
		Records:      recordViews(plan.Items),
		Digest:       hex.EncodeToString(review.Digest()),
		GrantSeconds: grantSeconds(reg.Lane),
	}

	check, warning, err := s.proofBeforeWriting(ctx, reg)
	if err != nil {
		return PassResponse{}, err
	}
	if warning != "" {
		out.Warnings = append(out.Warnings, warning)
	}
	if check.withdrawn {
		return stopped(out, check), nil
	}

	merged, warnings := s.relayInto(ctx, plan)
	out.Warnings = append(out.Warnings, warnings...)
	out.Records = recordViews(merged.Items)
	write, failure, err := writeSnapshot(reg, review, merged)
	if err != nil {
		return PassResponse{}, err
	}
	if failure != nil {
		out.Result, out.Failure = ResultDeferred, failure
		return out, nil
	}

	token, rotated, grantFailure := s.resolveGrant(ctx, cfg, reg, sealedToken)
	if token == nil {
		// The manual path. Nothing was written and nothing is wrong: the records
		// are already in out.Records, the same bytes we would have published,
		// because there is one derivation for both paths.
		out.Failure = grantFailure
		out.Result = ResultManual
		if grantFailure != nil && grantFailure.Retry {
			// A provider we could not reach is not a customer without a grant
			// (see ResultDeferred).
			out.Result = ResultDeferred
		}
		return out, nil
	}
	s.write(ctx, cfg, reg, token, rotated, write, &out)
	return out, nil
}

// Describe is read-only, needs no credential, and is the single source for what a
// console shows — so the screen and the writer cannot drift apart.
//
// 🔴 THE OWNERSHIP ROW IS JUDGED SEPARATELY, AND SKIPPING THAT IS A BUG WITH NO
// ERROR IN IT. observe.Plan refuses to decide the proof: the derived item carries
// the value under TODAY's active key, while verification accepts one value per
// key in the keyset, so a proof published months ago under a since-rotated key is
// valid and would be reported absent — contradicting Verify on the one record
// everything hangs from, and telling a customer whose domain works to fix a
// record that is fine.
func (s *Service) Describe(ctx context.Context, req DescribeRequest) (DescribeResponse, error) {
	reg, err := s.openRegistration(ctx, req.Registration)
	if err != nil {
		return DescribeResponse{}, err
	}
	plan, err := s.derivedPlan(ctx, reg)
	if err != nil {
		return DescribeResponse{}, err
	}
	merged, warnings := s.relayInto(ctx, plan)
	review, err := reviewSnapshot(reg.Lane, reg.Identity, plan)
	if err != nil {
		return DescribeResponse{}, err
	}
	out := DescribeResponse{
		Lane:         string(reg.Lane),
		Anchor:       reg.Anchor,
		Hosts:        merged.Hosts,
		Digest:       hex.EncodeToString(review.Digest()),
		GrantSeconds: grantSeconds(reg.Lane),
		Warnings:     warnings,
	}
	if s.Resolver == nil {
		return DescribeResponse{}, fmt.Errorf("%w: this deployment has no DNS resolver", ErrUnavailable)
	}
	observations, err := observe.Plan(ctx, s.Resolver, merged)
	if err != nil {
		// A plan this service will not observe is one it should not have derived —
		// a record outside the anchor, or a type it does not publish. Reporting
		// around it would put a line in front of a customer that we have no
		// business managing.
		return DescribeResponse{}, err
	}

	check, proofErr := s.checkProof(ctx, reg)
	if proofErr != nil {
		// Describe is the tool somebody reaches for BECAUSE something is not
		// working, so a resolver failure degrades it rather than failing it: the
		// proof row stays `unknown`, visibly incomplete rather than confidently
		// wrong.
		out.Warnings = append(out.Warnings, fmt.Sprintf("the ownership proof could not be read: %v", proofErr))
	}
	out.Verified = check.published

	views := make([]RecordView, 0, len(merged.Items))
	for i, item := range merged.Items {
		if item.Purpose == derive.PurposeOwnership {
			view := observedView(item, check.observation)
			out.Proof = view
			views = append(views, view)
			continue
		}
		views = append(views, observedView(item, observations[i]))
	}
	out.Records = views
	return out, nil
}

// Orphans reports what this service left behind when a domain is removed.
//
// A report, never a mutation, and the type system says so: the provider is
// reached through zoneReader, which has no create and no patch, and there is no
// delete anywhere in this service to reach in the first place.
//
// It prefers the customer's own zone, read with their grant, and falls back to
// public DNS whenever no usable grant exists, so the report still works for a
// customer who never authorized or has revoked. Using the grant ROTATES it, so
// the rotated envelope comes back in the response and must be persisted.
func (s *Service) Orphans(ctx context.Context, req OrphansRequest) (OrphansResponse, error) {
	reg, err := s.openRegistration(ctx, req.Registration)
	if err != nil {
		return OrphansResponse{}, err
	}
	plan, err := s.derivedPlan(ctx, reg)
	if err != nil {
		return OrphansResponse{}, err
	}
	merged, warnings := s.relayInto(ctx, plan)
	out := OrphansResponse{
		Anchor: reg.Anchor,
		// Always true; see the field.
		Incomplete: true,
		Warnings:   warnings,
	}

	cfg := s.oauthConfig(ctx)
	var token *oauth2.Token
	if cfg != nil && strings.TrimSpace(req.SealedToken) != "" {
		var rotated bool
		var failure *Failure
		token, rotated, failure = s.resolveGrant(ctx, cfg, reg, req.SealedToken)
		out.Rotated, out.Failure = rotated, failure
		if token != nil {
			// Seal before reading, for the same reason write() seals before
			// publishing: the refresh already rotated the caller's copy, and a read
			// that fails afterwards must not take the replacement with it.
			envelope, keyID, sealErr := s.sealGrant(ctx, token, reg)
			if sealErr == nil {
				out.SealedToken, out.KeyID = envelope, keyID
			} else {
				// 🔴 A SEALING FAILURE HERE IS THE 2026-08-24 FAILURE, IN A
				// FUNCTION THAT ONLY READS. The refresh above rotated the grant,
				// so the caller's stored token is already dead; if the replacement
				// cannot be sealed there is nothing to hand back, and a report
				// saying rotated:true with an empty sealedToken and no failure
				// would leave a LIVE grant at the provider that nothing in
				// MirrorStack can ever release. Dropping sealErr is how that
				// happens silently — so it is logged, the grant is ended where it
				// lives, and the response says so, the same three steps write()
				// takes.
				slog.Warn("intent: could not seal the delegated grant while reporting orphans; revoking instead of holding",
					"lane", reg.Lane, "anchor", reg.Anchor, "error", sealErr)
				s.revokeToken(ctx, cfg, token, reg, "the grant could not be held")
				out.Revoked = true
				out.Failure = &Failure{
					Code: FailureResealFailed, Retry: false,
					Message: "the rotated grant could not be held, so it has been revoked; this report is from public DNS",
				}
				// And it is not used to read afterwards: a credential just ended
				// is not one to spend a request on, and the public-DNS path below
				// is a complete answer — what every customer who never authorized
				// already gets.
				token = nil
			}
		}
	}

	if token != nil {
		views, readErr := s.readZone(ctx, token.AccessToken, merged)
		if readErr == nil {
			out.ReadThrough = "provider"
			out.Records = views
			return out, nil
		}
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"the zone could not be read with the delegated grant, so this report is from public DNS: %v", readErr))
	}

	out.ReadThrough = "public-dns"
	if s.Resolver == nil {
		return OrphansResponse{}, fmt.Errorf("%w: this deployment has no DNS resolver", ErrUnavailable)
	}
	observations, err := observe.Plan(ctx, s.Resolver, merged)
	if err != nil {
		return OrphansResponse{}, err
	}
	views := make([]RecordView, 0, len(merged.Items))
	for i, item := range merged.Items {
		views = append(views, observedView(item, observations[i]))
	}
	out.Records = views
	return out, nil
}

// Release revokes a held grant at the provider, refresh token first: revoking
// that kills the whole grant, where revoking only the access token leaves a
// credential that can mint another.
//
// 🔴 AN ENVELOPE THAT CANNOT BE OPENED IS REPORTED AS SUCH AND NEVER GUESSED AT.
// There is no fallback trying other keys, anchors or identities: a "helpful"
// guess is a request to revoke a credential we cannot prove is the one this row
// holds. The response says unreadable, the log says REVOKE BY HAND, and a person
// decides.
func (s *Service) Release(ctx context.Context, req ReleaseRequest) (ReleaseResponse, error) {
	cfg := s.oauthConfig(ctx)
	if cfg == nil {
		return ReleaseResponse{}, ErrUnavailable
	}
	reg, err := s.openRegistration(ctx, req.Registration)
	if err != nil {
		return ReleaseResponse{}, err
	}
	sealer := s.sealer(ctx)
	if sealer == nil {
		slog.Error("intent: a held grant cannot be opened without a keyset — REVOKE BY HAND",
			"lane", reg.Lane, "anchor", reg.Anchor, "reason", req.Reason)
		return ReleaseResponse{Unreadable: true}, nil
	}
	refresh, err := sealer.Open(req.SealedToken, GrantAAD(reg))
	if err != nil {
		slog.Error("intent: a held grant could not be opened for release — REVOKE BY HAND",
			"lane", reg.Lane, "anchor", reg.Anchor, "reason", req.Reason)
		return ReleaseResponse{Unreadable: true}, nil
	}
	s.revokeToken(ctx, cfg, &oauth2.Token{RefreshToken: refresh}, reg, req.Reason)
	return ReleaseResponse{Revoked: true}, nil
}

// ─── the ownership gate ─────────────────────────────────────────────────────

// proofCheck is what public DNS says about the one record everything hangs from.
type proofCheck struct {
	name        string
	expected    string
	observation observe.Observation

	// published means the proof resolved and matched one of the accepted values.
	published bool

	// withdrawn means public DNS gave a DEFINITE answer and the proof was not in
	// it. Not the negation of published: a lookup that did not complete is
	// neither.
	withdrawn bool
}

// checkProof resolves the ownership proof for a registration.
//
// 🔴 THE ASYMMETRY BETWEEN published AND withdrawn IS DELIBERATE IN BOTH
// DIRECTIONS. GRANTING authority requires a positive answer: Authorize refuses
// unless the proof resolved and matched right now, so a SERVFAIL, a timeout or an
// empty answer all mean "not yet". CONTINUING to exercise authority stops only on
// a NEGATIVE answer: a registration is stopped on an answer, never on a failure
// to get one. Folding "unknown" into "withdrawn" would make a nameserver blip
// indistinguishable from a customer saying no, and the loop would eventually
// release a live credential over a fault that was ours.
func (s *Service) checkProof(ctx context.Context, reg sealed.Registration) (proofCheck, error) {
	out := proofCheck{name: proof.Name(reg.Anchor)}
	if out.name == "" {
		// The anchor is over 230 bytes, so the challenge name would not be a legal
		// DNS name. derive refuses such a registration outright; this is the guard
		// on the path that opens a stored one.
		return out, fmt.Errorf("%w: %q is too deep to carry an ownership proof", ErrInvalidRequest, reg.Anchor)
	}
	prover, err := s.prover(ctx)
	if err != nil {
		return out, err
	}
	accepted, err := prover.Accepted(reg.Lane, reg.Identity, reg.Anchor)
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	// Computed for the response, not for the comparison: that is against the whole
	// accept set, so a rotation does not invalidate a value a customer published
	// months ago and has no reason to revisit.
	out.expected, err = prover.Expected(reg.Lane, reg.Identity, reg.Anchor)
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if s.Resolver == nil {
		return out, fmt.Errorf("%w: this deployment has no DNS resolver, so no proof can be verified", ErrUnavailable)
	}
	ok, obs, err := observe.Proof(ctx, s.Resolver, out.name, accepted)
	out.observation = obs
	out.published = ok
	out.withdrawn = obs.State == observe.StateAbsent
	return out, err
}

// stopped is the response for a registration whose proof has been withdrawn.
// Nothing was written, no credential was opened, and the remedy is the
// customer's: republish the TXT and the next pass continues.
func stopped(out PassResponse, check proofCheck) PassResponse {
	out.Result = ResultStopped
	out.Failure = &Failure{
		Code:  FailureProofWithdrawn,
		Retry: true,
		Message: fmt.Sprintf(
			"the ownership proof at %s does not resolve, so nothing was written. Republish %q there to continue.",
			check.name, check.expected),
	}
	return out
}

// proofBeforeWriting resolves the ownership proof for a pass that is about to
// publish, and decides whether the pass may continue at all.
//
// 🔴 A PASS THAT COULD NOT LOOK MUST NOT WRITE.
//
// checkProof fails for four reasons and only ONE is an answer about the world: a
// resolver that timed out or SERVFAILed degrades to a warning and the pass
// proceeds on the anchor proven at authorize time — the one place DESIGN §8
// admits a failure does not fail closed.
//
// The other three — no keyset, no resolver wired, an accept set we could not
// compute — mean this service was never in a position to ask. Publishing on those
// makes the customer's stop control silently inoperative: they delete the
// ownership proof, we never read it, and the records come back on every pass with
// nothing but a warning string inside a `published` response to say so.
//
// Describe takes the opposite branch: it writes nothing, so a report with an
// `unknown` proof row beats no report.
func (s *Service) proofBeforeWriting(ctx context.Context, reg sealed.Registration) (proofCheck, string, error) {
	check, err := s.checkProof(ctx, reg)
	switch {
	case err == nil:
		return check, "", nil
	case lookupFailed(err):
		return check, fmt.Sprintf("the ownership proof could not be read: %v", err), nil
	default:
		// Returning the zero proofCheck matters: withdrawn is false on it, and a
		// caller that ignored this error would fall through to the publish.
		return proofCheck{}, "", err
	}
}

// lookupFailed reports an error that belongs to the RESOLVER rather than to us.
//
// Everything this service could have got wrong is one of three sentinels: no
// keyset or no resolver wired (ErrUnavailable), an anchor too deep to carry a
// proof (ErrInvalidRequest), or a malformed observation request, including a
// keyset that produced no accepted value at all (observe.ErrObserve). Those stay
// RPC errors: a report about the customer's zone from a service that was not in a
// position to look is not a report. What is left is a well-formed lookup that did
// not come back.
func lookupFailed(err error) bool {
	return err != nil &&
		!errors.Is(err, ErrUnavailable) &&
		!errors.Is(err, ErrInvalidRequest) &&
		!errors.Is(err, observe.ErrObserve)
}

// ─── derivation, relay and the two snapshots ────────────────────────────────

func (s *Service) openRegistration(ctx context.Context, envelope string) (sealed.Registration, error) {
	sealer := s.sealer(ctx)
	if sealer == nil {
		return sealed.Registration{}, fmt.Errorf(
			"%w: this deployment holds no keyset, so no registration can be opened", ErrUnavailable)
	}
	reg, err := sealed.OpenRegistration(sealer, envelope)
	if err != nil {
		return sealed.Registration{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	return reg, nil
}

// derivedPlan re-derives a registration's records from the three sealed facts and
// this deployment's configuration. Nothing is read back from storage, because
// there is none: the certificate id, the custom-hostname id and the
// published-record cursor were deleted from the model (DESIGN §7).
func (s *Service) derivedPlan(ctx context.Context, reg sealed.Registration) (derive.Plan, error) {
	prover, err := s.prover(ctx)
	if err != nil {
		return derive.Plan{}, err
	}
	value, err := prover.Expected(reg.Lane, reg.Identity, reg.Anchor)
	if err != nil {
		return derive.Plan{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	plan, err := s.Derive.Registration(reg.Lane, reg.Identity, reg.Anchor, value)
	if err != nil {
		return derive.Plan{}, deriveError(err)
	}
	return plan, nil
}

// deriveError splits a derivation refusal by AUDIENCE: an incomplete routing
// configuration is an operator's problem and reports as unavailable, a domain
// that cannot be connected is the caller's and reports as an invalid request.
// derive.ErrConfig wraps derive.ErrDerive, so the narrower test comes first.
func deriveError(err error) error {
	if errors.Is(err, derive.ErrConfig) {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if errors.Is(err, derive.ErrDerive) {
		return fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	return err
}

// relayInto merges the records AWS and Cloudflare owe into a derived plan.
//
// 🔴 A RELAY FAILURE IS A WARNING, NOT A REFUSAL. Record 6 — the DCV pointer — is
// derived here and is what gets the CLOUDFLARE EDGE certificate issued, so a lane
// still gets TLS at the edge while ACM is unreadable. Lane 1's AWS certificate is
// a SECOND certificate and does not validate until record 5 is relayed; until
// then that lane is served at the edge and is not complete. Blocking record 6 on
// an ACM read failure would couple the fast path to the slow one and leave a
// domain unrouted over a permission problem on our side. So the pass publishes
// what it can and says what it could not read; swallowing the error would make a
// relay broken for a week indistinguishable from an upstream that is merely
// slow.
func (s *Service) relayInto(ctx context.Context, plan derive.Plan) (derive.Plan, []string) {
	var warnings []string
	items := append(make([]derive.Item, 0, len(plan.Items)+len(plan.Hosts)*2), plan.Items...)

	if hosts := plan.Lane.CertificateHosts(plan.Anchor); len(hosts) > 0 {
		records, err := relay.ValidationRecords(ctx, s.Certificates, hosts)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("the certificate authority could not be read: %v", err))
		}
		for _, record := range records {
			host := hostFor(hosts, record.Name)
			items = append(items, derive.Item{
				Record: record, Purpose: derive.PurposeCertACM, Source: derive.SourceRelayed, Host: host,
				Explain: fmt.Sprintf(
					"Amazon chose this name and this value when it issued the certificate for %s. Deleting it does not take anything down today; the certificate stops renewing and %s fails months later, with nothing in your zone looking wrong.",
					host, host),
			})
		}
	}

	if hosts := servingHosts(plan); len(hosts) > 0 {
		records, err := relay.ServingProofs(ctx, s.Edge, plan.Lane, hosts)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("the edge could not be read: %v", err))
		}
		for _, record := range records {
			host := hostFor(hosts, record.Name)
			items = append(items, derive.Item{
				Record: record, Purpose: derive.PurposeServing, Source: derive.SourceRelayed, Host: host,
				Explain: fmt.Sprintf(
					"Cloudflare checks this before it will serve %s through MirrorStack. Its absence is not a DNS failure: the name resolves and then answers with an edge error, which is why it is listed apart from the certificate records.",
					host),
			})
		}
	}

	plan.Items = items
	return plan, warnings
}

// servingHosts are the hostnames Cloudflare mints a serving proof for.
//
// Every lane owes record 7, but a WILDCARD is not a custom hostname on this
// account (an Enterprise feature), so `*.<anchor>` is skipped: that lane's proofs
// are minted per app at deploy time by BindAppToOrgAppDomain, whose plan names a
// concrete host and reaches this same function.
func servingHosts(plan derive.Plan) []string {
	out := make([]string, 0, len(plan.Hosts))
	for _, host := range plan.Hosts {
		if strings.Contains(host, "*") {
			continue
		}
		out = append(out, host)
	}
	return out
}

// hostFor picks the hostname a relayed record serves: the most specific one it
// sits at or under. `_acme-challenge.api.example.com` serves `api.example.com`,
// not `example.com`, and a console groups by that.
func hostFor(hosts []string, name string) string {
	best := ""
	for _, host := range hosts {
		if dnsplan.Contains(host, name) && len(host) > len(best) {
			best = host
		}
	}
	return best
}

// publishable is the record set this service may WRITE.
//
// 🔴 THE OWNERSHIP RECORD IS NEVER IN IT, AND A REGRESSION HERE SILENTLY RESTORES
// THE EXACT DEFECT THIS REBUILD EXISTS TO FIX: a proof we publish ourselves
// proves nothing.
//
// derive.Plan.Publishable is an allow-list on SourceDerived/SourceRelayed and
// already excludes it. This function does not repeat that filter — two copies of
// one filter drift, and the looser copy is the one that writes — it REFUSES the
// whole plan if anything owed by the customer turns up in the result, matched on
// (type, name) so a drifted value is caught as well as a drifted source.
func publishable(plan derive.Plan) ([]dnsplan.Record, error) {
	records := plan.Publishable()
	for _, owed := range plan.Manual() {
		for _, record := range records {
			if strings.EqualFold(record.Type, owed.Record.Type) &&
				dnsplan.NormalizeName(record.Name) == dnsplan.NormalizeName(owed.Record.Name) {
				slog.Error("intent: refusing a plan that would publish a record the CUSTOMER owes",
					"name", dnsplan.NormalizeName(record.Name), "type", record.Type, "anchor", plan.Anchor)
				return nil, fmt.Errorf(
					"%w: %s %q is the customer's to publish and must never be written by this service",
					dnsplan.ErrPlanInvalid, record.Type, dnsplan.NormalizeName(record.Name))
			}
		}
	}
	return records, nil
}

// snapshotKind maps a lane onto dnsplan's coarse binding.
//
// dnsplan predates the lanes and knows two kinds: lane 1 is the org's own
// platform, the other two both serve an application. Nothing is lost by the
// merge, because the lane lives in the sealed registration and inside the
// ownership HMAC, and the digest covers the anchor and the records. An
// unrecognised lane maps to the empty string, which dnsplan.NewSnapshot refuses.
func snapshotKind(l lane.Lane) string {
	switch l {
	case lane.OrgPlatformDomain:
		return dnsplan.KindPlatform
	case lane.OrgAppDomain, lane.AppDomain:
		return dnsplan.KindApp
	}
	return ""
}

// reviewSnapshot is the plan the CUSTOMER reviews, and the digest they consent
// to.
//
// It covers the DERIVED publishable records only: a relayed record's bytes do not
// exist at review time, so including them would move the digest between authorize
// and complete and tell every customer mid-connect that the plan had changed.
//
// The snapshot's TargetID is the registration's IDENTITY: this service holds no
// row id and §5 gives it no field to receive one, so the identity is the only
// canonical UUID in scope, and the right one — it binds the digest to WHOSE
// domain this is.
func reviewSnapshot(l lane.Lane, identity string, plan derive.Plan) (dnsplan.Snapshot, error) {
	records, err := publishable(plan)
	if err != nil {
		return dnsplan.Snapshot{}, err
	}
	return dnsplan.NewSnapshot(snapshotKind(l), identity, plan.Anchor, records)
}

// writeSnapshot is what actually goes to the provider: the reviewed set plus
// whatever the upstreams have produced since.
//
// 🔴 EVERY RECORD THIS SERVICE PUBLISHES GOES THROUGH dnsplan.NewSnapshot AND
// THEN reconcile.Publisher, WITH NO PATH AROUND EITHER. NewSnapshot enforces
// anchor containment and computes the digest; the Publisher is where
// never-delete, read-before-write, never-take-a-name-in-use and the bounded
// window live.
//
// It also asserts the reviewed plan is still COVERED by the write set, which may
// have GROWN — that is what a later pass is for — but never shrink or mutate,
// which would be a plan the customer did not see.
//
// 🔴 BE HONEST ABOUT WHAT THAT ASSERTION CURRENTLY CATCHES: NOTHING. On every
// path today, review and the write set are derived in the same call from the same
// plan and relayInto only APPENDS, so the containment holds by construction and
// the check cannot fire. It is here for the edit not yet made: the day something
// filters the merged set, or derives the two halves from different plans, this is
// what refuses. A reader must not come away thinking it catches a live drift
// between the consent screen and the write.
//
// A plan that is not publishable yet comes back as a Failure rather than an
// error: a wait, not a fault.
func writeSnapshot(
	reg sealed.Registration, review dnsplan.Snapshot, merged derive.Plan,
) (dnsplan.Snapshot, *Failure, error) {
	records, err := publishable(merged)
	if err != nil {
		return dnsplan.Snapshot{}, nil, err
	}
	write, err := dnsplan.NewSnapshot(snapshotKind(reg.Lane), reg.Identity, reg.Anchor, records)
	if err != nil {
		if errors.Is(err, dnsplan.ErrPlanPreparing) {
			return dnsplan.Snapshot{}, &Failure{
				Code: FailurePlanPreparing, Retry: true, Message: err.Error(),
			}, nil
		}
		return dnsplan.Snapshot{}, nil, err
	}
	if !review.CoveredBy(write) {
		slog.Error("intent: refusing a write set that does not cover the reviewed plan",
			"lane", reg.Lane, "anchor", reg.Anchor)
		return dnsplan.Snapshot{}, nil, fmt.Errorf(
			"%w: the records to be written no longer cover the reviewed plan", dnsplan.ErrPlanChanged)
	}
	return write, nil, nil
}

// ─── the credential half ────────────────────────────────────────────────────

// GrantAAD binds a sealed refresh token to the registration that holds it.
//
// 🔴 WITHOUT IT A CIPHERTEXT MOVES BETWEEN REGISTRATIONS. A sealed token lifted
// from one org's grant and pasted into another's row would decrypt perfectly and
// hand the second a live write credential on the first's zone — by a database
// write alone, in a store this service does not own.
//
// 🔴 THE LANE IS IN IT, WHICH internal/grant's VERSION HAD NO WAY TO DO. One org
// can connect the same domain on two lanes: two consents, two ownership proofs,
// two grants. Without the lane, a grant obtained for the wildcard lane would open
// in the platform lane's row.
//
// It takes the opened Registration rather than three strings: the only way to
// hold one is to have opened an envelope this service sealed, so a caller cannot
// choose the binding — and one that could choose it could unbind it.
func GrantAAD(reg sealed.Registration) string {
	return "ms-dns-grant/v1\x00" + string(reg.Lane) + "\x00" + reg.Identity + "\x00" + reg.Anchor
}

// resolveGrant opens the held grant and refreshes it.
//
// A nil token is the MANUAL path and the Failure says which kind: no grant
// supplied (the ordinary state of a customer who never authorized), an envelope
// that could not be opened, a provider that rejected it, or one that could not be
// reached. Only the last is retryable: confusing "dead" with "unreachable" either
// strands a customer or destroys a working grant.
func (s *Service) resolveGrant(
	ctx context.Context, cfg *cfoauth.Config, reg sealed.Registration, sealedToken string,
) (*oauth2.Token, bool, *Failure) {
	if strings.TrimSpace(sealedToken) == "" {
		return nil, false, &Failure{
			Code: FailureNoGrant, Retry: false,
			Message: "no delegated grant is held for this domain, so nothing was written",
		}
	}
	sealer := s.sealer(ctx)
	if sealer == nil {
		return nil, false, &Failure{
			Code: FailureTokenUnreadable, Retry: false,
			Message: "this deployment holds no keyset, so a sealed grant cannot be opened",
		}
	}
	refresh, err := sealer.Open(sealedToken, GrantAAD(reg))
	if err != nil {
		return nil, false, &Failure{
			Code: FailureTokenUnreadable, Retry: false,
			Message: "the sealed grant could not be opened for this registration",
		}
	}
	token, err := s.refresh(ctx, cfg, refresh)
	if err != nil {
		if isInvalidGrant(err) {
			return nil, false, &Failure{
				Code: FailureInvalidGrant, Retry: false,
				Message: "the provider rejected the refresh token",
			}
		}
		return nil, false, &Failure{
			Code: FailureProvider, Retry: true,
			Message: "the delegated grant could not be refreshed",
		}
	}
	return token, token.RefreshToken != "" && token.RefreshToken != refresh, nil
}

// write seals the credential and publishes. It is the ONLY place in this package
// that reaches reconcile.Publisher.
//
// 🔴 SEAL BEFORE PUBLISHING, NOT AFTER. The provider rotates the refresh token on
// every use, so once the refresh above returned, the caller's stored token is
// ALREADY DEAD. If the publish below fails and this response carries no
// replacement, the grant kills itself on the next pass — measured 2026-08-24: the
// first pass returned early on a preparing plan without storing the rotated
// token, and the second pass found a token the provider had already replaced.
// That is why every failure from here on is reported in the response and never as
// an RPC error.
func (s *Service) write(
	ctx context.Context, cfg *cfoauth.Config, reg sealed.Registration,
	token *oauth2.Token, rotated bool, snapshot dnsplan.Snapshot, out *PassResponse,
) {
	out.Result = ResultPublished
	out.Rotated = rotated

	envelope, keyID, sealErr := s.sealGrant(ctx, token, reg)
	if sealErr == nil {
		out.SealedToken, out.KeyID = envelope, keyID
	}

	if err := s.Publisher.Publish(ctx, token.AccessToken, snapshot); err != nil {
		out.Result = ResultDeferred
		out.Failure = publishFailure(err)
		if out.SealedToken == "" {
			// A grant nobody recorded must not be left alive at the provider:
			// nothing would ever release it.
			s.revokeToken(ctx, cfg, token, reg, "the grant could not be held")
			out.Revoked = true
		}
		return
	}
	out.Published = snapshot.Identities

	if out.SealedToken == "" {
		slog.Warn("intent: could not seal the delegated grant; revoking instead of holding",
			"lane", reg.Lane, "anchor", reg.Anchor, "error", sealErr)
		s.revokeToken(ctx, cfg, token, reg, "the grant could not be held")
		out.Revoked = true
		out.Failure = &Failure{
			Code: FailureResealFailed, Retry: false,
			Message: "the records published but the grant could not be held; it has been revoked",
		}
	}
}

func (s *Service) sealGrant(ctx context.Context, token *oauth2.Token, reg sealed.Registration) (string, string, error) {
	if token == nil || token.RefreshToken == "" {
		return "", "", errors.New("intent: the provider returned no refresh token")
	}
	sealer := s.sealer(ctx)
	if sealer == nil {
		return "", "", grantcrypto.ErrNoKeyset
	}
	return sealer.Seal(token.RefreshToken, GrantAAD(reg))
}

func (s *Service) exchange(ctx context.Context, cfg *cfoauth.Config, code, verifier string) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, s.httpClient())
	return cfg.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
}

func (s *Service) refresh(ctx context.Context, cfg *cfoauth.Config, refreshToken string) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, s.httpClient())
	return cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
}

// isInvalidGrant reports the provider saying the refresh token is dead — the one
// refresh failure that must NOT be retried: the grant will never come back.
func isInvalidGrant(err error) bool {
	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) {
		if retrieveErr.ErrorCode == "invalid_grant" {
			return true
		}
		// Some providers answer 400 with a body oauth2 does not parse into
		// ErrorCode. A 400/401 on a refresh is a rejected credential either way;
		// 5xx and transport failures are not.
		return retrieveErr.Response != nil &&
			(retrieveErr.Response.StatusCode == http.StatusBadRequest ||
				retrieveErr.Response.StatusCode == http.StatusUnauthorized)
	}
	return false
}

func publishFailure(err error) *Failure {
	switch {
	case errors.Is(err, dnsplan.ErrAnchorEscape), errors.Is(err, dnsplan.ErrPlanInvalid),
		errors.Is(err, reconcile.ErrConflictingPlan), errors.Is(err, reconcile.ErrNoRecords):
		// A plan defect. Retrying the same plan cannot help.
		return &Failure{Code: FailureProvider, Retry: false, Message: err.Error()}
	case errors.Is(err, reconcile.ErrNameInUse):
		// The customer is serving something else from a name in the plan. Only they
		// can decide it should go, so a retry changes nothing until they do — but
		// it is not a dead grant either.
		return &Failure{Code: FailureProvider, Retry: false, Message: err.Error()}
	case errors.Is(err, dnsplan.ErrPlanPreparing):
		return &Failure{Code: FailurePlanPreparing, Retry: true, Message: err.Error()}
	default:
		// 🔴 EVERYTHING UNKNOWN IS RETRYABLE. Defaulting to "dead" would release a
		// working customer credential over a transient provider blip, and a
		// released grant cannot be recovered without sending the customer back
		// through consent.
		return &Failure{Code: FailureProvider, Retry: true, Message: err.Error()}
	}
}

// revokeToken ends a grant at the provider, refresh token first: that kills the
// whole grant, where revoking only the access token leaves a credential that can
// mint another.
//
// Every failure is a precise log line and nothing else: the caller has already
// succeeded or failed on its own terms, and a failed revocation is an operator
// task.
func (s *Service) revokeToken(
	ctx context.Context, cfg *cfoauth.Config, token *oauth2.Token, reg sealed.Registration, reason string,
) {
	if token == nil || cfg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	client := s.httpClient()
	for _, t := range []struct{ value, hint string }{
		{token.RefreshToken, "refresh_token"},
		{token.AccessToken, "access_token"},
	} {
		if t.value == "" {
			continue
		}
		form := url.Values{"token": {t.value}, "token_type_hint": {t.hint}}
		if cfg.AuthMethod != cfoauth.AuthNone {
			form.Set("client_id", cfg.ClientID)
			form.Set("client_secret", cfg.ClientSecret)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.RevokeURL, strings.NewReader(form.Encode()))
		if err != nil {
			slog.Error("intent: token revocation could not be built — REVOKE BY HAND",
				"lane", reg.Lane, "anchor", reg.Anchor, "token_type", t.hint, "reason", reason, "error", err)
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			slog.Error("intent: token revocation failed — REVOKE BY HAND",
				"lane", reg.Lane, "anchor", reg.Anchor, "token_type", t.hint, "reason", reason, "error", err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			slog.Error("intent: the provider rejected token revocation — REVOKE BY HAND",
				"lane", reg.Lane, "anchor", reg.Anchor, "token_type", t.hint, "reason", reason,
				"status", resp.StatusCode)
		}
	}
}

// ─── the read-only zone report ──────────────────────────────────────────────

// readZone reads every planned name through the customer's own provider and
// reports what is there. It calls FindZone and ListRecordsAt and nothing else
// (see zoneReader).
func (s *Service) readZone(ctx context.Context, token string, plan derive.Plan) ([]RecordView, error) {
	var reader zoneReader = s.Publisher.Provider
	if reader == nil {
		return nil, errors.New("intent: no DNS provider is configured")
	}
	if len(plan.Items) == 0 {
		return nil, nil
	}
	// Located by the ANCHOR: the name the customer proved, and the only one in the
	// plan guaranteed to be in their zone rather than under a delegation somebody
	// could have created beneath it.
	zoneID, err := reader.FindZone(ctx, token, plan.Anchor)
	if err != nil {
		return nil, err
	}
	live := make(map[string][]dnsprovider.LiveRecord, len(plan.Items))
	for _, item := range plan.Items {
		key := dnsplan.NormalizeName(item.Record.Name)
		if _, ok := live[key]; ok {
			continue
		}
		rows, err := reader.ListRecordsAt(ctx, token, zoneID, item.Record.Name)
		if err != nil {
			return nil, err
		}
		live[key] = rows
	}

	out := make([]RecordView, 0, len(plan.Items))
	for _, item := range plan.Items {
		view := recordView(item)
		state := observe.StateAbsent
		var found []string
		sameType := 0
		for _, row := range live[dnsplan.NormalizeName(item.Record.Name)] {
			if !strings.EqualFold(strings.TrimSpace(row.Type), strings.TrimSpace(item.Record.Type)) {
				continue
			}
			sameType++
			found = append(found, row.Value)
			if reader.SameValue(strings.ToUpper(strings.TrimSpace(item.Record.Type)), row.Value, item.Record.Value) {
				state = observe.StatePresent
			}
		}
		// Only a CNAME can conflict, because only a CNAME is exclusive at its
		// owner: a TXT that is not ours sits beside ours, so "something else is
		// here" is still absent for our purposes. Same vocabulary as
		// internal/observe, so one report can be read against the other.
		if state == observe.StateAbsent && sameType > 0 && strings.EqualFold(item.Record.Type, "CNAME") {
			state = observe.StateConflicting
		}
		view.State, view.Found = string(state), found
		out = append(out, view)
	}
	return out, nil
}

// ─── small shared pieces ────────────────────────────────────────────────────

// grantSeconds is how long a grant on this lane is held, in seconds, with 0
// meaning STANDING.
//
// A negative value means this build does not recognise the lane. It is returned
// rather than clamped: a caller that adds it to `now` computes an expiry in the
// PAST, which is lane.GrantLifetime's deliberate fail-closed answer.
func grantSeconds(l lane.Lane) int64 {
	return int64(l.GrantLifetime() / time.Second)
}
