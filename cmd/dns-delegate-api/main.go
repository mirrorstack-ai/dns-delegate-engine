// Command dns-delegate-api is the dns-delegate-engine internal RPC Lambda.
//
// Two transports, one dispatcher:
//
//   - lambda.Invoke (production): payload is the {action, request} RPC
//     envelope; response is the {ok, response | error} envelope.
//   - HTTP (local dev): a small mux on DNS_DELEGATE_API_PORT (default 8093),
//     gated by X-MS-Internal-Secret on every route except /healthz.
//
// Auth contract:
//
//   - Production: IAM gates lambda.Invoke. This service is NOT exposed through
//     API Gateway; api-platform invokes it by alias-qualified ARN.
//   - Local HTTP: X-MS-Internal-Secret, fail-closed (empty secret → 503).
//
// # Two surfaces, one binary, and the older one is on its way out
//
// The INTENT surface (internal/intent) is the one this repository is built
// around: a caller names a domain and an intent, and cannot name a DNS record at
// all. Every byte that reaches a customer's zone is derived in internal/derive
// or relayed verbatim from AWS or Cloudflare in internal/relay, and the anchor
// is proven by a TXT record the CUSTOMER publishes, re-checked on every pass
// that writes.
//
// The GRANT surface (internal/grant) is the record-list API that preceded it:
// Authorize / Publish / Revoke, where the caller supplies the records. It closes
// neither of the two defects docs/DESIGN.md §1 describes — containment bounds a
// record's NAME and nothing bounds its VALUE, and the ownership proof was a
// record we published, gated on a public lookup of that same record.
//
// 🔴 IT IS RETAINED ANYWAY, AND DELETING IT IS NOT A CLEANUP. api-platform calls
// Health, Capabilities, Authorize, Publish and Revoke today. Removing or
// renaming any of them takes production down, so the intent actions were added
// BESIDE them rather than over them. Each deprecated case below names the intent
// action that replaces it; the retirement happens when the caller has moved, and
// it is a change to two repositories, in that order.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/consent"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/derive"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/grant"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/intent"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/observe"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/provider/cloudflare"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/reconcile"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/relay"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/sealed"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/auth"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/cfoauth"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/config"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/grantcrypto"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/httputil"
)

// rpcEnvelope is the lambda.Invoke request payload shape.
type rpcEnvelope struct {
	Action  string          `json:"action"`
	Request json.RawMessage `json:"request"`
}

// errUnknownAction is returned for an action this build does not implement. It
// is deliberately distinct from a transport failure: api-platform's client maps
// it to a hard error, never to a retry, so a version skew fails loudly instead
// of hammering the engine.
var errUnknownAction = errors.New("unknown action")

// errInvalidInput is a malformed request payload, distinct from any refusal the
// grant service itself makes.
var errInvalidInput = errors.New("invalid request payload")

type dispatcher struct {
	// grants is the deprecated record-list surface. See the package doc.
	grants *grant.Service
	// intents is the surface docs/DESIGN.md describes.
	intents *intent.Service
}

func (d *dispatcher) dispatch(ctx context.Context, action string, payload json.RawMessage) (any, error) {
	switch action {

	// ─── observation: writes nothing, needs no credential ────────────────────

	case "Health":
		return d.health(ctx), nil

	// ─── the intent surface (docs/DESIGN.md) ─────────────────────────────────
	//
	// The four intents. Each of the FIRST THREE registers a domain and writes
	// nothing — it computes the proof the customer must publish, derives the
	// records and seals a registration, and reaches no provider at all. The
	// fourth runs at deploy time and is the only one of the four that can
	// publish on its own.

	case "AddOrgPlatformDomain":
		return decodeAnd(ctx, payload, d.intents, intent.ErrUnavailable,
			(*intent.Service).AddOrgPlatformDomain)
	case "AddOrgAppDomain":
		return decodeAnd(ctx, payload, d.intents, intent.ErrUnavailable,
			(*intent.Service).AddOrgAppDomain)
	case "AddAppDomain":
		return decodeAnd(ctx, payload, d.intents, intent.ErrUnavailable,
			(*intent.Service).AddAppDomain)
	case "BindAppToOrgAppDomain":
		return decodeAnd(ctx, payload, d.intents, intent.ErrUnavailable,
			(*intent.Service).BindAppToOrgAppDomain)

	// The lifecycle. Identical on all three lanes, which is why there is one
	// set of these and not three.
	//
	// 🔴 THREE ACTIONS ON THIS SURFACE WRITE TO A CUSTOMER'S ZONE: "Complete",
	// "Advance", and "BindAppToOrgAppDomain" in the group above. All three reach
	// reconcile.Publisher.Publish through internal/intent's `write`, and the
	// last two share one code path (`pass`) so that "a later pass degrades the
	// same way on every lane" is true by construction rather than by intent.
	// Every other intent action derives, reads, seals or revokes, and puts no
	// record in front of a provider. If you are tracing what can change a zone,
	// those three are it — plus the deprecated "Publish" below, which is the
	// only one that takes its records from the caller.

	case "Verify":
		return decodeAnd(ctx, payload, d.intents, intent.ErrUnavailable,
			(*intent.Service).Verify)

	// 🔴 "IntentAuthorize", NOT "Authorize", AND THE TWO MUST NEVER BECOME
	// ALIASES.
	//
	// Legacy Authorize takes the OAuth state as a REQUEST FIELD. A caller-minted
	// state is a string the caller can also mint for a registration it is not
	// holding, and the completing call then has to be handed the identity, the
	// lane and the domain as separate fields — which is a pair of requests that
	// can be made to disagree.
	//
	// IntentAuthorize mints the state itself, as a sealed envelope carrying the
	// lane, the identity, the anchor and a nonce, so Complete needs none of them
	// as fields. It also refuses unless the ownership proof resolves RIGHT NOW,
	// and, on the wildcard lane, unless this service's own consent page was
	// served and acknowledged.
	//
	// A caller that reached the wrong one would be authorized with none of those
	// checks and would get no error saying so — a silent downgrade, which is the
	// quietest way to lose the property this surface exists to add. Two distinct
	// names turn that mistake into an `unknown_action` refusal instead. So
	// neither name may ever be pointed at the other implementation, and in
	// particular "Authorize" must not be re-routed to the intent service as a
	// migration convenience: the caller's request shape is what selects the
	// weaker check, not the action name it happens to be behind.
	//
	// 🔴 LANE 2 (org_app_domain) CANNOT BE AUTHORIZED ON THIS TRANSPORT, AND
	// THAT IS A KNOWN GAP RATHER THAN A DECISION.
	//
	// The wildcard lane also requires this service's own consent page to have
	// been served AND acknowledged, and an acknowledgement is a consent.Token
	// minted under this deployment's keyset. Nothing in this binary mints one:
	// the /consent route below renders the page and deliberately stops there,
	// and there is no other call to consent.Token outside the tests. A caller
	// cannot mint one either — that is the whole point of it being a MAC under a
	// key that never leaves here. So IntentAuthorize refuses org_app_domain with
	// `consent_required`, every time, on every deployment of this build.
	//
	// It ships that way because the refusal is the safe end of the failure. The
	// alternative is minting the acknowledgement somewhere the customer was not,
	// which is exactly the claim-with-nothing-behind-it the consent page exists
	// to replace. It stays refused until the customer-facing consent route is
	// settled: where it is served, and which event counts as the agreement.
	case "IntentAuthorize":
		return decodeAnd(ctx, payload, d.intents, intent.ErrUnavailable,
			(*intent.Service).Authorize)

	case "Complete":
		return decodeAnd(ctx, payload, d.intents, intent.ErrUnavailable,
			(*intent.Service).Complete)
	case "Advance":
		return decodeAnd(ctx, payload, d.intents, intent.ErrUnavailable,
			(*intent.Service).Advance)
	case "Describe":
		return decodeAnd(ctx, payload, d.intents, intent.ErrUnavailable,
			(*intent.Service).Describe)
	case "Orphans":
		return decodeAnd(ctx, payload, d.intents, intent.ErrUnavailable,
			(*intent.Service).Orphans)
	case "Release":
		return decodeAnd(ctx, payload, d.intents, intent.ErrUnavailable,
			(*intent.Service).Release)

	// IntentCapabilities is named on the same rule as IntentAuthorize, for a
	// hazard of the same shape. It answers a strictly larger response than the
	// legacy Capabilities — the two routing targets, the DCV delegation
	// identifier, the declared cadence, the per-lane grant lifetimes and whether
	// each lane needs a consent page — and a client that decoded one into the
	// other's struct would not fail. It would read Available:false and render no
	// connect affordance at all, which looks exactly like a deployment that
	// cannot offer delegated DNS.
	//
	// It publishes the routing targets and the DCV identifier deliberately. None
	// is a secret: every one of them ends up in a customer's own zone as the
	// VALUE of a record we ask them to accept, and publishing them here is what
	// lets somebody check, BEFORE authorizing anything, that the CNAME they are
	// about to be asked for is the one this repository derives.
	case "IntentCapabilities":
		if d.intents == nil {
			return intent.CapabilitiesResponse{}, intent.ErrUnavailable
		}
		return d.intents.Capabilities(ctx), nil

	// ─── the deprecated record-list surface ──────────────────────────────────
	//
	// 🔴 EVERY CASE BELOW IS LIVE. api-platform calls them today. They are
	// retained until it has migrated, and not one line of their behaviour has
	// changed.

	// DEPRECATED — replaced by "IntentCapabilities", which reports what the
	// intent surface can offer and what it would put in a zone.
	case "Capabilities":
		if d.grants == nil {
			return grant.CapabilitiesResponse{}, nil
		}
		return d.grants.Capabilities(ctx), nil

	// DEPRECATED — replaced by "IntentAuthorize", which mints the state instead
	// of accepting one, and refuses without a live ownership proof.
	case "Authorize":
		return decodeAnd(ctx, payload, d.grants, grant.ErrUnavailable,
			(*grant.Service).Authorize)

	// DEPRECATED — replaced by "Complete" for the first pass and "Advance" for
	// every later one. This is the action that takes a record list, and so it is
	// the one defect 1 lives in: it bounds where we write and nothing bounds
	// what.
	//
	// 🔴 SO THE SURFACE AS A WHOLE IS NOT YET BOUNDED, AND ANY CLAIM OTHERWISE
	// IS ABOUT THE INTENT ACTIONS ALONE. While this case is routed, what
	// MirrorStack can put in a customer's zone is the UNION of what the intent
	// surface derives and whatever record list the private half hands to this
	// one — so somebody auditing the blast radius has to read both halves, and
	// the weaker half is the one that decides.
	//
	// Deleting this case is what turns the bound into a property of the
	// DEPLOYMENT rather than of the intent surface, and it is the next step.
	// "Complete" is what api-platform moves to; the retirement is a change to
	// two repositories in the order the package doc gives, caller first.
	case "Publish":
		return decodeAnd(ctx, payload, d.grants, grant.ErrUnavailable,
			(*grant.Service).Publish)

	// DEPRECATED — replaced by "Release", which opens the sealed grant itself
	// and revokes the REFRESH token rather than the access token: revoking the
	// refresh token kills the whole grant, where revoking only the access token
	// leaves a credential that can mint another. It does NOT refresh first —
	// there is nothing a refresh would add once the whole grant is going — and
	// an envelope this deployment cannot open is reported unreadable and logged
	// REVOKE BY HAND rather than guessed at.
	case "Revoke":
		return decodeAnd(ctx, payload, d.grants, grant.ErrUnavailable,
			(*grant.Service).Revoke)

	default:
		return nil, fmt.Errorf("%w: %q", errUnknownAction, action)
	}
}

// decodeAnd unmarshals one action's request and runs it. A malformed payload is
// errInvalidInput, never the action's own failure vocabulary: the caller must be
// able to tell "you sent nonsense" from "the provider refused".
//
// 🔴 IT PASSES THE INVOCATION'S CONTEXT, NOT context.Background().
//
// An earlier version substituted Background here, which meant the Lambda
// deadline never reached the provider call. A write that outran the deadline was
// killed with its HTTP request still in flight, and the caller was left with a
// transport failure carrying nothing about whether Cloudflare had applied it.
// With the real context the request is cancelled a moment earlier and returns an
// error cloudflare.Client.IsAmbiguous classifies — and that classifier fails
// TOWARD ambiguous for anything which is not a decoded API error — so reconcile
// re-reads rather than guessing. "Never retry an ambiguous write, re-read
// instead" is only enforceable when the ambiguity is visible.
//
// unavailable is the calling surface's OWN not-wired sentinel rather than one
// shared value, because errorCode derives the caller's contract from it: handing
// back grant's sentinel from an intent action would produce a correct code by
// luck instead of by construction, and would stop being correct the moment the
// two vocabularies diverge.
func decodeAnd[Svc any, Req any, Res any](
	ctx context.Context,
	payload json.RawMessage,
	svc *Svc,
	unavailable error,
	run func(*Svc, context.Context, Req) (Res, error),
) (any, error) {
	var zero Res
	if svc == nil {
		return zero, unavailable
	}
	var req Req
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &req); err != nil {
			return zero, fmt.Errorf("%w: %v", errInvalidInput, err)
		}
	}
	return run(svc, ctx, req)
}

// commit is the git SHA this binary was built from. .github/workflows/publish.yml
// stamps it with `-X main.commit=$GITHUB_SHA` at the one build that produces a
// deployed artifact; every other build leaves it at the default below.
//
// 🔴 EVERY OTHER CLAIM IN THIS REPOSITORY RESTS ON IT. Containment at the
// anchor, a provider interface with no delete, record values derived rather
// than accepted: each of those is a fact about SOURCE. A reader can only carry
// one across to the service actually holding their credential if they can tell
// that the code they read is the code answering them. Without a commit on this
// surface there is no step from "I audited this repository" to "this is what
// holds my credential", and every property here degrades from checkable to
// merely stated.
//
// 🔴 AN UNSTAMPED BUILD SAYS "unknown" AND NEVER SOMETHING PLAUSIBLE. No zero
// sha, no "dev", no build timestamp dressed up as a version. A well-formed but
// wrong answer is worse than none: it is a value somebody looks up, fails to
// find, and then either writes off the whole surface over or — far worse —
// matches against the wrong tree and audits code that is not running. "unknown"
// is checkable and true, and it is what a local `make run` reports.
//
// 🔴 AND IT IS PUBLISHED ON AN INTERNAL SURFACE, NOT A PUBLIC ONE. Health is
// reached by IAM-gated lambda.Invoke in production and behind the internal
// secret locally, so today it is MirrorStack's own operators and the private
// half that can read this, not a customer's developer directly. That makes the
// deployment auditable by whoever is asked; it does not yet make it
// self-serve-auditable by the customer. Publishing it on the unauthenticated
// gateway probe is a separate decision and this file deliberately does not take
// it.
var commit = "unknown"

type healthResponse struct {
	OK bool `json:"ok"`
	// Commit is the build stamp above. It is reported on every answer, healthy
	// or not: a deployment that is refusing traffic is exactly when somebody
	// needs to know which code is doing the refusing.
	Commit string `json:"commit"`
	// Delegation reports whether this deployment can actually offer delegated
	// DNS: "ready" (client and keyset), "no-keyset" (client only — grants can be
	// published but not held), or "unconfigured".
	Delegation string `json:"delegation"`
}

// health is the arming check for a deploy. It resolves the credentials the same
// way a real request does — through the runtime loaders, so a secret filled in
// after this Lambda started counts — without contacting the provider. It also
// publishes the deployed commit, which is what docs/DESIGN.md §4 means by every
// other property here being verifiable rather than merely readable; see the
// `commit` var for why an unstamped build must say so.
//
// It reads whichever surface is wired, preferring the intent one. Both surfaces
// resolve the same two credentials from the same two loaders, so today that
// branch is a no-op and the answers are identical. It exists for the day the
// deprecated service is deleted: without it, removing d.grants would
// leave a perfectly healthy deployment answering "unconfigured", and
// mirrorstack-infra's health check would read the service as down. A retirement
// that presents as an outage is the kind of thing that gets rolled back and
// blamed on the wrong change.
//
// A derivation configuration that is incomplete is deliberately NOT reported
// here. It is a real fault and it belongs in IntentCapabilities, which says
// exactly what is missing; failing the health check over it would take a
// deployment out of rotation for a capability the live caller does not yet use —
// the same reason "no-keyset" is a healthy state rather than a failing one.
func (d *dispatcher) health(ctx context.Context) healthResponse {
	var available, canHold bool
	switch {
	case d.intents != nil:
		caps := d.intents.Capabilities(ctx)
		available, canHold = caps.Available, caps.CanHold
	case d.grants != nil:
		caps := d.grants.Capabilities(ctx)
		available, canHold = caps.Available, caps.CanHold
	}
	switch {
	case !available:
		return healthResponse{Commit: commit, Delegation: "unconfigured"}
	case !canHold:
		return healthResponse{OK: true, Commit: commit, Delegation: "no-keyset"}
	default:
		return healthResponse{OK: true, Commit: commit, Delegation: "ready"}
	}
}

func main() {
	// One OAuth loader and one keyset loader, SHARED by both surfaces. They
	// cache on a TTL and re-read their secret when it expires, so a credential
	// rotated after this Lambda started is picked up without a redeploy — and
	// sharing them is what stops the two surfaces from disagreeing about which
	// credential is current while one of them is being retired.
	oauth := cfoauth.NewDefaultLoader()
	keys := grantcrypto.NewDefaultLoader()
	// Cloudflare is the first provider. A second one is an adapter beside it
	// plus a selector here; every safety rule stays in reconcile.
	publisher := reconcile.Publisher{Provider: cloudflare.Client{}}

	d := &dispatcher{
		grants: &grant.Service{OAuth: oauth, Keys: keys, Publisher: publisher},
		intents: &intent.Service{
			OAuth:     oauth,
			Keys:      keys,
			Publisher: publisher,
			Derive:    derive.ConfigFromEnv(),

			// Wired explicitly and never defaulted inside the package.
			// internal/intent gives the reason: a package-level default would
			// mean a test that forgot to supply a fake silently resolved real
			// names, and "no test needs a network" has to be enforced by
			// something other than discipline. A binary is the one place that
			// may say yes.
			Resolver: observe.NetResolver{},

			Certificates: certificateAuthority(context.Background()),

			// 🔴 Edge — record 7, Cloudflare's serving proof — IS NOT WIRED, AND
			// THIS IS A KNOWN GAP RATHER THAN A DECISION.
			//
			// relay.Edge needs MirrorStack's OWN Cloudflare API token and the
			// zone id of the SaaS zone the custom hostname sits in. There is no
			// loader for that token in this repository, and the zone differs
			// between the org lane and the app lane while this field does not.
			// Both have to be settled before it can be filled in.
			//
			// Nil is a supported state, not a failure: internal/intent publishes
			// everything it can derive and record 7 simply never appears, which
			// is visibly incomplete rather than confidently wrong.
		},
	}

	if config.IsLambda() {
		lambda.Start(d.lambdaHandler)
		return
	}

	port := config.Port("DNS_DELEGATE_API_PORT", "8093")
	slog.Info("dns-delegate-api listening", "addr", ":"+port)
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           d.httpHandler(os.Getenv("MS_INTERNAL_SECRET")),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("dns-delegate-api: server stopped", "error", err)
		os.Exit(1)
	}
}

// certificateAuthority wires the ACM relay — record 5, the certificate
// validation CNAMEs that lane 1 relays verbatim from AWS — or says why it did
// not.
//
// 🔴 IT IS WIRED IN LAMBDA ONLY, AND THAT IS A SAFETY RULE RATHER THAN A
// CONVENIENCE. relay.NewACM with an empty region falls back to whatever the
// process's ambient AWS configuration resolves. Inside Lambda that is the
// deployment's own execution role and region, which is exactly right. On a
// developer's laptop it is whatever account their shell happens to be logged
// into, and a local `make run` would quietly start listing certificates out of
// it.
//
// A nil return is supported rather than fatal, and the reason is the same one
// internal/intent gives for treating a relay failure as a warning: record 6 —
// the DCV pointer — is DERIVED here and is what gets the CLOUDFLARE EDGE
// certificate issued, so a lane still gets TLS at the edge while ACM is
// unreadable. Lane 1's AWS certificate does not validate until record 5 is
// relayed, and until then that lane is served at the edge and is not complete.
// Refusing to start over an unreadable relay would couple that slow path to the
// fast one and leave every domain unrouted over a permission problem on our
// side. The failure is logged at Error precisely because the alternative —
// wiring a reader pointed at the wrong region — answers "no records, no error",
// which is indistinguishable from an ACM that has not filled them in yet, and
// would sit that way forever.
func certificateAuthority(ctx context.Context) relay.CertificateAuthority {
	if !config.IsLambda() {
		return nil
	}
	// MS_ACM_REGION is an override for the case where the certificates do not
	// live in the function's own region. Empty is the normal case and resolves
	// to the execution environment's.
	ca, err := relay.NewACM(ctx, os.Getenv("MS_ACM_REGION"))
	if err != nil {
		slog.Error("dns-delegate-api: certificate relay not wired, so lane 1 will publish "+
			"no ACM validation records and its certificates cannot validate", "error", err)
		return nil
	}
	return ca
}

// lambdaHandler answers both the RPC envelope and the API-Gateway health probe
// that mirrorstack-infra maps onto this same function.
//
// The two are told apart by "rawPath": API Gateway payload format 2.0 always
// sets it and the RPC envelope never does. The probe returns a static 200
// without touching the dispatcher, so a health check can never be read as an
// authenticated RPC call.
func (d *dispatcher) lambdaHandler(ctx context.Context, payload json.RawMessage) (any, error) {
	var probe struct {
		RawPath string `json:"rawPath"`
	}
	if err := json.Unmarshal(payload, &probe); err == nil && probe.RawPath != "" {
		return map[string]any{
			"statusCode": 200,
			"headers":    map[string]string{"content-type": "application/json"},
			"body":       `{"ok":true}`,
		}, nil
	}

	var envelope rpcEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return httputil.Envelope{OK: false, Error: &httputil.Error{
			Code: "invalid_input", Message: "malformed rpc envelope",
		}}, nil
	}
	response, err := d.dispatch(ctx, envelope.Action, envelope.Request)
	if err != nil {
		code := errorCode(err)
		// The error is returned INSIDE the envelope, not as the Lambda
		// function error: a function error is indistinguishable from a
		// transport failure at the caller, and this service's client must be
		// able to tell "the engine refused" from "the engine was unreachable".
		// Getting that wrong destroys a working customer credential.
		return httputil.Envelope{OK: false, Error: &httputil.Error{Code: code, Message: err.Error()}}, nil
	}
	return httputil.Envelope{OK: true, Response: response}, nil
}

func (d *dispatcher) httpHandler(secret string) http.Handler {
	mux := http.NewServeMux()
	// Unauthenticated on purpose: a liveness probe that needs a credential
	// cannot report that the credential is missing.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	gated := http.NewServeMux()
	gated.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		health := d.health(r.Context())
		status := http.StatusOK
		if !health.OK {
			status = http.StatusServiceUnavailable
		}
		httputil.WriteJSON(w, status, health)
	})
	gated.HandleFunc("GET /consent", d.serveConsent)
	mux.Handle("/", auth.InternalSecret(secret)(gated))
	return mux
}

// serveConsent renders the wildcard lane's consent page, for LOCAL DEVELOPMENT.
//
// 🔴 IT RENDERS; IT DOES NOT ACKNOWLEDGE. There is no POST here and no
// consent.Token minted anywhere on this route. Being shown the page and agreeing
// to it are two events, and collapsing them would mean everything holding the
// internal secret — the private half included — held a customer's agreement to a
// standing wildcard without a customer having read a word of it. What this route
// is for is READING the page: the sentences a customer acts on live in
// internal/consent, and whoever edits them should be able to look at the result.
//
// 🔴 BEING BEHIND THE INTERNAL SECRET IS WHAT MAKES IT NOT THE CUSTOMER'S PATH.
// A customer's browser sends no such header. In production this Lambda has no
// API Gateway route at all and the page is proxied by the private half; this
// file deliberately adds no wiring for that.
//
// 🔴 THE PAGE'S REFERENCE IS NOT A QUERY PARAMETER AND MUST NOT BECOME ONE. The
// only input this route takes is the sealed registration; the reference an
// acknowledgement would be MACed over comes out of that envelope. A reference
// supplied on the URL is a value the requester chooses, which makes it a pair
// they hold both halves of: one agreement, given once by one customer on one
// screen, would then satisfy every later authorization on that anchor forever.
// internal/sealed's Registration.ConsentNonce carries that reasoning in full.
// Adding `?nonce=` back here would reintroduce the replay silently, because a
// page rendered against a chosen reference looks exactly like a correct one.
func (d *dispatcher) serveConsent(w http.ResponseWriter, r *http.Request) {
	if d.intents == nil {
		http.Error(w, "the intent surface is not wired in this build", http.StatusServiceUnavailable)
		return
	}
	registration := r.URL.Query().Get("registration")
	if registration == "" {
		http.Error(w, "?registration= is required: the sealed envelope AddOrgAppDomain returned",
			http.StatusBadRequest)
		return
	}
	page, err := d.intents.ConsentPage(r.Context(), registration)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, intent.ErrUnavailable):
			status = http.StatusServiceUnavailable
		case errors.Is(err, intent.ErrInvalidRequest), errors.Is(err, consent.ErrConsent):
			status = http.StatusBadRequest
		}
		// Safe to echo, and checked rather than assumed: ConsentPage opens an
		// envelope, computes a proof and derives a plan, and reaches no DNS
		// provider on any path — so no refusal here can be carrying a provider
		// response body, which httputil.Error warns can quote zone contents.
		// http.Error writes text/plain with X-Content-Type-Options: nosniff, so a
		// message quoting a caller-supplied domain cannot be sniffed as markup.
		http.Error(w, err.Error(), status)
		return
	}

	// The page loads nothing: no script, no external stylesheet, no font, no
	// image — one inline <style> and that is all. internal/consent asserts that
	// in a test; this header is what makes a BROWSER enforce it, so an edit that
	// adds a remote asset breaks visibly here instead of quietly widening what a
	// customer's consent screen depends on. Whatever proxies the page in
	// production is responsible for sending its own.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// 🔴 The page names the anchor and every value we would write beneath it. A
	// shared cache holding it would serve the next request somebody else's zone.
	w.Header().Set("Cache-Control", "no-store")
	if _, err := io.WriteString(w, page); err != nil {
		slog.Error("dns-delegate-api: write consent page", "error", err)
	}
}

// errorCode maps an engine error onto the caller's contract.
//
// 🔴 THE CALLER ACTS ON THESE. `unavailable`, `invalid_request`, `not_proven`,
// `consent_required` and `state_expired` all mean NOTHING WAS CONSUMED; a plan
// refusal means the plan is wrong and retrying it cannot help. Anything
// unrecognised falls through to `internal`, which the caller must treat as a
// retry — never as a reason to release a grant. That default is the reason this
// function stays conservative: a refusal mapped too specifically tells a caller
// to give up on a domain that was never the problem, and the only failure worse
// than a wasted pass is a working customer credential thrown away.
//
// 🔴 ORDER IS LOAD-BEARING, AND NOTHING ENFORCES IT BUT THE TESTS.
//
// Several sentinels below are reachable while ALSO matching a broader case
// further down — sealed.ErrExpired travels inside intent.ErrInvalidRequest,
// dnsplan.ErrAnchorEscape wraps dnsplan.ErrPlanInvalid, and derive.ErrConfig
// wraps derive.ErrDerive. Moving one beneath its general form breaks no build
// and throws no error: it just quietly answers a coarser code, which is how a
// caller ends up showing "this is a bug" to a customer whose only problem is
// that their consent screen went stale.
func errorCode(err error) string {
	switch {
	case errors.Is(err, errUnknownAction):
		return "unknown_action"

	// ── the specific refusals, before the general ones that carry them ──

	case errors.Is(err, sealed.ErrExpired):
		// The ten-minute authorization window closed. Nothing was consumed and
		// nothing is broken: the customer simply took longer than ten minutes on
		// the provider's own screen. internal/intent keeps this sentinel intact
		// inside ErrInvalidRequest for exactly this boundary to find, because
		// "start again" and "this is a bug" are different screens.
		return "state_expired"

	case errors.Is(err, intent.ErrNotProven):
		// The ownership TXT does not resolve at the anchor right now. The request
		// is well formed; what is missing is a record in somebody else's zone, so
		// the caller shows the value to publish rather than an error. It is
		// deliberately not a kind of invalid_request — a caller that could only
		// tell the two apart by reading a message would eventually show the wrong
		// one.
		return "not_proven"

	case errors.Is(err, intent.ErrConsentRequired):
		// The wildcard lane, without an acknowledged consent page. Also not a
		// bug: the customer has not been shown, or has not agreed to, the one
		// grant whose scope they cannot enumerate for themselves.
		return "consent_required"

	// derive.ErrConfig WRAPS derive.ErrDerive, so the narrower test comes first
	// — the same ordering internal/intent's deriveError makes, for the same
	// reason. An incomplete routing configuration is an OPERATOR's problem, and
	// reporting it to the caller as a bad request would have it give up
	// permanently on a domain that was never at fault.
	case errors.Is(err, derive.ErrConfig):
		return "unavailable"
	case errors.Is(err, derive.ErrDerive):
		return "invalid_request"

	// dnsplan.ErrAnchorEscape wraps dnsplan.ErrPlanInvalid; the specific code
	// must win. A containment failure is the one refusal in this service an
	// operator greps for by name.
	case errors.Is(err, dnsplan.ErrAnchorEscape):
		return "anchor_escape"
	case errors.Is(err, dnsplan.ErrPlanChanged):
		return "plan_changed"
	case errors.Is(err, dnsplan.ErrPlanPreparing):
		return "plan_preparing"
	case errors.Is(err, dnsplan.ErrPlanInvalid):
		return "plan_invalid"

	// ── the two general refusals, both meaning nothing was consumed ──

	case errors.Is(err, errInvalidInput),
		errors.Is(err, grant.ErrInvalidRequest),
		errors.Is(err, intent.ErrInvalidRequest),
		// lane.ErrInvalid is what every identity, domain and slug refusal wraps.
		// It arrives already inside intent.ErrInvalidRequest today; naming it
		// keeps the answer right if a future path returns one bare, and it can
		// only ever refine `internal` into a code that is unambiguously the
		// request's fault.
		errors.Is(err, lane.ErrInvalid):
		return "invalid_request"

	case errors.Is(err, grant.ErrUnavailable),
		errors.Is(err, intent.ErrUnavailable):
		return "unavailable"

	default:
		return "internal"
	}
}
