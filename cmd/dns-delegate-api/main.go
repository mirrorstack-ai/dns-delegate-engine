// Command dns-delegate-api is the dns-delegate-engine internal RPC Lambda.
//
// Two transports, one dispatcher:
//
//   - lambda.Invoke (production): the {action, request} RPC envelope in, the
//     {ok, response | error} envelope out. IAM gates the invoke; this service is
//     NOT exposed through API Gateway, and api-platform reaches it by
//     alias-qualified ARN.
//   - HTTP (local dev): a mux on DNS_DELEGATE_API_PORT (default 8093), gated by
//     X-MS-Internal-Secret on every route except /healthz, fail-closed (empty
//     secret → 503).
//
// # Two surfaces, one binary, and the older one is on its way out
//
// The INTENT surface (internal/intent) is what this repository is built around:
// a caller names a domain and an intent and cannot name a DNS record at all,
// every byte reaching a customer's zone is derived in internal/derive or relayed
// verbatim from AWS or Cloudflare in internal/relay, and the anchor is proven by
// a TXT record the CUSTOMER publishes, re-checked on every pass that writes. The
// GRANT surface (internal/grant) is the record-list API that preceded it —
// Authorize / Publish / Revoke, caller-supplied records — and closes neither of
// the two defects docs/DESIGN.md §1 describes: nothing bounds a record's VALUE,
// and the ownership proof was a record we published, gated on a lookup of that
// same write.
//
// 🔴 IT IS RETAINED ANYWAY, AND DELETING IT IS NOT A CLEANUP. api-platform calls
// Health, Capabilities, Authorize, Publish and Revoke today; removing or
// renaming any of them takes production down, so the intent actions were added
// BESIDE them rather than over them. Each deprecated case below names the intent
// action that replaces it. The retirement happens when the caller has moved, and
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

// errUnknownAction is returned for an action this build does not implement,
// deliberately distinct from a transport failure: api-platform's client maps it
// to a hard error, never a retry, so a version skew fails loudly.
var errUnknownAction = errors.New("unknown action")

// errInvalidInput is a malformed request payload, distinct from any refusal a
// service itself makes.
var errInvalidInput = errors.New("invalid request payload")

type dispatcher struct {
	// grants is the deprecated record-list surface. See the package doc.
	grants *grant.Service
	// intents is the surface docs/DESIGN.md describes.
	intents *intent.Service
}

// Three action names are load-bearing, and each is a constant so the reason
// travels with the name rather than with a line in a switch.

// actionIntentAuthorize is "IntentAuthorize", and it must NEVER become an alias
// of the legacy "Authorize". Legacy Authorize takes the OAuth state as a REQUEST
// FIELD — one the caller can mint for a registration it is not holding — and
// Complete is then handed identity, lane and domain as separate fields that can
// be made to disagree. This one mints the state itself, sealed over lane,
// identity, anchor and nonce, and refuses unless the ownership proof resolves
// RIGHT NOW and, on the wildcard lane, unless the consent page was acknowledged.
// A caller reaching the wrong one gets none of those checks and no error saying
// so; two names make that an `unknown_action` refusal instead. So neither name
// may point at the other implementation, "Authorize" least of all as a migration
// convenience: the REQUEST SHAPE selects the weaker check, not the action name.
//
// 🔴 LANE 2 CANNOT BE AUTHORIZED ON THIS TRANSPORT — A KNOWN GAP, NOT A DECISION.
// The wildcard lane additionally needs a consent.Token minted under this
// deployment's keyset, and nothing in this binary mints one: /consent renders the
// page and stops. A caller cannot mint one either — the point of a MAC under a
// key that never leaves here — so this action refuses org_app_domain with
// `consent_required` on every deployment of this build. Refusing is the safe end
// of the failure; minting an acknowledgement somewhere the customer was not is
// the claim-with-nothing-behind-it the consent page exists to replace.
const actionIntentAuthorize = "IntentAuthorize"

// actionIntentCapabilities is named on the same rule, for a hazard of the same
// shape: it answers a strictly LARGER response than legacy "Capabilities"
// (docs/DESIGN.md §4 lists it), and a client decoding one into the other's
// struct would not fail — it would read Available:false and render no connect
// affordance, indistinguishable from a deployment that cannot offer delegated
// DNS. Publishing the routing targets and the DCV identifier is deliberate: none
// is a secret, every one ends up in a customer's own zone as the VALUE of a
// record we ask them to accept, and publishing them lets somebody check BEFORE
// authorizing that the CNAME they will be asked for is the one this repository
// derives.
const actionIntentCapabilities = "IntentCapabilities"

// actionPublish is the deprecated record-list action, and where defect 1 lives:
// it bounds WHERE we write and nothing bounds WHAT.
//
// 🔴 WHILE IT IS ROUTED, THE SURFACE AS A WHOLE IS NOT BOUNDED. What MirrorStack
// can put in a customer's zone is the UNION of what the intent surface derives
// and whatever record list the private half hands to this one, so an audit has
// to read both halves and the weaker one decides. It also takes the ANCHOR as a
// request field, so its reach is the whole zone the provider authorized rather
// than the domain the customer connected. Deleting it is what turns the bound
// into a property of the DEPLOYMENT rather than of the intent surface, and it is
// the next step; "Complete" is what api-platform moves to.
const actionPublish = "Publish"

// handler is one action, already bound to its service and its request type.
type handler func(*dispatcher, context.Context, json.RawMessage) (any, error)

// route is one entry in the wire surface.
type route struct {
	handle handler

	// writes records that this action can reach a customer's zone.
	//
	// 🔴 DATA RATHER THAN A COMMENT: "which actions can change my zone" is the
	// first question a reader has, and a comment drifts from the table it
	// describes. TestTheWritingActionsAreExactlyTheDeclaredSet pins it.
	writes bool

	// deprecated marks the record-list surface. Not one line of its behaviour
	// changed when this table replaced the switch.
	deprecated bool
}

// routes is the whole wire surface. A reader tracing what this service can be
// asked to do reads this table and nothing else; `writes` is derived from each
// action's response type — see on().
var routes = map[string]route{
	// Observation. Writes nothing, needs no credential.
	"Health": reads((*dispatcher).handleHealth),

	// ─── the intent surface (docs/DESIGN.md) ────────────────────────────────
	// The first three register a domain and write nothing: each computes the
	// proof the customer must publish, derives the records, seals a registration
	// and reaches no provider. The fourth runs at deploy time.
	"AddOrgPlatformDomain":  on(intents, (*intent.Service).AddOrgPlatformDomain),
	"AddOrgAppDomain":       on(intents, (*intent.Service).AddOrgAppDomain),
	"AddAppDomain":          on(intents, (*intent.Service).AddAppDomain),
	"BindAppToOrgAppDomain": on(intents, (*intent.Service).BindAppToOrgAppDomain),

	// The lifecycle. Identical on all three lanes, which is why there is one set
	// of these and not three.
	"Verify":                 on(intents, (*intent.Service).Verify),
	actionIntentAuthorize:    on(intents, (*intent.Service).Authorize),
	"Complete":               on(intents, (*intent.Service).Complete),
	"Advance":                on(intents, (*intent.Service).Advance),
	"Describe":               on(intents, (*intent.Service).Describe),
	"Orphans":                on(intents, (*intent.Service).Orphans),
	"Release":                on(intents, (*intent.Service).Release),
	actionIntentCapabilities: reads((*dispatcher).handleIntentCapabilities),

	// ─── the deprecated record-list surface ─────────────────────────────────
	"Capabilities": deprecate(reads((*dispatcher).handleGrantCapabilities)),
	"Authorize":    deprecate(on(grants, (*grant.Service).Authorize)),
	actionPublish:  deprecate(writesToAZone(on(grants, (*grant.Service).Publish))),
	"Revoke":       deprecate(on(grants, (*grant.Service).Revoke)),
}

// writesToAZone marks the one action whose writing is INVISIBLE IN ITS TYPE.
//
// 🔴 THAT IT NEEDS MARKING AT ALL IS THE POINT. Every intent action reaching a
// customer's zone says so by returning intent.PassResponse. This one returns
// grant.PublishResponse and is the only route whose blast radius a reader cannot
// get from its signature — the property that made the record-list surface worth
// replacing.
func writesToAZone(r route) route { r.writes = true; return r }

// surface is one of the two RPC surfaces: how to reach it off the dispatcher and
// the sentinel it answers unwired. See decodeAnd for why it is per-surface.
type surface[Svc any] struct {
	get         func(*dispatcher) *Svc
	unavailable error
}

var (
	intents = surface[intent.Service]{
		get:         func(d *dispatcher) *intent.Service { return d.intents },
		unavailable: intent.ErrUnavailable,
	}
	grants = surface[grant.Service]{
		get:         func(d *dispatcher) *grant.Service { return d.grants },
		unavailable: grant.ErrUnavailable,
	}
)

// on binds one service method into a route, deriving `writes` from the response
// type rather than taking a flag: intent.PassResponse is returned by exactly the
// actions that can reach a customer's zone and nothing else — Service.write
// takes one in its signature — so an intent action added later is classified
// correctly without anyone remembering to say so.
func on[Svc any, Req any, Res any](
	sf surface[Svc],
	run func(*Svc, context.Context, Req) (Res, error),
) route {
	var res Res
	_, writes := any(res).(intent.PassResponse)
	return route{
		writes: writes,
		handle: func(d *dispatcher, ctx context.Context, payload json.RawMessage) (any, error) {
			return decodeAnd(ctx, payload, sf.get(d), sf.unavailable, run)
		},
	}
}

// reads builds a route for an action that answers without decoding a request.
func reads(h handler) route { return route{handle: h} }

// deprecate marks a route as belonging to the legacy record-list surface.
func deprecate(r route) route { r.deprecated = true; return r }

func (d *dispatcher) dispatch(ctx context.Context, action string, payload json.RawMessage) (any, error) {
	r, ok := routes[action]
	if !ok {
		return nil, fmt.Errorf("%w: %q", errUnknownAction, action)
	}
	return r.handle(d, ctx, payload)
}

// The three actions that answer without decoding a request.

func (d *dispatcher) handleHealth(ctx context.Context, _ json.RawMessage) (any, error) {
	return d.health(ctx), nil
}

func (d *dispatcher) handleIntentCapabilities(ctx context.Context, _ json.RawMessage) (any, error) {
	if d.intents == nil {
		return intent.CapabilitiesResponse{}, intent.ErrUnavailable
	}
	return d.intents.Capabilities(ctx), nil
}

// handleGrantCapabilities answers a ZERO VALUE rather than a sentinel when the
// surface is not wired — the legacy contract, not an oversight: Available:false
// renders no connect affordance, where an error renders a failure.
func (d *dispatcher) handleGrantCapabilities(ctx context.Context, _ json.RawMessage) (any, error) {
	if d.grants == nil {
		return grant.CapabilitiesResponse{}, nil
	}
	return d.grants.Capabilities(ctx), nil
}

// decodeAnd unmarshals one action's request and runs it. A malformed payload is
// errInvalidInput, never the action's own failure vocabulary: the caller must be
// able to tell "you sent nonsense" from "the provider refused".
//
// 🔴 IT PASSES THE INVOCATION'S CONTEXT, NOT context.Background(). An earlier
// version substituted Background, so the Lambda deadline never reached the
// provider call: a write that outran it was killed with its HTTP request still
// in flight, leaving the caller a transport failure that said nothing about
// whether Cloudflare had applied it. With the real context the request is
// cancelled a moment earlier and returns an error
// cloudflare.Client.IsAmbiguous classifies — that classifier failing TOWARD
// ambiguous for anything not a decoded API error — so reconcile re-reads rather
// than guessing.
//
// unavailable is the calling surface's OWN not-wired sentinel, not one shared
// value, because errorCode derives the caller's contract from it: grant's
// sentinel returned from an intent action would be correct by luck, and would
// stop being correct the moment the two vocabularies diverge.
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
// deployed artifact; every other build leaves it at the default below. It is
// what turns "I read this repository" into "this is the revision holding my
// credential" (docs/DESIGN.md §4): containment at the anchor, a provider
// interface with no delete, values derived rather than accepted are all facts
// about SOURCE, and none carries across without it.
//
// 🔴 AN UNSTAMPED BUILD SAYS "unknown" AND NEVER SOMETHING PLAUSIBLE. No zero
// sha, no "dev", no build timestamp dressed up as a version. A well-formed but
// wrong answer is worse than none: somebody looks it up, fails to find it, and
// either writes off the whole surface or — far worse — matches the wrong tree
// and audits code that is not running. "unknown" is checkable and true, and it
// is what a local `make run` reports.
//
// It is published on an INTERNAL surface, not a public one: Health is reached by
// IAM-gated lambda.Invoke in production and behind the internal secret locally,
// so today it is auditable on request rather than by a customer's developers
// unaided. Publishing it on the unauthenticated gateway probe is a separate
// decision this file does not take.
var commit = "unknown"

type healthResponse struct {
	OK bool `json:"ok"`
	// Commit is the build stamp above, reported on every answer, healthy or not:
	// a deployment refusing traffic is when somebody most needs to know which
	// code is doing the refusing.
	Commit string `json:"commit"`
	// Delegation reports whether this deployment can offer delegated DNS: "ready"
	// (client and keyset), "no-keyset" (client only — grants can be published but
	// not held), or "unconfigured".
	Delegation string `json:"delegation"`
}

// health is the arming check for a deploy. It resolves the credentials the same
// way a real request does — through the runtime loaders, so a secret filled in
// after this Lambda started counts — without contacting the provider, and
// publishes the deployed commit (see the `commit` var).
//
// It reads whichever surface is wired, preferring the intent one. Both resolve
// the same two credentials from the same loaders, so today that branch is a
// no-op; it exists for the day the deprecated service is deleted, when removing
// d.grants would otherwise leave a healthy deployment answering "unconfigured"
// and mirrorstack-infra's health check reading the service as down.
//
// An incomplete derivation configuration is deliberately NOT reported here. It
// is a real fault, but it belongs in IntentCapabilities, which says exactly what
// is missing; failing health over it would take a deployment out of rotation for
// a capability the live caller does not yet use — the same reason "no-keyset" is
// healthy rather than failing.
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
	// rotated after this Lambda started is picked up without a redeploy; sharing
	// them stops the two surfaces disagreeing about which credential is current
	// while one is being retired.
	oauth := cfoauth.NewDefaultLoader()
	keys := grantcrypto.NewDefaultLoader()
	// Cloudflare is the first provider. A second is an adapter beside it plus a
	// selector here; every safety rule stays in reconcile.
	publisher := reconcile.Publisher{Provider: cloudflare.Client{}}

	// How public DNS is read, and how much a positive reading is worth. The
	// default is the container's single recursive resolver — this service's
	// behaviour before the quorum existed — and DNS_DELEGATE_RESOLVERS /
	// DNS_DELEGATE_AUTHORITATIVE widen it; observe.ResolverFromEnv documents why
	// hardening is opt-in. The policy is logged and republished through
	// IntentCapabilities, so a deployment cannot claim more vantage points than
	// it wired.
	resolver := observe.ResolverFromEnv()
	policy := observe.PolicyOf(resolver)
	slog.Info("dns-delegate-api: public DNS vantage points",
		"vantages", policy.Vantages, "threshold", policy.Threshold,
		"authoritative", policy.Authoritative, "dnssec", false)

	d := &dispatcher{
		grants: &grant.Service{OAuth: oauth, Keys: keys, Publisher: publisher},
		intents: &intent.Service{
			OAuth:     oauth,
			Keys:      keys,
			Publisher: publisher,
			Derive:    derive.ConfigFromEnv(),

			// Wired explicitly, never defaulted inside the package: a
			// package-level default would mean a test that forgot a fake
			// silently resolved real names. A binary is the one place that may
			// say yes.
			Resolver: resolver,

			Certificates: certificateAuthority(context.Background()),

			// 🔴 Edge — record 7, Cloudflare's serving proof — IS NOT WIRED, AND
			// THIS IS A KNOWN GAP RATHER THAN A DECISION. relay.Edge needs
			// MirrorStack's OWN Cloudflare API token, for which there is no
			// loader here, and the SaaS zone id, which differs between the org
			// lane and the app lane while this field does not.
			//
			// Nil is supported, not a failure: everything derivable is still
			// published and record 7 never appears — visibly incomplete rather
			// than confidently wrong. docs/RECORDS.md § serving names the
			// consequence: every lane can land in 526-with-a-healthy-certificate.
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
// validation CNAMEs lane 1 relays verbatim from AWS — or says why it did not.
//
// 🔴 IT IS WIRED IN LAMBDA ONLY, A SAFETY RULE RATHER THAN A CONVENIENCE.
// relay.NewACM with an empty region falls back to the process's ambient AWS
// configuration: inside Lambda that is the deployment's own execution role and
// region, but on a laptop it is whatever account the shell is logged into, and a
// local `make run` would quietly start listing certificates out of it.
//
// A nil return is supported rather than fatal. Record 6, the DCV pointer, is
// DERIVED here and is what gets the Cloudflare edge certificate issued
// (docs/RECORDS.md § certificate), so a lane still gets TLS at the edge while
// ACM is unreadable; lane 1's AWS certificate does not validate until record 5
// is relayed, and until then that lane is served at the edge and incomplete.
// Refusing to start would couple that slow path to the fast one and leave every
// domain unrouted over a permission problem on our side. The failure is logged
// at Error because the alternative — a reader pointed at the wrong region —
// answers "no records, no error", indistinguishable from an ACM that has not
// filled them in yet, and would sit that way forever.
func certificateAuthority(ctx context.Context) relay.CertificateAuthority {
	if !config.IsLambda() {
		return nil
	}
	// MS_ACM_REGION overrides the case where the certificates do not live in the
	// function's own region. Empty is normal: the execution environment's.
	ca, err := relay.NewACM(ctx, os.Getenv("MS_ACM_REGION"))
	if err != nil {
		slog.Error("dns-delegate-api: certificate relay not wired, so lane 1 will publish "+
			"no ACM validation records and its certificates cannot validate", "error", err)
		return nil
	}
	return ca
}

// lambdaHandler answers both the RPC envelope and the API-Gateway health probe
// mirrorstack-infra maps onto this same function. They are told apart by
// "rawPath": API Gateway payload format 2.0 always sets it and the RPC envelope
// never does. The probe returns a static 200 without touching the dispatcher, so
// a health check can never be read as an authenticated RPC call.
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
		// The error is returned INSIDE the envelope, not as the Lambda function
		// error: at the caller a function error is indistinguishable from a
		// transport failure, and the client must be able to tell "the engine
		// refused" from "the engine was unreachable". Getting that wrong
		// destroys a working customer credential.
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
// 🔴 IT RENDERS; IT DOES NOT ACKNOWLEDGE. No POST, and no consent.Token minted
// anywhere on this route. Being shown the page and agreeing to it are two
// events; collapsing them would mean everything holding the internal secret —
// the private half included — held a customer's agreement to a standing wildcard
// without a customer having read a word of it. The route exists for READING the
// page, whose sentences live in internal/consent.
//
// Being behind the internal secret is what makes it not the customer's path: a
// customer's browser sends no such header. In production this Lambda has no API
// Gateway route at all and the page is proxied by the private half; this file
// deliberately adds no wiring for that.
//
// 🔴 THE PAGE'S REFERENCE IS NOT A QUERY PARAMETER AND MUST NOT BECOME ONE. The
// only input is the sealed registration; the reference an acknowledgement would
// be MACed over comes out of that envelope. A reference supplied on the URL is
// one the requester chooses, so they hold both halves of the pair, and one
// agreement given once on one screen would satisfy every later authorization on
// that anchor forever. Adding `?nonce=` back reintroduces that replay silently.
// docs/DESIGN.md §5 and internal/sealed's Registration.ConsentNonce carry the
// reasoning in full.
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
		// Safe to echo, checked rather than assumed: ConsentPage opens an
		// envelope, computes a proof and derives a plan, reaching no DNS provider
		// on any path — so no refusal here carries a provider response body,
		// which httputil.Error warns can quote zone contents. http.Error writes
		// text/plain with nosniff, so a message quoting a caller-supplied domain
		// cannot be sniffed as markup.
		http.Error(w, err.Error(), status)
		return
	}

	// The page loads nothing: no script, no external stylesheet, no font, no
	// image — one inline <style>. internal/consent asserts that in a test; this
	// header makes a BROWSER enforce it, so an edit adding a remote asset breaks
	// visibly here instead of quietly widening what a customer's consent screen
	// depends on. Whatever proxies the page in production sends its own.
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
// refusal means the plan is wrong and retrying cannot help. Anything
// unrecognised falls through to `internal`, which the caller must treat as a
// retry, never as a reason to release a grant. Hence the conservatism: a refusal
// mapped too specifically tells a caller to give up on a domain that was never
// the problem, and the only failure worse than a wasted pass is a working
// customer credential thrown away.
//
// 🔴 ORDER IS LOAD-BEARING, AND NOTHING ENFORCES IT BUT THE TESTS. Several
// sentinels below are reachable while ALSO matching a broader case further down
// — sealed.ErrExpired travels inside intent.ErrInvalidRequest,
// dnsplan.ErrAnchorEscape wraps dnsplan.ErrPlanInvalid, derive.ErrConfig wraps
// derive.ErrDerive. Moving one beneath its general form breaks no build and
// throws no error; it quietly answers a coarser code, which is how a caller ends
// up showing "this is a bug" to a customer whose consent screen went stale.
func errorCode(err error) string {
	switch {
	case errors.Is(err, errUnknownAction):
		return "unknown_action"

	// ── the specific refusals, before the general ones that carry them ──

	case errors.Is(err, sealed.ErrExpired):
		// The ten-minute authorization window closed: nothing consumed, nothing
		// broken, the customer just took longer on the provider's own screen.
		// internal/intent keeps this sentinel intact inside ErrInvalidRequest for
		// this boundary to find — "start again" and "this is a bug" are
		// different screens.
		return "state_expired"

	case errors.Is(err, intent.ErrNotProven):
		// The ownership TXT does not resolve at the anchor right now. The request
		// is well formed; what is missing is a record in somebody else's zone, so
		// the caller shows the value to publish rather than an error. Not a kind
		// of invalid_request: a caller telling the two apart only by reading a
		// message would eventually show the wrong one.
		return "not_proven"

	case errors.Is(err, intent.ErrConsentRequired):
		// The wildcard lane without an acknowledged consent page. Also not a bug:
		// the customer has not been shown, or has not agreed to, the one grant
		// whose scope they cannot enumerate.
		return "consent_required"

	// derive.ErrConfig WRAPS derive.ErrDerive, so the narrower test comes first —
	// the ordering internal/intent's deriveError makes. An incomplete routing
	// configuration is an OPERATOR's problem; reported as a bad request it would
	// have the caller give up permanently on a blameless domain.
	case errors.Is(err, derive.ErrConfig):
		return "unavailable"
	case errors.Is(err, derive.ErrDerive):
		return "invalid_request"

	// dnsplan.ErrAnchorEscape wraps dnsplan.ErrPlanInvalid; the specific code must
	// win. A containment failure is the one refusal an operator greps for by name.
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
		// lane.ErrInvalid wraps every identity, domain and slug refusal, and
		// arrives inside intent.ErrInvalidRequest today. Naming it keeps the
		// answer right if a future path returns one bare, and can only refine
		// `internal` into a code unambiguously the request's fault.
		errors.Is(err, lane.ErrInvalid):
		return "invalid_request"

	case errors.Is(err, grant.ErrUnavailable),
		errors.Is(err, intent.ErrUnavailable):
		return "unavailable"

	default:
		return "internal"
	}
}
