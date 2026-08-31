// Command dns-delegate-api is the dns-delegate-engine internal RPC Lambda.
//
// Two transports, one dispatcher:
//
//   - lambda.Invoke (production): the {action, request} RPC envelope in, the
//     {ok, response | error} envelope out. IAM gates the invoke; this service is
//     NOT exposed through API Gateway, and api-platform reaches it by
//     alias-qualified ARN.
//   - HTTP (local dev and, through API Gateway, production): a mux on
//     DNS_DELEGATE_API_PORT (default 8093), gated by X-MS-Internal-Secret on
//     every route except /healthz and /consent, fail-closed (empty secret →
//     503). /consent is gated on the sealed reference instead — see
//     serveConsent for why that is the whole gate it can have.
//
// # One surface, and the record list is gone
//
// The INTENT surface (internal/intent) is the whole of it: a caller names a
// domain and an intent and cannot name a DNS record at all, every byte reaching
// a customer's zone is derived in internal/derive or relayed verbatim from AWS
// or Cloudflare in internal/relay, and the anchor is proven by a TXT record the
// CUSTOMER publishes, re-checked on every pass that writes.
//
// The record-list surface that preceded it — Capabilities, Authorize, Publish
// and Revoke, over caller-supplied records — is deleted, together with
// internal/grant. While it was routed, what MirrorStack could put in a
// customer's zone was the UNION of what this surface derives and whatever list
// the private half handed the other one, so the bound docs/DESIGN.md §1
// describes was a property of one surface rather than of the deployment. The
// four names are gone from `routes`, so a caller still sending one gets an
// `unknown_action` refusal.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/derive"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/intent"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/observe"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/provider/cloudflare"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/reconcile"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/relay"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/sealed"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/auth"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/cfedge"
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
	// intents is the surface docs/DESIGN.md describes, and the only one.
	intents *intent.Service

	// web is the HTTP transport, built once in main and served on BOTH
	// transports: directly in local development, and through API Gateway in
	// Lambda (see serveGateway). One handler, so the route a customer reaches in
	// production is the route a developer reads locally.
	web http.Handler
}

// Two action names are load-bearing, and each is a constant so the reason
// travels with the name rather than with a row in the table.

// actionIntentAuthorize is "IntentAuthorize", and the prefix must not be tidied
// away now that the record-list "Authorize" is gone: this is the name
// api-platform's client puts on the wire, so renaming it here is a version skew
// that shows up only under live traffic, as an `unknown_action` refusal on every
// connect.
//
// 🔴 THE WILDCARD LANE'S ACKNOWLEDGEMENT IS NOT REACHABLE FROM THIS TABLE, AND
// MUST NOT BECOME REACHABLE. It is minted by posting back the challenge printed
// on the page /consent served, and both halves live on that HTTP route. Adding
// either as an action here hands MirrorStack's private half — the only caller
// IAM admits — a customer's agreement to a standing wildcard with no customer
// involved. internal/consent's package comment states what that separation does
// and does not prove.
const actionIntentAuthorize = "IntentAuthorize"

// actionIntentCapabilities is a constant for the same wire reason. What it
// publishes is deliberate: the routing targets and the DCV identifier are not
// secrets, every one of them ends up in a customer's own zone as the VALUE of a
// record we ask them to accept, and publishing them lets somebody check BEFORE
// authorizing that the CNAME they will be asked for is the one this repository
// derives.
const actionIntentCapabilities = "IntentCapabilities"

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
}

// surface is an RPC surface: how to reach it off the dispatcher and the sentinel
// it answers unwired. There is one today; it stays parameterised because the
// sentinel is per-surface, and decodeAnd says why that matters.
type surface[Svc any] struct {
	get         func(*dispatcher) *Svc
	unavailable error
}

var intents = surface[intent.Service]{
	get:         func(d *dispatcher) *intent.Service { return d.intents },
	unavailable: intent.ErrUnavailable,
}

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

func (d *dispatcher) dispatch(ctx context.Context, action string, payload json.RawMessage) (any, error) {
	r, ok := routes[action]
	if !ok {
		return nil, fmt.Errorf("%w: %q", errUnknownAction, action)
	}
	return r.handle(d, ctx, payload)
}

// The two actions that answer without decoding a request.

func (d *dispatcher) handleHealth(ctx context.Context, _ json.RawMessage) (any, error) {
	return d.health(ctx), nil
}

func (d *dispatcher) handleIntentCapabilities(ctx context.Context, _ json.RawMessage) (any, error) {
	if d.intents == nil {
		return intent.CapabilitiesResponse{}, intent.ErrUnavailable
	}
	return d.intents.Capabilities(ctx), nil
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
// unavailable is the calling surface's OWN not-wired sentinel rather than one
// shared value, because errorCode derives the caller's contract from it: a
// second surface added here would need its own, and borrowing intent's would be
// correct only by luck.
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

	// Resolution is the vantage-point rule and this deployment's own measurement
	// of whether it can reach those vantage points, republished from
	// IntentCapabilities so the thing that takes a Lambda out of rotation reads
	// it too. Absent when no intent surface is wired.
	Resolution *intent.ResolutionCapability `json:"resolution,omitempty"`
}

// health is the arming check for a deploy. It resolves the credentials the same
// way a real request does — through the runtime loaders, so a secret filled in
// after this Lambda started counts — without contacting the provider, and
// publishes the deployed commit (see the `commit` var).
//
// An incomplete derivation configuration is deliberately NOT reported here. It
// is a real fault, but it belongs in IntentCapabilities, which says exactly what
// is missing; failing health over it would take a deployment out of rotation for
// a capability the live caller does not yet use — the same reason "no-keyset" is
// healthy rather than failing.
//
// 🔴 UNREACHABLE RESOLVERS ARE THE OTHER WAY: THEY FAIL HEALTH. A deployment
// that cannot reach enough vantage points to meet its own threshold verifies
// nothing — every proof reads `unknown` and every authorization is refused — so
// it is already out of service, and the only choice here is whether it says so
// or serves refusals that look like customer mistakes. The threshold is never
// lowered to fit what is reachable; see observe.Probe.
func (d *dispatcher) health(ctx context.Context) healthResponse {
	out := healthResponse{Commit: commit}
	if d.intents == nil {
		out.Delegation = "unconfigured"
		return out
	}
	caps := d.intents.Capabilities(ctx)
	out.Resolution = &caps.Resolution
	switch {
	case !caps.Available:
		out.Delegation = "unconfigured"
		return out
	case !caps.CanHold:
		out.Delegation = "no-keyset"
	default:
		out.Delegation = "ready"
	}
	out.OK = !resolversDegraded(out.Resolution)
	return out
}

// resolversDegraded reads the probe's verdict. Unmeasured is not degraded: a
// deployment with no probe wired is where this service was before the probe
// existed, and failing health over an absent measurement would take it out of
// rotation for something nobody measured.
func resolversDegraded(r *intent.ResolutionCapability) bool {
	return r != nil && r.Reachability != nil && r.Reachability.Degraded
}

func main() {
	// One OAuth loader and one keyset loader. They cache on a TTL and re-read
	// their secret when it expires, so a credential rotated after this Lambda
	// started is picked up without a redeploy.
	oauth := cfoauth.NewDefaultLoader()
	keys := grantcrypto.NewDefaultLoader()
	// Cloudflare is the first provider. A second is an adapter beside it plus a
	// selector here; every safety rule stays in reconcile.
	publisher := reconcile.Publisher{Provider: cloudflare.Client{}}
	// The two reads that spend MirrorStack's own Cloudflare token, off one zone
	// table and one loader.
	edge, delegation := edgeReaders()

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

	// 🔴 THE POLICY ABOVE IS A DECLARATION UNTIL SOMETHING MEASURES IT. Whether
	// this Lambda can egress port 53 to addresses a customer's zone chose is not
	// knowable from configuration, and an unreachable vantage point answers
	// `unknown`, which refuses every Authorize. So the running service probes its
	// own vantage points and publishes the result through Capabilities and
	// health, instead of an operator having to remember to check.
	//
	// The org routing target is the probe name because it is a name this
	// deployment already publishes and every lane's records point at: it must
	// resolve wherever this runs, and it costs an operator nothing to configure.
	derived := derive.ConfigFromEnv()
	reach := &observe.Probe{Resolver: resolver, Name: derived.OrgRoutingTarget}

	d := &dispatcher{
		intents: &intent.Service{
			OAuth:     oauth,
			Keys:      keys,
			Publisher: publisher,
			Derive:    derived,

			// Wired explicitly, never defaulted inside the package: a
			// package-level default would mean a test that forgot a fake
			// silently resolved real names. A binary is the one place that may
			// say yes.
			Resolver: resolver,
			Reach:    reach,

			Certificates: certificateAuthority(context.Background()),
			Edge:         edge,
			Delegation:   delegation,
		},
	}

	d.web = d.httpHandler(os.Getenv("MS_INTERNAL_SECRET"))

	if config.IsLambda() {
		lambda.Start(d.lambdaHandler)
		return
	}

	port := config.Port("DNS_DELEGATE_API_PORT", "8093")
	slog.Info("dns-delegate-api listening", "addr", ":"+port)
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           d.web,
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

// The two MirrorStack zones record 7 is read from, one per lane. Named beside
// CF_SAAS_ORG_TARGET and CF_SAAS_TARGET in internal/derive, because they are the
// same two zones seen from the other end: a lane's routing target is a name IN
// the zone its custom hostnames live in.
const (
	edgeOrgZoneEnv = "CF_SAAS_ORG_ZONE_ID"
	edgeAppZoneEnv = "CF_SAAS_APP_ZONE_ID"
)

// edgeReaders wires the two reads that use MirrorStack's OWN Cloudflare token —
// record 7's serving proof, and record 6's DCV delegation identifier — or
// returns nils.
//
// 🔴 NIL IS THE UNCONFIGURED ANSWER, AND IT IS A WAIT RATHER THAN A FAULT. A
// deployment that names no edge token, or no zone for any lane, publishes
// everything it can derive: record 7 is reported as not yet available and record
// 6 falls back to CF_ORG_DCV_DELEGATION_UUID — visibly incomplete rather than
// confidently wrong, and never an error on a pass. A deployment that names a
// token it cannot READ is the other case, and internal/shared/cfedge keeps the
// two apart.
//
// Both readers take the same zone table and the same credential: one Cloudflare
// account, two reads. Nils are returned as untyped nil, never as a typed nil
// pointer, which is non-nil through an interface and would fail every pass.
//
// Not gated on config.IsLambda, unlike certificateAuthority: that gate exists
// because relay.NewACM falls back to an ambient AWS account with no variable set
// at all, and reading here takes an explicit CF_EDGE_TOKEN_SECRET_ID or
// CF_EDGE_API_TOKEN.
func edgeReaders() (relay.EdgeHostnames, relay.DCVDelegations) {
	zones := relay.EdgeZones{
		OrgPlatform: strings.TrimSpace(os.Getenv(edgeOrgZoneEnv)),
		App:         strings.TrimSpace(os.Getenv(edgeAppZoneEnv)),
	}
	if !zones.Configured() || !cfedge.Configured() {
		slog.Info("dns-delegate-api: the edge reads are not wired, so the serving proof will be "+
			"reported as not yet available and the DCV delegation identifier will be the configured one",
			"zones", zones.Configured(), "credential", cfedge.Configured())
		return nil, nil
	}
	// The loader is its own, not shared with the OAuth and keyset loaders: it
	// reads a different secret, and it is the one credential in this binary that
	// is MirrorStack's rather than a customer's.
	token := cfedge.NewDefaultLoader().Token
	return relay.Edge{Zones: zones, Token: token}, relay.NewDCV(zones, token)
}

// lambdaHandler answers both the RPC envelope and the API-Gateway health probe
// mirrorstack-infra maps onto this same function. They are told apart by
// "rawPath": API Gateway payload format 2.0 always sets it and the RPC envelope
// never does. The probe returns a static 200 without touching the dispatcher, so
// a health check can never be read as an authenticated RPC call.
// lambdaHandler answers both the RPC envelope and the HTTP requests API Gateway
// maps onto this same function. They are told apart by "rawPath": API Gateway
// payload format 2.0 always sets it and the RPC envelope never does.
func (d *dispatcher) lambdaHandler(ctx context.Context, payload json.RawMessage) (any, error) {
	var gateway gatewayRequest
	if err := json.Unmarshal(payload, &gateway); err == nil && gateway.RawPath != "" {
		return d.serveGateway(ctx, gateway), nil
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

// consentPath is the one HTTP path this service serves besides the probes, on
// both transports.
const consentPath = "/consent"

// gatewayRequest is the subset of API Gateway payload format 2.0 this function
// reads.
type gatewayRequest struct {
	RawPath         string            `json:"rawPath"`
	RawQueryString  string            `json:"rawQueryString"`
	Headers         map[string]string `json:"headers"`
	Body            string            `json:"body"`
	IsBase64Encoded bool              `json:"isBase64Encoded"`
	RequestContext  struct {
		HTTP struct {
			Method string `json:"method"`
		} `json:"http"`
	} `json:"requestContext"`
}

// serveGateway answers a request that arrived through API Gateway: the consent
// page through the same handler local development serves, and everything else as
// the static health probe that has always been here.
//
// 🔴 EVERY OTHER PATH KEEPS THE STATIC 200, WITHOUT TOUCHING THE DISPATCHER.
// mirrorstack-infra maps the probe at a path this file does not know
// (/dns-delegate/healthz today), so answering only a known list would read the
// service as down the day a stage is renamed.
//
// The consent path is matched by SUFFIX and then rewritten to consentPath: what
// sits in front of it is a stage or base path belonging to the deployment, and a
// mux pattern here cannot know it.
func (d *dispatcher) serveGateway(ctx context.Context, req gatewayRequest) map[string]any {
	if d.web == nil || !strings.HasSuffix(req.RawPath, consentPath) {
		// 🔴 THE COMMIT GOES HERE TOO, AND THIS IS THE COPY THAT REACHES A
		// CUSTOMER. The mux handler in httpHandler answers direct HTTP; every
		// request that arrives through API Gateway — which is every production
		// request — lands on this branch instead. Stamping only the other one
		// left the public probe answering a bare {"ok":true}, so the build a
		// customer is checking was still unreadable to them. Caught in
		// production on v9, after the change was verified in the wrong place.
		//
		// Built with fmt rather than a struct so this stays the static answer
		// its comment above promises: no dispatcher, no service, nothing that
		// can fail. commit is a build-time constant.
		return gatewayResponse(http.StatusOK, http.Header{"Content-Type": {"application/json"}},
			fmt.Sprintf(`{"ok":true,"commit":%q}`, commit))
	}
	body := []byte(req.Body)
	if req.IsBase64Encoded {
		decoded, err := base64.StdEncoding.DecodeString(req.Body)
		if err != nil {
			return gatewayText(http.StatusBadRequest, "malformed request body")
		}
		body = decoded
	}
	// A gateway that sent no method is not one this code should guess for: GET is
	// the only method that reads, so a missing one cannot be made to acknowledge.
	method := req.RequestContext.HTTP.Method
	if method == "" {
		method = http.MethodGet
	}
	target := consentPath
	if req.RawQueryString != "" {
		target += "?" + req.RawQueryString
	}
	r, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return gatewayText(http.StatusBadRequest, "malformed request")
	}
	for name, value := range req.Headers {
		r.Header.Set(name, value)
	}
	// One handler, so the gate is whatever d.web says it is: the internal secret
	// on every route it covers, and the sealed reference on /consent. A gateway
	// route to this function is not a way around either.
	rec := &capture{header: http.Header{}, status: http.StatusOK}
	d.web.ServeHTTP(rec, r)
	return gatewayResponse(rec.status, rec.header, rec.body.String())
}

// capture is the ResponseWriter the gateway adapter writes into. Deliberately
// minimal: nothing on this transport streams, flushes or hijacks.
type capture struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (c *capture) Header() http.Header         { return c.header }
func (c *capture) Write(b []byte) (int, error) { return c.body.Write(b) }
func (c *capture) WriteHeader(status int)      { c.status = status }

func gatewayResponse(status int, header http.Header, body string) map[string]any {
	headers := make(map[string]string, len(header))
	for name, values := range header {
		headers[strings.ToLower(name)] = strings.Join(values, ", ")
	}
	return map[string]any{"statusCode": status, "headers": headers, "body": body}
}

func gatewayText(status int, body string) map[string]any {
	return gatewayResponse(status, http.Header{
		"Content-Type":           {"text/plain; charset=utf-8"},
		"X-Content-Type-Options": {"nosniff"},
	}, body)
}

func (d *dispatcher) httpHandler(secret string) http.Handler {
	mux := http.NewServeMux()
	// Unauthenticated on purpose: a liveness probe that needs a credential
	// cannot report that the credential is missing.
	// 🔴 THE COMMIT IS PUBLISHED HERE BECAUSE THIS IS THE ONE PROBE A CUSTOMER
	// CAN REACH, AND IT IS WHAT MAKES THE REPOSITORY CHECKABLE.
	//
	// This repository is public so a customer can audit what may touch their
	// DNS. What runs is a private artifact in a private bucket, so reading the
	// source proved nothing about the deployment: "the code you read is the code
	// we run" was a promise with no way to test it.
	//
	// With .github/workflows/publish.yml attesting each artifact through
	// Sigstore, this line closes the loop — a customer reads the commit here,
	// verifies its provenance against GitHub, and reads that exact source. All
	// three steps are on public infrastructure and need nothing from us:
	//
	//     curl https://account.<domain>/dns-consent/healthz
	//     gh attestation verify <artifact> --repo mirrorstack-ai/dns-delegate-engine
	//
	// The RPC Health action already reported it, but that surface is behind the
	// internal secret — visible to MirrorStack, which is the party a customer is
	// checking, and therefore the one place it was worth nothing.
	//
	// It is a build stamp and nothing else: no configuration, no zone, no
	// identity, no state. "unknown" means a binary built outside the publish
	// workflow, which is itself the answer to "is this a release build?".
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"ok": "true", "commit": commit})
	})
	// 🔴 THE CONSENT PAGE IS THE ONE ROUTE OUTSIDE THE GATE, AND IT IS AN
	// EXCEPTION RATHER THAN A RELAXATION. Everything else on this transport —
	// /readyz below and every path that does not match — stays behind
	// X-MS-Internal-Secret. serveConsent carries the argument.
	mux.HandleFunc("GET "+consentPath, d.serveConsent)
	mux.HandleFunc("POST "+consentPath, d.acknowledgeConsent)

	gated := http.NewServeMux()
	gated.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		health := d.health(r.Context())
		status := http.StatusOK
		if !health.OK {
			status = http.StatusServiceUnavailable
		}
		httputil.WriteJSON(w, status, health)
	})
	mux.Handle("/", auth.InternalSecret(secret)(gated))
	return mux
}

// serveConsent renders the wildcard lane's consent page: the disclosure, plus
// the one form that can acknowledge it, carrying a challenge over the
// disclosure's bytes.
//
// 🔴 THE SEALED REGISTRATION IS THE WHOLE GATE, AND THE INTERNAL SECRET WAS
// REMOVED FROM THIS ROUTE ON PURPOSE. A page only MirrorStack can read is not a
// disclosure: the one party who has to read it is the customer, and no
// customer's browser holds that header.
//
// What the page discloses is the derived plan for one registration, and the only
// way to name that registration is the envelope this deployment sealed — AEAD
// ciphertext under its own keyset, carrying a 128-bit reference (sealed.NewNonce)
// — which cannot be guessed and cannot be forged, so holding it means having been
// handed it by the flow. The secret protected nothing that does not, while
// guaranteeing the reader the page exists for could never arrive.
//
// It costs nothing the acknowledgement had either: the control was always over
// SEQUENCE and CONTENT, never over presence (internal/consent's package comment,
// docs/DESIGN.md §4), and the private half proxying the page was never excluded.
// This is the SAME control, finally reachable by the person it is for.
//
// 🔴 IT IS THE ONLY EXCEPTION. Every other route on this transport keeps the
// gate; see httpHandler.
//
// 🔴 IT RENDERS; IT DOES NOT ACKNOWLEDGE. No consent.Token is minted here, and
// the challenge it prints is not one — internal/consent namespaces the two values
// apart, so holding the page is not holding the customer's agreement.
//
// 🔴 NEITHER EVENT MAY BECOME AN RPC ACTION. This Lambda is IAM-gated, so an
// entry in `routes` is one MirrorStack's private half can call, and with both on
// that surface it holds an agreement no customer gave. internal/consent's package
// comment states what this separation does and does not prove — and it does NOT
// prove a human was present.
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
	consentHeaders(w)
	if d.intents == nil {
		http.Error(w, "this deployment cannot serve consent pages", http.StatusServiceUnavailable)
		return
	}
	page, err := d.intents.ConsentPage(r.Context(), r.URL.Query().Get("registration"))
	if err != nil {
		if consentIsOurs(err) {
			http.Error(w, "this deployment cannot serve consent pages", http.StatusServiceUnavailable)
			return
		}
		logConsentRefusal("page", err)
		http.Error(w, noConsentPage, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := io.WriteString(w, page); err != nil {
		slog.Error("dns-delegate-api: write consent page", "error", err)
	}
}

// acknowledgeConsent redeems the challenge printed on a served page into the
// acknowledgement IntentAuthorize requires on the wildcard lane.
//
// 🔴 THE CHALLENGE IS THE WHOLE CONTROL, AND A REGISTRATION ALONE MUST NEVER BE
// ENOUGH. It is a MAC over the reference, the anchor and the SHA-256 of the
// disclosure that was rendered, so an acknowledgement exists only where this
// service served that page and the value came back off it. Accepting a bare
// registration here would be the `ConsentAck` action this design exists to not
// have.
//
// The answer is JSON rather than a page: it is read by whatever posted the form.
// In the production flow that is the private half proxying it, which stores the
// token and sends it to IntentAuthorize; a customer who opened the page directly
// gets the token itself, which grants nothing until it reaches that call. The
// screen a person reads is the GET.
func (d *dispatcher) acknowledgeConsent(w http.ResponseWriter, r *http.Request) {
	consentHeaders(w)
	if d.intents == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "unavailable",
			"this deployment cannot serve consent pages")
		return
	}
	// A form this service rendered is a few hundred bytes; the bound is here so a
	// redemption cannot be turned into an allocation before anything is checked.
	// It is the second of the two this route has — internal/sealed bounds the
	// envelope at 4096 before attempting to open it — and between them they are
	// the only rate-shaping a service with no database can do. Request-rate limits
	// belong to whatever fronts this deployment.
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		logConsentRefusal("acknowledgement", err)
		httputil.WriteError(w, http.StatusNotFound, codeNoConsentPage, noConsentPage)
		return
	}
	token, err := d.intents.AcknowledgeConsent(
		r.Context(), r.URL.Query().Get("registration"), r.PostForm.Get("challenge"))
	if err != nil {
		if consentIsOurs(err) {
			httputil.WriteError(w, http.StatusServiceUnavailable, "unavailable",
				"this deployment cannot serve consent pages")
			return
		}
		logConsentRefusal("acknowledgement", err)
		httputil.WriteError(w, http.StatusNotFound, codeNoConsentPage, noConsentPage)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, struct {
		ConsentToken string `json:"consentToken"`
	}{token})
}

// noConsentPage and codeNoConsentPage are the ONE answer this route gives to
// every refusal that is not the deployment's own fault: no reference, a
// malformed one, one this deployment did not mint, one whose lane has no page,
// one carrying no sealed reference, and a challenge that does not redeem.
//
// 🔴 THEY MUST STAY ONE ANSWER, BECAUSE THE ROUTE IS NO LONGER GATED. A refusal
// that said which of those it was would let anyone holding a candidate learn
// whether it names a registration, turning a disclosure page into a probe of
// what MirrorStack has been asked to connect. The specific cause goes to the
// log, where an operator reads it and a requester does not.
const (
	noConsentPage     = "no consent page for this reference"
	codeNoConsentPage = "no_consent_page"
)

// consentIsOurs reports whether a refusal is the DEPLOYMENT's fault rather than
// the requester's — no keyset, an unreadable routing configuration — which is the
// one split this route may make out loud, because it is true of every reference
// alike and so reveals nothing about the one that was sent. intent.ErrUnavailable
// already carries derive.ErrConfig (intent.deriveError), so this is one test and
// not two.
func consentIsOurs(err error) bool { return errors.Is(err, intent.ErrUnavailable) }

// logConsentRefusal keeps the cause an operator needs on the side a requester
// cannot read. Info rather than Error: a stale link is normal traffic here.
func logConsentRefusal(half string, err error) {
	slog.Info("dns-delegate-api: consent refused", "half", half, "error", err)
}

// consentHeaders are set on EVERY answer this route gives, refusals included,
// which is why they are here and not beside the successful write.
//
// The URL carries the sealed registration and the page names an anchor with every
// value we would write beneath it: no-store keeps a shared cache from handing one
// customer's zone to the next request, and no-referrer keeps the envelope out of
// any Referer.
//
// The CSP makes a BROWSER enforce what the page already is. It loads nothing —
// no script, external stylesheet, font or image, one inline <style>, which
// internal/consent asserts in a test — so an edit adding a remote asset breaks
// visibly here rather than quietly widening what a consent screen depends on.
// form-action is 'self' rather than 'none' because the page carries the one form
// that acknowledges it, posting back to the URL it was served from.
// frame-ancestors is the header this route gained when the gate came off: a
// disclosure a customer's browser can now reach is one that can now be framed
// under a decoy button, and the agreement is a click on a form.
func consentHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "+
			"frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
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
		errors.Is(err, intent.ErrInvalidRequest),
		// lane.ErrInvalid wraps every identity, domain and slug refusal, and
		// arrives inside intent.ErrInvalidRequest today. Naming it keeps the
		// answer right if a future path returns one bare, and can only refine
		// `internal` into a code unambiguously the request's fault.
		errors.Is(err, lane.ErrInvalid):
		return "invalid_request"

	case errors.Is(err, intent.ErrUnavailable):
		return "unavailable"

	default:
		return "internal"
	}
}
