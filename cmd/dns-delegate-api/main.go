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
// This binary holds no business actions yet. It exists so the artifact, the
// publish role, the SSM pointer, the stack, the database role and the invoke
// grant can all be built and PROVEN before any credential path moves into them
// — an arming path that is first exercised in production is not armed.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/grant"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/provider/cloudflare"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/reconcile"
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
	grants *grant.Service
}

func (d *dispatcher) dispatch(ctx context.Context, action string, payload json.RawMessage) (any, error) {
	switch action {
	case "Health":
		return d.health(ctx), nil
	case "Capabilities":
		if d.grants == nil {
			return grant.CapabilitiesResponse{}, nil
		}
		return d.grants.Capabilities(ctx), nil
	case "Authorize":
		return decodeAnd(payload, d.grants, (*grant.Service).Authorize)
	case "Publish":
		return decodeAnd(payload, d.grants, (*grant.Service).Publish)
	case "Revoke":
		return decodeAnd(payload, d.grants, (*grant.Service).Revoke)
	default:
		return nil, fmt.Errorf("%w: %q", errUnknownAction, action)
	}
}

// decodeAnd unmarshals one action's request and runs it. A malformed payload is
// errInvalidInput, never the action's own failure vocabulary: the caller must be
// able to tell "you sent nonsense" from "the provider refused".
func decodeAnd[Req any, Res any](
	payload json.RawMessage,
	svc *grant.Service,
	run func(*grant.Service, context.Context, Req) (Res, error),
) (any, error) {
	var zero Res
	if svc == nil {
		return zero, grant.ErrUnavailable
	}
	var req Req
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &req); err != nil {
			return zero, fmt.Errorf("%w: %v", errInvalidInput, err)
		}
	}
	return run(svc, context.Background(), req)
}

type healthResponse struct {
	OK bool `json:"ok"`
	// Delegation reports whether this deployment can actually offer delegated
	// DNS: "ready" (client and keyset), "no-keyset" (client only — grants can be
	// published but not held), or "unconfigured".
	Delegation string `json:"delegation"`
}

// health is the arming check for a deploy. It resolves the credentials the same
// way a real request does — through the runtime loaders, so a secret filled in
// after this Lambda started counts — without contacting the provider.
func (d *dispatcher) health(ctx context.Context) healthResponse {
	if d.grants == nil {
		return healthResponse{Delegation: "unconfigured"}
	}
	caps := d.grants.Capabilities(ctx)
	switch {
	case !caps.Available:
		return healthResponse{Delegation: "unconfigured"}
	case !caps.CanHold:
		return healthResponse{OK: true, Delegation: "no-keyset"}
	default:
		return healthResponse{OK: true, Delegation: "ready"}
	}
}

func main() {
	d := &dispatcher{grants: &grant.Service{
		OAuth: cfoauth.NewDefaultLoader(),
		Keys:  grantcrypto.NewDefaultLoader(),
		// Cloudflare is the first provider. A second one is an adapter beside it
		// plus a selector here; every safety rule stays in reconcile.
		Publisher: reconcile.Publisher{Provider: cloudflare.Client{}},
	}}

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
	mux.Handle("/", auth.InternalSecret(secret)(gated))
	return mux
}

// errorCode maps an engine error onto the caller's contract.
//
// 🔴 THE CALLER ACTS ON THESE. `unavailable` and `invalid_request` mean nothing
// was consumed; a plan refusal means the plan is wrong and retrying it cannot
// help. Anything unrecognised falls through to `internal`, which the caller must
// treat as a retry — never as a reason to release a grant.
func errorCode(err error) string {
	switch {
	case errors.Is(err, errUnknownAction):
		return "unknown_action"
	case errors.Is(err, errInvalidInput), errors.Is(err, grant.ErrInvalidRequest):
		return "invalid_request"
	case errors.Is(err, grant.ErrUnavailable):
		return "unavailable"
	case errors.Is(err, dnsplan.ErrAnchorEscape):
		return "anchor_escape"
	case errors.Is(err, dnsplan.ErrPlanChanged):
		return "plan_changed"
	case errors.Is(err, dnsplan.ErrPlanPreparing):
		return "plan_preparing"
	case errors.Is(err, dnsplan.ErrPlanInvalid):
		return "plan_invalid"
	default:
		return "internal"
	}
}
