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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/auth"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/config"
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

// pinger is the narrow slice of *pgxpool.Pool the readiness probe needs, as an
// interface so the probe is testable without a database.
type pinger interface {
	Ping(context.Context) error
}

type dispatcher struct {
	// db is nil until a deployment supplies DATABASE_URL. A nil pool is a
	// truthful "not ready", never a panic.
	db pinger
}

func (d *dispatcher) dispatch(ctx context.Context, action string, _ json.RawMessage) (any, error) {
	switch action {
	case "Health":
		return d.health(ctx), nil
	default:
		return nil, fmt.Errorf("%w: %q", errUnknownAction, action)
	}
}

type healthResponse struct {
	OK       bool   `json:"ok"`
	Database string `json:"database"`
}

// health reports whether the service can reach its database. It is the arming
// check for the deploy: the stack, the RDS-Proxy grant, the IAM database role
// and the VPC path are all either working here or not working at all.
func (d *dispatcher) health(ctx context.Context) healthResponse {
	if d.db == nil {
		return healthResponse{OK: false, Database: "unconfigured"}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := d.db.Ping(ctx); err != nil {
		slog.Error("dns-delegate: database ping failed", "error", err)
		return healthResponse{OK: false, Database: "unreachable"}
	}
	return healthResponse{OK: true, Database: "ok"}
}

func main() {
	var pool *pgxpool.Pool
	if os.Getenv("DATABASE_URL") != "" {
		pool = config.MustPgxPool()
		defer pool.Close()
	}
	d := &dispatcher{}
	// A typed nil *pgxpool.Pool in an interface is non-nil, and the health
	// check's `d.db == nil` would then be false and Ping would panic. Assign
	// only when there is a real pool.
	if pool != nil {
		d.db = pool
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
		code := "internal"
		if errors.Is(err, errUnknownAction) {
			code = "unknown_action"
		}
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
