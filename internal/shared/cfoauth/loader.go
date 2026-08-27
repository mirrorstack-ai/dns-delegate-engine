package cfoauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// SecretIDEnv names the Secrets Manager secret holding {"client_id",
// "client_secret"}. When it is set, those two values are read AT RUNTIME rather
// than baked into the Lambda environment at deploy time.
//
// 🔴 THIS IS THE WHOLE POINT, and it is not merely tidier. A CloudFormation
// `{{resolve:secretsmanager:...}}` env var is resolved ONCE, at deploy. Putting
// a new value in the secret does not reach a running function — so rotating
// this credential would silently leave every Lambda authenticating with the old
// one until somebody happened to redeploy, and the failure would surface as
// Cloudflare rejecting token exchanges for reasons nothing in our logs explains.
const SecretIDEnv = "CF_OAUTH_SECRET_ID"

// successTTL bounds how long a good config is reused before it is re-read.
//
// DELIBERATELY DIFFERENT from the assertion-key resolver in
// internal/account/service, which caches success for the whole process
// lifetime. That is right for a key whose rotation implies a coordinated
// re-issue; it is wrong here, because the entire reason this loader exists is
// that the credential rotates underneath us. A process-lifetime cache would
// reintroduce the exact staleness the deploy-time env var had, just with a
// shorter and less predictable window.
//
// Five minutes is the trade: at most one GetSecretValue per five minutes per
// execution environment, and a rotation is picked up within five minutes with
// no deploy and no restart.
const successTTL = 5 * time.Minute

// failureTTL is short so a transient Secrets Manager error degrades the feature
// for seconds rather than for the life of the execution environment.
const failureTTL = 30 * time.Second

// SecretFetcher returns a secret's raw string value. An interface seam so tests
// drive rotation without AWS.
type SecretFetcher func(ctx context.Context, secretID string) (string, error)

// Loader resolves the client configuration, re-reading the secret on a TTL.
//
// The non-secret half (redirect URL, scopes, auth method) still comes from the
// environment: those are deployment topology, they change only with a deploy,
// and putting them in the secret would mean a rotation could silently alter the
// redirect_uri — which Cloudflare matches exactly.
type Loader struct {
	fetch SecretFetcher

	mu       sync.Mutex
	cfg      *Config
	loadedAt time.Time
	failedAt time.Time
}

func NewLoader(fetch SecretFetcher) *Loader { return &Loader{fetch: fetch} }

// NewDefaultLoader reads from Secrets Manager with the ambient AWS config.
func NewDefaultLoader() *Loader {
	return NewLoader(func(ctx context.Context, secretID string) (string, error) {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return "", fmt.Errorf("cfoauth: load aws config: %w", err)
		}
		out, err := secretsmanager.NewFromConfig(cfg).GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: &secretID,
		})
		if err != nil {
			return "", err
		}
		if out.SecretString == nil {
			return "", fmt.Errorf("cfoauth: secret %q has no string value", secretID)
		}
		return *out.SecretString, nil
	})
}

// Config returns the current client, or nil when this deployment cannot offer
// delegated DNS. Safe for concurrent use.
//
// nil is a TRUTHFUL state, not an error: callers report it as unavailable and
// the console renders no connect affordance at all, which is the right
// degradation. It is also indistinguishable from "misconfigured" outside the
// logs, which is why every refusal below logs distinctly.
func (l *Loader) Config(ctx context.Context) *Config {
	secretID := strings.TrimSpace(os.Getenv(SecretIDEnv))
	if secretID == "" {
		// No secret configured: fall back to plain env vars. This is the local
		// and dev path, and it keeps FromEnv the single place that validates
		// scopes, the auth method and the secret/method agreement.
		return FromEnv()
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.cfg != nil && now.Sub(l.loadedAt) < successTTL {
		return l.cfg
	}
	if l.cfg == nil && !l.failedAt.IsZero() && now.Sub(l.failedAt) < failureTTL {
		// Inside the negative-cache window. Returning nil WITHOUT re-fetching
		// stops a burst of requests each paying for its own failed API call.
		return nil
	}

	raw, err := l.fetch(ctx, secretID)
	if err != nil {
		// Keep serving the last good config if we have one. A Secrets Manager
		// blip must not take a working feature dark — the credential we hold is
		// still valid, we merely failed to re-read it.
		if l.cfg != nil {
			slog.Warn("cfoauth: re-reading the client secret failed; continuing with the cached client",
				"secret_id", secretID, "error", err)
			l.loadedAt = now
			return l.cfg
		}
		slog.Error("cfoauth: cannot read the Cloudflare OAuth client secret", "secret_id", secretID, "error", err)
		l.failedAt = now
		return nil
	}

	var payload struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		slog.Error("cfoauth: the Cloudflare OAuth secret is not the expected JSON object",
			"secret_id", secretID, "error", err)
		l.failedAt = now
		return nil
	}
	// An UNFILLED placeholder is the default state of a freshly deployed
	// environment: CDK creates the secret with empty strings and a human fills
	// it out of band. Treated as "not configured yet", not as an error, because
	// that is exactly what it is.
	if strings.TrimSpace(payload.ClientID) == "" {
		slog.Info("cfoauth: the Cloudflare OAuth secret is still the empty placeholder; delegated DNS stays unavailable",
			"secret_id", secretID)
		l.cfg = nil
		l.failedAt = now
		return nil
	}

	cfg := fromParts(payload.ClientID, payload.ClientSecret)
	if cfg == nil {
		// fromParts already logged which rule was broken.
		l.cfg = nil
		l.failedAt = now
		return nil
	}
	l.cfg = cfg
	l.loadedAt = now
	l.failedAt = time.Time{}
	return cfg
}
