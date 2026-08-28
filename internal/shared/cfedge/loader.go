package cfedge

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

// SecretIDEnv names the Secrets Manager secret holding {"api_token"}. Reading it
// AT RUNTIME rather than baking it into the Lambda environment is the whole
// point: a CloudFormation `{{resolve:secretsmanager:...}}` env var resolves once,
// at deploy, so rotating this token would leave every running function reading
// MirrorStack's zones with the old one until somebody happened to redeploy
// (cfoauth.SecretIDEnv says the same, for the same reason).
const SecretIDEnv = "CF_EDGE_TOKEN_SECRET_ID"

// TokenEnv is the plain-variable fallback for local runs, taken only when
// SecretIDEnv is unset. A laptop has no Secrets Manager to read.
const TokenEnv = "CF_EDGE_API_TOKEN"

// successTTL and failureTTL mirror cfoauth.Loader and grantcrypto.Loader
// exactly: a process-lifetime cache would reintroduce the deploy-time staleness
// this loader exists to remove.
const (
	successTTL = 5 * time.Minute
	failureTTL = 30 * time.Second
)

// SecretFetcher returns a secret's raw string value. A seam so tests drive
// rotation without AWS.
type SecretFetcher func(ctx context.Context, secretID string) (string, error)

// Configured reports whether this deployment names an edge token at all. The
// binary asks BEFORE it wires the relay, so an unconfigured deployment passes a
// nil reader rather than one that fails every pass.
func Configured() bool {
	return strings.TrimSpace(os.Getenv(SecretIDEnv)) != "" ||
		strings.TrimSpace(os.Getenv(TokenEnv)) != ""
}

// Loader resolves the token, re-reading the secret on a TTL.
type Loader struct {
	fetch SecretFetcher

	mu       sync.Mutex
	token    Token
	failure  error
	loadedAt time.Time
	failedAt time.Time
}

func NewLoader(fetch SecretFetcher) *Loader { return &Loader{fetch: fetch} }

// NewDefaultLoader reads from Secrets Manager with the ambient AWS config.
func NewDefaultLoader() *Loader {
	return NewLoader(func(ctx context.Context, secretID string) (string, error) {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return "", fmt.Errorf("cfedge: load aws config: %w", err)
		}
		out, err := secretsmanager.NewFromConfig(cfg).GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: &secretID,
		})
		if err != nil {
			return "", err
		}
		if out.SecretString == nil {
			return "", fmt.Errorf("cfedge: secret %q has no string value", secretID)
		}
		return *out.SecretString, nil
	})
}

// Token is a Source: it returns the current token, or says why there is none.
// Safe for concurrent use.
//
// 🔴 THE TWO WAYS TO HAVE NO TOKEN ARE DIFFERENT ANSWERS. An unfilled secret is
// ErrNotConfigured, which internal/relay reports as "not available yet"; a
// secret that cannot be read or parsed is an ordinary error, which surfaces as a
// warning on the pass. Collapsing them would make a deployment nobody finished
// look exactly like one whose IAM policy is wrong.
func (l *Loader) Token(ctx context.Context) (Token, error) {
	secretID := strings.TrimSpace(os.Getenv(SecretIDEnv))
	if secretID == "" {
		if token := strings.TrimSpace(os.Getenv(TokenEnv)); token != "" {
			return Token(token), nil
		}
		return "", ErrNotConfigured
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.token != "" && now.Sub(l.loadedAt) < successTTL {
		return l.token, nil
	}
	if l.token == "" && !l.failedAt.IsZero() && now.Sub(l.failedAt) < failureTTL {
		// Inside the negative-cache window: the remembered answer, WITHOUT a
		// second API call. Remembered rather than recomputed so a placeholder
		// keeps reporting ErrNotConfigured instead of degrading to a fault.
		return "", l.failure
	}

	raw, err := l.fetch(ctx, secretID)
	if err != nil {
		// A Secrets Manager blip must not take a working relay dark: the token we
		// hold is still valid, we merely failed to re-read it.
		if l.token != "" {
			slog.Warn("cfedge: re-reading the MirrorStack Cloudflare token failed; continuing with the cached one",
				"secret_id", secretID, "error", err)
			l.loadedAt = now
			return l.token, nil
		}
		return l.fail(now, fmt.Errorf("cfedge: cannot read the MirrorStack Cloudflare token: %w", err))
	}

	var payload struct {
		APIToken string `json:"api_token"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		// The raw value is never echoed; it is the secret.
		return l.fail(now, fmt.Errorf("cfedge: secret %q is not the expected JSON object: %w", secretID, err))
	}
	if strings.TrimSpace(payload.APIToken) == "" {
		// The default state of a freshly deployed environment: CDK creates the
		// secret and a human fills it out of band.
		slog.Info("cfedge: the MirrorStack Cloudflare token is still the empty placeholder; the serving proof stays unavailable",
			"secret_id", secretID)
		return l.fail(now, ErrNotConfigured)
	}

	l.token, l.loadedAt, l.failedAt, l.failure = Token(strings.TrimSpace(payload.APIToken)), now, time.Time{}, nil
	return l.token, nil
}

// fail records a refusal for the negative-cache window and returns it. The token
// is cleared: a value that failed to re-read must not be served as current.
func (l *Loader) fail(now time.Time, err error) (Token, error) {
	l.token, l.failedAt, l.failure = "", now, err
	return "", err
}
