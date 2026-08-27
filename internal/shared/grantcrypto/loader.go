package grantcrypto

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// SecretIDEnv names the Secrets Manager secret holding the keyset. Unset means
// this deployment does not hold grants at all — see Loader.Sealer.
const SecretIDEnv = "CF_GRANT_KEYSET_SECRET_ID"

// successTTL and failureTTL mirror cfoauth.Loader exactly, and for the same
// reason: the whole point of reading at runtime is that the value can rotate
// underneath a running function, so a process-lifetime cache would reintroduce
// the staleness a deploy-time env var already had.
const (
	successTTL = 5 * time.Minute
	failureTTL = 30 * time.Second
)

// SecretFetcher returns a secret's raw string value. An interface seam so tests
// drive rotation without AWS.
type SecretFetcher func(ctx context.Context, secretID string) (string, error)

// Loader resolves the sealer, re-reading the secret on a TTL.
type Loader struct {
	fetch SecretFetcher

	mu       sync.Mutex
	sealer   *Sealer
	loadedAt time.Time
	failedAt time.Time
}

func NewLoader(fetch SecretFetcher) *Loader { return &Loader{fetch: fetch} }

// NewDefaultLoader reads from Secrets Manager with the ambient AWS config.
func NewDefaultLoader() *Loader {
	return NewLoader(func(ctx context.Context, secretID string) (string, error) {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return "", fmt.Errorf("grantcrypto: load aws config: %w", err)
		}
		out, err := secretsmanager.NewFromConfig(cfg).GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: &secretID,
		})
		if err != nil {
			return "", err
		}
		if out.SecretString == nil {
			return "", fmt.Errorf("grantcrypto: secret %q has no string value", secretID)
		}
		return *out.SecretString, nil
	})
}

// Sealer returns the sealer for THIS request, or nil.
//
// 🔴 NIL IS A SUPPORTED, FAIL-CLOSED ANSWER, and every caller must treat it as
// "do not hold a grant" — which means revoking the token immediately, exactly
// as this flow behaved before held grants existed. It must never be read as
// "store the token unsealed": a deployment that has not been given a keyset is
// the normal state of every dev box and of production before the secret is
// created, and the worst possible response to that is a plaintext customer
// credential in a table.
//
// Each refusal logs distinctly, because from outside they are identical.
func (l *Loader) Sealer(ctx context.Context) *Sealer {
	secretID := strings.TrimSpace(os.Getenv(SecretIDEnv))
	if secretID == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.sealer != nil && now.Sub(l.loadedAt) < successTTL {
		return l.sealer
	}
	if !l.failedAt.IsZero() && now.Sub(l.failedAt) < failureTTL {
		return l.sealer // possibly nil; a recent failure is not retried per-request
	}
	raw, err := l.fetch(ctx, secretID)
	if err != nil {
		l.failedAt = now
		slog.Error("grantcrypto: could not read the grant keyset; delegated grants will not be held this window",
			"secret_id", secretID, "error", err)
		return l.sealer
	}
	keys, err := ParseKeyset(raw)
	if err != nil {
		l.failedAt = now
		// The VALUE is never logged, only the shape complaint.
		slog.Error("grantcrypto: the grant keyset is unusable; delegated grants will not be held",
			"secret_id", secretID, "error", err)
		return l.sealer
	}
	sealer, err := NewSealer(keys)
	if err != nil {
		l.failedAt = now
		slog.Error("grantcrypto: keyset produced no sealer", "secret_id", secretID, "error", err)
		return l.sealer
	}
	l.sealer, l.loadedAt, l.failedAt = sealer, now, time.Time{}
	return l.sealer
}
