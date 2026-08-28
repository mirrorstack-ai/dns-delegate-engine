package cfedge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// 🔴 NO TEST HERE READS SECRETS MANAGER. The fetcher is a seam so rotation, the
// unfilled placeholder and an unreadable secret are all checkable without an AWS
// account.

// 🔴 THE TOKEN MUST NOT BE ABLE TO REACH A LOG LINE OR AN ERROR STRING. It is
// wrapped by fmt at several removes — a slog attribute, an %w chain — and the
// one place it is meant to appear is a Bearer header, which converts explicitly.
func TestTheTokenRedactsItselfUnderEveryVerb(t *testing.T) {
	const secret = "cf-live-token-value"
	for _, rendered := range []string{
		fmt.Sprintf("%v", Token(secret)),
		fmt.Sprintf("%s", Token(secret)),
		fmt.Sprintf("%q", Token(secret)),
		fmt.Sprint(Token(secret)),
		fmt.Errorf("wrapped: %w", fmt.Errorf("carrying %v", Token(secret))).Error(),
	} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("the token rendered as %q", rendered)
		}
	}
	// Explicit, and only explicit, conversion reaches the wire.
	if string(Token(secret)) != secret {
		t.Fatal("an explicit conversion must still yield the token")
	}
}

// An unconfigured deployment says so distinctly, because internal/relay turns
// that answer into "not available yet" and every other answer into a warning.
func TestAnUnconfiguredDeploymentReportsErrNotConfigured(t *testing.T) {
	t.Setenv(SecretIDEnv, "")
	t.Setenv(TokenEnv, "")
	if Configured() {
		t.Fatal("Configured must be false when neither variable is set")
	}
	if _, err := NewLoader(nil).Token(t.Context()); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured, got %v", err)
	}
	if _, err := Static("")(t.Context()); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("an empty static token is not configured either, got %v", err)
	}
}

// The plain variable is the local path, taken only when no secret is named. A
// laptop has no Secrets Manager to read.
func TestThePlainVariableIsTheLocalFallback(t *testing.T) {
	t.Setenv(SecretIDEnv, "")
	t.Setenv(TokenEnv, "  local-token  ")
	if !Configured() {
		t.Fatal("Configured must see the plain variable")
	}
	token, err := NewLoader(nil).Token(t.Context())
	if err != nil || token != "local-token" {
		t.Fatalf("want the trimmed local token, got %q / %v", token, err)
	}
}

// 🔴 THE WHOLE REASON THIS LOADER EXISTS: a token rotated after the process
// started must be picked up without a redeploy. A deploy-time environment
// variable resolves once, so the old one would be used until somebody happened
// to redeploy.
func TestARotatedSecretIsPickedUpWhenTheCacheExpires(t *testing.T) {
	t.Setenv(SecretIDEnv, "cf/edge/token")
	t.Setenv(TokenEnv, "")
	current := `{"api_token":"first"}`
	reads := 0
	loader := NewLoader(func(context.Context, string) (string, error) {
		reads++
		return current, nil
	})
	if token, err := loader.Token(t.Context()); err != nil || token != "first" {
		t.Fatalf("first read: %q / %v", token, err)
	}
	current = `{"api_token":"second"}`
	if token, err := loader.Token(t.Context()); err != nil || token != "first" || reads != 1 {
		t.Fatalf("inside the TTL the cached token is served: %q / %v / %d reads", token, err, reads)
	}
	loader.loadedAt = loader.loadedAt.Add(-2 * successTTL)
	if token, err := loader.Token(t.Context()); err != nil || token != "second" || reads != 2 {
		t.Fatalf("after the TTL the rotated token must be read: %q / %v / %d reads", token, err, reads)
	}
}

// An UNFILLED secret is the default state of a freshly deployed environment —
// CDK creates it and a human fills it out of band — so it is "not configured",
// not a fault. A secret that cannot be READ is the fault, and the two must not
// collapse into one answer.
func TestAnUnfilledSecretIsNotConfiguredAndAnUnreadableOneIsAFault(t *testing.T) {
	t.Setenv(SecretIDEnv, "cf/edge/token")
	t.Setenv(TokenEnv, "")

	placeholder := NewLoader(func(context.Context, string) (string, error) {
		return `{"api_token":""}`, nil
	})
	if _, err := placeholder.Token(t.Context()); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("an empty placeholder is not configured yet, got %v", err)
	}
	// The negative-cache window must return the REMEMBERED answer, or a
	// placeholder would degrade into a fault on the very next call.
	if _, err := placeholder.Token(t.Context()); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("the cached refusal must keep its identity, got %v", err)
	}

	for name, fetch := range map[string]SecretFetcher{
		"unreadable": func(context.Context, string) (string, error) { return "", errors.New("access denied") },
		"not json":   func(context.Context, string) (string, error) { return "not-json", nil },
	} {
		_, err := NewLoader(fetch).Token(t.Context())
		if err == nil || errors.Is(err, ErrNotConfigured) {
			t.Fatalf("%s: want a fault distinct from ErrNotConfigured, got %v", name, err)
		}
	}
}

// A Secrets Manager blip must not take a working relay dark: the token we hold
// is still valid, we merely failed to re-read it.
func TestAFailedRereadKeepsServingTheCachedToken(t *testing.T) {
	t.Setenv(SecretIDEnv, "cf/edge/token")
	t.Setenv(TokenEnv, "")
	fail := false
	loader := NewLoader(func(context.Context, string) (string, error) {
		if fail {
			return "", errors.New("throttled")
		}
		return `{"api_token":"held"}`, nil
	})
	if _, err := loader.Token(t.Context()); err != nil {
		t.Fatalf("first read: %v", err)
	}
	fail = true
	loader.loadedAt = loader.loadedAt.Add(-2 * successTTL)
	if token, err := loader.Token(t.Context()); err != nil || token != "held" {
		t.Fatalf("want the cached token, got %q / %v", token, err)
	}
}
