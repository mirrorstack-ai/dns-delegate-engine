package cfoauth

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func topology(t *testing.T) {
	t.Helper()
	t.Setenv("CF_OAUTH_REDIRECT_URL", "https://account.mirrorstack.ai/integrations/cloudflare/callback")
	t.Setenv("CF_OAUTH_SCOPES", "zone.read dns.write")
	t.Setenv("CF_OAUTH_CLIENT_AUTH_METHOD", "client_secret_post")
	t.Setenv("CF_OAUTH_CLIENT_ID", "")
	t.Setenv("CF_OAUTH_CLIENT_SECRET", "")
}

// The reason this loader exists. A deploy-time env var is resolved ONCE, so a
// rotated credential would never reach a running Lambda; this asserts a new
// value IS picked up, with no redeploy and no restart.
func TestLoaderPicksUpARotatedSecret(t *testing.T) {
	topology(t)
	t.Setenv(SecretIDEnv, "mirrorstack-prod-cf-oauth")

	current := `{"client_id":"cid-1","client_secret":"old"}`
	calls := 0
	l := NewLoader(func(ctx context.Context, id string) (string, error) {
		calls++
		return current, nil
	})

	first := l.Config(context.Background())
	if first == nil || first.ClientSecret != "old" {
		t.Fatalf("first read = %+v, want the current secret", first)
	}

	// Rotation. Expiring the cache stands in for the TTL elapsing — asserting
	// against real time would make this test sleep for minutes.
	current = `{"client_id":"cid-1","client_secret":"new"}`
	l.loadedAt = l.loadedAt.Add(-successTTL - 1)

	second := l.Config(context.Background())
	if second == nil || second.ClientSecret != "new" {
		t.Fatalf("after rotation = %+v, want the NEW secret — a stale client "+
			"fails token exchange at Cloudflare for reasons nothing in our logs explains", second)
	}
	if calls != 2 {
		t.Fatalf("fetches = %d, want 2", calls)
	}
}

// Within the TTL the secret must NOT be re-read on every request: this is on the
// path of an interactive console action, and a GetSecretValue per click is both
// latency and a throttling risk.
func TestLoaderCachesWithinTTL(t *testing.T) {
	topology(t)
	t.Setenv(SecretIDEnv, "s")
	calls := 0
	l := NewLoader(func(ctx context.Context, id string) (string, error) {
		calls++
		return `{"client_id":"cid","client_secret":"sec"}`, nil
	})
	for range 5 {
		if l.Config(context.Background()) == nil {
			t.Fatal("Config returned nil for a valid secret")
		}
	}
	if calls != 1 {
		t.Fatalf("fetches = %d, want 1 — the cache is not holding", calls)
	}
}

// A Secrets Manager blip must not take a WORKING feature dark. The credential
// already in hand is still valid; we merely failed to re-read it.
func TestLoaderKeepsLastGoodConfigWhenReReadFails(t *testing.T) {
	topology(t)
	t.Setenv(SecretIDEnv, "s")
	fail := false
	l := NewLoader(func(ctx context.Context, id string) (string, error) {
		if fail {
			return "", errors.New("throttled")
		}
		return `{"client_id":"cid","client_secret":"sec"}`, nil
	})
	if l.Config(context.Background()) == nil {
		t.Fatal("first read failed")
	}
	fail = true
	l.loadedAt = l.loadedAt.Add(-successTTL - 1)
	if got := l.Config(context.Background()); got == nil || got.ClientSecret != "sec" {
		t.Fatal("a transient fetch error took a working client down; it must keep serving the cached one")
	}
}

// The DEFAULT state of a freshly deployed environment: CDK creates the secret
// with empty strings and a human fills it out of band.
//
// 🔴 THE ASSERTION IS THE LOG, NOT THE NIL — and that distinction was found by
// mutation, not by reasoning. fromParts already returns nil for an empty client
// id, so an earlier version of this test asserting only "Config == nil" passed
// with the placeholder branch DELETED. What the branch uniquely provides is an
// operator-facing signal separating "nobody has run put-secret-value yet" from
// "misconfigured", and on this path a missing log IS the bug: every refusal here
// is otherwise invisible from outside the process.
func TestLoaderLogsThatThePlaceholderIsStillEmpty(t *testing.T) {
	topology(t)
	t.Setenv(SecretIDEnv, "s")

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	l := NewLoader(func(ctx context.Context, id string) (string, error) {
		return `{"client_id":"","client_secret":""}`, nil
	})
	if l.Config(context.Background()) != nil {
		t.Fatal("an unfilled placeholder produced a config — the console would show a button that dies at Cloudflare")
	}
	if !strings.Contains(buf.String(), "empty placeholder") {
		t.Fatalf("no placeholder log was emitted; an operator has no way to tell "+
			"\"not filled in yet\" from \"misconfigured\". got=%q", buf.String())
	}
}

// A failure must not be re-fetched on every request in a burst.
func TestLoaderNegativeCachesFailures(t *testing.T) {
	topology(t)
	t.Setenv(SecretIDEnv, "s")
	calls := 0
	l := NewLoader(func(ctx context.Context, id string) (string, error) {
		calls++
		return "", errors.New("boom")
	})
	for range 4 {
		if l.Config(context.Background()) != nil {
			t.Fatal("Config returned a client despite a failing fetch")
		}
	}
	if calls != 1 {
		t.Fatalf("fetches = %d, want 1 — every request is paying for its own failed API call", calls)
	}
}

// Without the secret id the loader falls back to plain env vars, so local
// development needs no AWS at all.
func TestLoaderFallsBackToEnvWithoutASecretID(t *testing.T) {
	topology(t)
	t.Setenv(SecretIDEnv, "")
	t.Setenv("CF_OAUTH_CLIENT_ID", "cid")
	t.Setenv("CF_OAUTH_CLIENT_SECRET", "sec")

	l := NewLoader(func(ctx context.Context, id string) (string, error) {
		t.Fatal("fetched from Secrets Manager despite no secret id being set")
		return "", nil
	})
	if got := l.Config(context.Background()); got == nil || got.ClientID != "cid" {
		t.Fatalf("env fallback = %+v, want the env-configured client", got)
	}
}

// Malformed JSON is a misconfiguration, not a valid client.
func TestLoaderRefusesMalformedSecret(t *testing.T) {
	topology(t)
	t.Setenv(SecretIDEnv, "s")
	l := NewLoader(func(ctx context.Context, id string) (string, error) { return "not json", nil })
	if l.Config(context.Background()) != nil {
		t.Fatal("malformed secret produced a config")
	}
}
