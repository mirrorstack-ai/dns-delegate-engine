package cfoauth

import (
	"testing"

	"golang.org/x/oauth2"
)

// Every refusal in FromEnv returns nil, and a nil config is reported to the
// console as "unavailable" — which renders as NO connect affordance at all.
// That is the right degradation, but it means a misconfigured deployment and an
// unconfigured one look identical from outside the process. These are the only
// things that can tell them apart in CI.
func TestFromEnvRefusals(t *testing.T) {
	valid := map[string]string{
		"CF_OAUTH_CLIENT_ID":          "6270d3c6dd0e0836aa65df3b4b3ff6da",
		"CF_OAUTH_CLIENT_SECRET":      "s3cret",
		"CF_OAUTH_REDIRECT_URL":       "https://account.mirrorstack.ai/integrations/cloudflare/callback",
		"CF_OAUTH_SCOPES":             "zone.read dns.write",
		"CF_OAUTH_CLIENT_AUTH_METHOD": "client_secret_post",
	}

	tests := []struct {
		name    string
		mutate  map[string]string
		wantNil bool
		why     string
	}{
		{name: "fully configured", wantNil: false},
		{name: "unconfigured", mutate: map[string]string{"CF_OAUTH_CLIENT_ID": ""}, wantNil: true,
			why: "no client id is the DEFAULT state of every deployment that has not been given one"},
		{name: "no redirect url", mutate: map[string]string{"CF_OAUTH_REDIRECT_URL": ""}, wantNil: true,
			why: "the redirect is exact-match at Cloudflare; an empty one cannot be guessed"},
		{name: "no scopes", mutate: map[string]string{"CF_OAUTH_SCOPES": ""}, wantNil: true},
		{
			name:    "pre-#539 invented scope spellings",
			mutate:  map[string]string{"CF_OAUTH_SCOPES": "zone:read dns_records:edit"},
			wantNil: true,
			why: "these colon/underscore ids are not Cloudflare's and shipped once; " +
				"refusing takes the feature dark rather than over-requesting on a customer zone",
		},
		{
			name:    "scope outside the pinned ceiling",
			mutate:  map[string]string{"CF_OAUTH_SCOPES": "zone.read dns.write account.read"},
			wantNil: true,
			why:     "the ceiling is a maximum, not a default — a wider grant must not be reachable by config alone",
		},
		{
			name:    "confidential client with no secret",
			mutate:  map[string]string{"CF_OAUTH_CLIENT_SECRET": ""},
			wantNil: true,
			why:     "it cannot authenticate at all; discovering that at REVOCATION time leaves a live dns.write grant",
		},
		{
			name:    "public client shipping a secret",
			mutate:  map[string]string{"CF_OAUTH_CLIENT_AUTH_METHOD": "none"},
			wantNil: true,
			why:     "a public client that sends a secret is not the client that was registered",
		},
		{
			name:    "unsupported auth method",
			mutate:  map[string]string{"CF_OAUTH_CLIENT_AUTH_METHOD": "private_key_jwt"},
			wantNil: true,
			why:     "the token AND revocation endpoints both reject the wrong method",
		},
		{name: "auth method defaults to client_secret_post", mutate: map[string]string{"CF_OAUTH_CLIENT_AUTH_METHOD": ""}, wantNil: false},
		{name: "offline_access is admitted", mutate: map[string]string{"CF_OAUTH_SCOPES": "zone.read dns.write offline_access"}, wantNil: false,
			why: "Cloudflare attaches it to the registered client itself"},
		{
			name:    "the zone-scoped transform-rules scope is admitted",
			mutate:  map[string]string{"CF_OAUTH_SCOPES": "zone.read dns.write zone-transform-rules.write"},
			wantNil: false,
			why: "a white-label host in a customer's own zone cannot be reached by OUR transform rule, " +
				"so their zone has to inject the edge headers itself",
		},
		{
			name:    "the ACCOUNT-scoped transform-rules sibling is refused",
			mutate:  map[string]string{"CF_OAUTH_SCOPES": "zone.read dns.write transform-rules.write"},
			wantNil: true,
			why: "the two ids differ by one prefix and the account-scoped one asks for authority " +
				"over every zone in the customer's account, not the one they picked",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range valid {
				t.Setenv(k, v)
			}
			for k, v := range tc.mutate {
				t.Setenv(k, v)
			}
			got := FromEnv()
			if tc.wantNil && got != nil {
				t.Fatalf("FromEnv returned a config, want nil — %s", tc.why)
			}
			if !tc.wantNil && got == nil {
				t.Fatalf("FromEnv returned nil, want a config — this configuration is valid and the feature would be dark")
			}
		})
	}
}

// The endpoints and auth style are properties of the REGISTERED client, so they
// are pinned as literals rather than re-derived from the same expression the
// implementation uses.
func TestFromEnvBuildsTheRegisteredClient(t *testing.T) {
	t.Setenv("CF_OAUTH_CLIENT_ID", "cid")
	t.Setenv("CF_OAUTH_CLIENT_SECRET", "sec")
	t.Setenv("CF_OAUTH_REDIRECT_URL", "https://account.mirrorstack.ai/integrations/cloudflare/callback")
	t.Setenv("CF_OAUTH_SCOPES", "zone.read dns.write")
	t.Setenv("CF_OAUTH_CLIENT_AUTH_METHOD", "client_secret_basic")

	cfg := FromEnv()
	if cfg == nil {
		t.Fatal("FromEnv returned nil for a valid configuration")
	}
	if cfg.Endpoint.AuthURL != "https://dash.cloudflare.com/oauth2/auth" {
		t.Errorf("AuthURL = %q", cfg.Endpoint.AuthURL)
	}
	if cfg.Endpoint.TokenURL != "https://dash.cloudflare.com/oauth2/token" {
		t.Errorf("TokenURL = %q", cfg.Endpoint.TokenURL)
	}
	if cfg.RevokeURL != "https://dash.cloudflare.com/oauth2/revoke" {
		t.Errorf("RevokeURL = %q — a wrong one means revocation silently no-ops and the grant survives", cfg.RevokeURL)
	}
	// client_secret_basic must put credentials in the HEADER. Sending them in
	// params instead is rejected by the token endpoint AND the revocation
	// endpoint, and a rejected revocation leaves a live grant on a customer zone.
	if cfg.Endpoint.AuthStyle != oauth2.AuthStyleInHeader {
		t.Errorf("AuthStyle = %v, want AuthStyleInHeader for client_secret_basic", cfg.Endpoint.AuthStyle)
	}
}

// StateHash must not be reversible to the state that travelled through the
// customer's browser and Cloudflare's redirect.
func TestStateHashIsStableAndNotThePlaintext(t *testing.T) {
	a, b := StateHash("abc"), StateHash("abc")
	if string(a) != string(b) {
		t.Fatal("StateHash is not deterministic — no attempt could ever be consumed")
	}
	if string(a) == "abc" {
		t.Fatal("StateHash returned the plaintext")
	}
	if len(a) != 32 {
		t.Fatalf("StateHash length = %d, want 32", len(a))
	}
	if string(StateHash("abd")) == string(a) {
		t.Fatal("StateHash collides on a one-character change")
	}
}
