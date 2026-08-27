// Package cfoauth holds the Cloudflare OAuth client configuration shared by
// every service that asks a customer for delegated DNS access.
//
// It exists because there are now TWO such flows against ONE registered
// Cloudflare client — app domains (internal/applications) and org domains
// (internal/organizations) — and the client's scopes, endpoints and token-auth
// method are properties of that registration, not of either caller. A second
// hand-maintained copy would drift, and the failure mode of drift here is
// silent: every rejection path returns nil, the console renders no connect
// affordance at all, and "misconfigured" is indistinguishable from "not
// deployed yet" outside one log line.
package cfoauth

import (
	"crypto/sha256"
	"log/slog"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// TTL bounds how long an authorization attempt stays usable. Short on purpose:
// the row carries PKCE material and ownership context, and the user is mid-flow
// in another tab, not coming back tomorrow.
const TTL = 10 * time.Minute

// Token-endpoint client authentication methods, spelled the way Cloudflare's
// own "create an OAuth client" screen spells them (RFC 7591 §2). The registered
// client decides which one is correct; guessing is not an option, because the
// token endpoint and the revocation endpoint both reject the wrong one — and a
// rejected revocation leaves a live dns.write grant on a customer's zone.
const (
	AuthClientSecretPost  = "client_secret_post"
	AuthClientSecretBasic = "client_secret_basic"
	AuthNone              = "none"
)

// AllowedScopes is the CEILING, not a default. Anything outside it makes
// FromEnv refuse rather than over-request against a customer's zone.
//
// The ids are DOTTED. `zone:read`/`dns_records:edit` are invented spellings
// that shipped once and are not Cloudflare's. offline_access is admitted
// because Cloudflare attaches it to the registered client itself — the client
// 6270d3c6… was registered with [zone.read dns.write] and came back carrying
// offline_access — so a token response mentioning it is normal.
//
// 🔴 zone-transform-rules.write IS THE ZONE-SCOPED ID. Its account-scoped
// sibling is spelled `transform-rules.write`, and the two are not
// interchangeable: this flow holds a grant on ONE zone the customer picked, so
// the account-scoped id would ask for authority over every zone in their
// account — which a careful customer should refuse, and a careless one should
// not have to.
//
// 🔴 THE REGISTERED CLIENT DOES NOT HOLD THIS SCOPE YET. 6270d3c6… was
// registered with [zone.read dns.write], and widening it is a manual,
// owner-approved change to the live client — a partial PATCH of an OAuth client
// risks clearing its exact-match redirect_uris and taking the entire connect
// flow dark. Admitting the id here only means CF_OAUTH_SCOPES may name it; until
// the client is widened, Cloudflare issues a token without it and the ruleset
// write 403s. That failure is non-fatal by construction (see the organizations
// service's publishEdgeTransform), so this ships INERT rather than broken.
var AllowedScopes = map[string]struct{}{
	"zone.read":                  {},
	"dns.write":                  {},
	"zone-transform-rules.write": {},
	"offline_access":             {},
}

// Config is the registered client plus the two endpoints oauth2.Config has no
// field for.
type Config struct {
	oauth2.Config
	RevokeURL  string
	AuthMethod string
}

// FromEnv builds the client, or returns nil when this deployment has not been
// given one.
//
// 🔴 EVERY refusal returns nil, and a nil config is reported to callers as
// "unavailable" — which the console renders as no connect affordance at all.
// That is the right degradation (a dead button that fails on Cloudflare's own
// consent screen is worse), but it means an unconfigured deployment and a
// MISCONFIGURED one look identical from outside. Each branch below logs
// distinctly for exactly that reason; CloudWatch is the only place they differ.
func FromEnv() *Config {
	return fromParts(
		strings.TrimSpace(os.Getenv("CF_OAUTH_CLIENT_ID")),
		strings.TrimSpace(os.Getenv("CF_OAUTH_CLIENT_SECRET")),
	)
}

// fromParts validates a client id and secret against the environment-supplied
// topology (redirect URL, scopes, auth method).
//
// Split out so the two sources of the CREDENTIAL — plain env vars for local
// development, Secrets Manager at runtime in a deployment — cannot disagree
// about what makes a client valid. Every refusal below is silent from outside
// the process, so a second copy of these rules would be a second place for the
// feature to go dark for reasons nobody can see.
func fromParts(clientID, clientSecret string) *Config {
	redirectURL := strings.TrimSpace(os.Getenv("CF_OAUTH_REDIRECT_URL"))
	scopes := strings.Fields(os.Getenv("CF_OAUTH_SCOPES"))
	if clientID == "" || redirectURL == "" || len(scopes) == 0 {
		return nil
	}
	authMethod := strings.TrimSpace(os.Getenv("CF_OAUTH_CLIENT_AUTH_METHOD"))
	if authMethod == "" {
		authMethod = AuthClientSecretPost
	}
	var authStyle oauth2.AuthStyle
	switch authMethod {
	case AuthClientSecretPost, AuthNone:
		authStyle = oauth2.AuthStyleInParams
	case AuthClientSecretBasic:
		authStyle = oauth2.AuthStyleInHeader
	default:
		slog.Error("cfoauth: refusing to configure Cloudflare OAuth — CF_OAUTH_CLIENT_AUTH_METHOD is not supported",
			"auth_method", authMethod)
		return nil
	}
	// The secret and the method must agree, or every provider call is
	// mis-authenticated: a confidential client with no secret cannot
	// authenticate at all, and a public client that ships one is not the client
	// that was registered. Refuse rather than discover it at revocation time.
	if authMethod != AuthNone && clientSecret == "" {
		slog.Error("cfoauth: refusing to configure Cloudflare OAuth — confidential client authentication requires CF_OAUTH_CLIENT_SECRET",
			"auth_method", authMethod)
		return nil
	}
	if authMethod == AuthNone && clientSecret != "" {
		slog.Error("cfoauth: refusing to configure Cloudflare OAuth — public client authentication requires an empty CF_OAUTH_CLIENT_SECRET",
			"auth_method", authMethod)
		return nil
	}
	for _, scope := range scopes {
		if _, ok := AllowedScopes[scope]; !ok {
			slog.Error("cfoauth: refusing to configure Cloudflare OAuth — CF_OAUTH_SCOPES requests a scope outside the pinned minimum",
				"scope", scope)
			return nil
		}
	}
	return &Config{
		Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:   "https://dash.cloudflare.com/oauth2/auth",
				TokenURL:  "https://dash.cloudflare.com/oauth2/token",
				AuthStyle: authStyle,
			},
		},
		RevokeURL:  "https://dash.cloudflare.com/oauth2/revoke",
		AuthMethod: authMethod,
	}
}

// StateHash is what the attempts table stores. The raw state travels in a URL
// through the customer's browser and Cloudflare's redirect; hashing it means a
// leaked URL or a logged referer cannot be replayed against the row.
func StateHash(state string) []byte {
	sum := sha256.Sum256([]byte(state))
	return sum[:]
}
