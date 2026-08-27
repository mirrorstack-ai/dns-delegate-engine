package grant

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/reconcile"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/cfoauth"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/grantcrypto"
)

// RPC-level errors. These are the refusals that consume NOTHING, so the caller
// can safely treat them as "nothing happened".
var (
	// ErrUnavailable means this deployment has no OAuth client. It is a truthful
	// state, not a fault: the console renders no connect affordance at all,
	// which beats a button that fails on the provider's own consent screen.
	ErrUnavailable = errors.New("grant: delegated DNS unavailable")
	// ErrInvalidRequest covers a malformed or self-contradictory request.
	ErrInvalidRequest = errors.New("grant: invalid request")
)

// oauthLoader and keyLoader are the two credential sources, as interfaces so a
// test drives them without AWS.
type oauthLoader interface {
	Config(ctx context.Context) *cfoauth.Config
}

type keyLoader interface {
	Sealer(ctx context.Context) *grantcrypto.Sealer
}

// Service is the RPC implementation.
type Service struct {
	OAuth     oauthLoader
	Keys      keyLoader
	Publisher reconcile.Publisher

	// HTTPClient is used for token exchange, refresh and revocation. Nil means
	// a 10-second default.
	HTTPClient *http.Client
}

func (s *Service) httpClient() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// oauthConfig resolves the client for THIS request.
//
// Per-request, not per-process: the loader re-reads the secret on a TTL, so a
// credential filled in or rotated after this Lambda started is picked up without
// a redeploy — which is the entire reason the loader exists.
func (s *Service) oauthConfig(ctx context.Context) *cfoauth.Config {
	if s.OAuth == nil {
		return nil
	}
	return s.OAuth.Config(ctx)
}

func (s *Service) sealer(ctx context.Context) *grantcrypto.Sealer {
	if s.Keys == nil {
		return nil
	}
	return s.Keys.Sealer(ctx)
}

// Capabilities reports what this deployment can offer.
func (s *Service) Capabilities(ctx context.Context) CapabilitiesResponse {
	out := CapabilitiesResponse{Provider: s.providerName()}
	cfg := s.oauthConfig(ctx)
	if cfg == nil {
		return out
	}
	out.Available = true
	out.Scopes = cfg.Scopes
	out.CanHold = s.sealer(ctx) != nil
	return out
}

func (s *Service) providerName() string {
	if s.Publisher.Provider == nil {
		return ""
	}
	return s.Publisher.Provider.Name()
}

// Authorize builds the URL the customer is sent to.
//
// The client id, redirect URL and scope list come from this service's own
// configuration, never from the request, so a caller cannot widen what a
// customer is asked to approve.
func (s *Service) Authorize(ctx context.Context, req AuthorizeRequest) (AuthorizeResponse, error) {
	cfg := s.oauthConfig(ctx)
	if cfg == nil {
		return AuthorizeResponse{}, ErrUnavailable
	}
	if strings.TrimSpace(req.State) == "" || strings.TrimSpace(req.CodeChallenge) == "" {
		return AuthorizeResponse{}, fmt.Errorf("%w: state and codeChallenge are required", ErrInvalidRequest)
	}
	return AuthorizeResponse{AuthorizationURL: cfg.AuthCodeURL(req.State,
		oauth2.SetAuthURLParam("code_challenge", req.CodeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)}, nil
}

// Publish is the one call that touches a customer's zone.
func (s *Service) Publish(ctx context.Context, req PublishRequest) (PublishResponse, error) {
	cfg := s.oauthConfig(ctx)
	if cfg == nil {
		return PublishResponse{}, ErrUnavailable
	}

	// ── Everything below this line happens BEFORE a credential is used. Every
	// refusal here is an RPC error, because nothing was consumed. ─────────────
	hasCode := strings.TrimSpace(req.Code) != ""
	hasSealed := strings.TrimSpace(req.SealedToken) != ""
	if hasCode == hasSealed {
		return PublishResponse{}, fmt.Errorf("%w: exactly one of code or sealedToken is required", ErrInvalidRequest)
	}
	if hasCode && strings.TrimSpace(req.CodeVerifier) == "" {
		return PublishResponse{}, fmt.Errorf("%w: code requires codeVerifier", ErrInvalidRequest)
	}
	if strings.TrimSpace(req.OrgID) == "" {
		return PublishResponse{}, fmt.Errorf("%w: orgId is required", ErrInvalidRequest)
	}

	snapshot, err := dnsplan.NewSnapshot(req.Kind, req.TargetID, req.Anchor, req.Records)
	if err != nil {
		// Includes the containment refusal. Nothing has been exchanged.
		return PublishResponse{}, err
	}
	if req.ExpectedDigest != "" {
		want, decodeErr := hex.DecodeString(strings.TrimSpace(req.ExpectedDigest))
		if decodeErr != nil {
			return PublishResponse{}, fmt.Errorf("%w: expectedDigest is not hex", ErrInvalidRequest)
		}
		if err := snapshot.Validate(want); err != nil {
			slog.Error("grant: refusing a plan that does not reproduce the reviewed digest",
				"org_id", req.OrgID, "kind", req.Kind, "error", err)
			return PublishResponse{}, err
		}
	}
	if len(req.Reviewed) > 0 {
		if err := dnsplan.AssertReviewed(req.Reviewed, snapshot.Identities); err != nil {
			return PublishResponse{}, err
		}
	}

	aad := GrantAAD(req.OrgID, snapshot.TargetID, snapshot.Anchor)

	// ── From here a credential is in play. Outcomes are reported in the
	// response, never as an RPC error. ───────────────────────────────────────
	var (
		token   *oauth2.Token
		rotated bool
	)
	if hasCode {
		token, err = s.exchange(ctx, cfg, req.Code, req.CodeVerifier)
		if err != nil {
			// The code is single-use and now spent, but no token was ever
			// issued, so there is nothing for the caller to persist and nothing
			// to revoke. This is the one post-boundary case that stays an error.
			return PublishResponse{}, fmt.Errorf("%w: exchange authorization code: %w", ErrUnavailable, err)
		}
	} else {
		sealer := s.sealer(ctx)
		if sealer == nil {
			return PublishResponse{Failure: &Failure{
				Code: FailureTokenUnreadable, Retry: false,
				Message: "this deployment holds no keyset, so a sealed grant cannot be opened",
			}}, nil
		}
		refresh, openErr := sealer.Open(req.SealedToken, aad)
		if openErr != nil {
			return PublishResponse{Failure: &Failure{
				Code: FailureTokenUnreadable, Retry: false,
				Message: "the sealed grant could not be opened for this row",
			}}, nil
		}
		token, err = s.refresh(ctx, cfg, refresh)
		if err != nil {
			if isInvalidGrant(err) {
				return PublishResponse{Failure: &Failure{
					Code: FailureInvalidGrant, Retry: false,
					Message: "the provider rejected the refresh token",
				}}, nil
			}
			// Could not reach the provider. The grant is untouched.
			return PublishResponse{Failure: &Failure{
				Code: FailureProvider, Retry: true,
				Message: "could not refresh the delegated grant",
			}}, nil
		}
		rotated = token.RefreshToken != "" && token.RefreshToken != refresh
	}

	out := PublishResponse{Rotated: rotated}

	// 🔴 SEAL BEFORE PUBLISHING, NOT AFTER.
	//
	// The provider rotates the refresh token on every use, so once the refresh
	// above returned, the caller's stored token is already dead. If the publish
	// below fails and this response carries no replacement, the grant kills
	// itself on the next pass — measured 2026-08-24: the first pass returned
	// early on a preparing plan without storing the rotated token, and the
	// second pass found a token the provider had already replaced.
	if req.Hold {
		if sealed, keyID, sealErr := s.sealIfPossible(ctx, token, aad); sealErr == nil && sealed != "" {
			out.SealedToken, out.KeyID, out.Held = sealed, keyID, true
		}
	}

	publishErr := s.Publisher.Publish(ctx, token.AccessToken, snapshot)
	if publishErr != nil {
		out.Failure = publishFailure(publishErr)
		// A grant we are not holding must not be left alive at the provider: an
		// unrecorded live grant is one nothing will ever release.
		if !out.Held {
			s.revokeToken(ctx, cfg, token, req.OrgID)
			out.Revoked = true
		}
		return out, nil
	}
	out.Published = snapshot.Identities

	if !req.Hold {
		s.revokeToken(ctx, cfg, token, req.OrgID)
		out.Revoked = true
		return out, nil
	}
	if !out.Held {
		// Holding was asked for and could not be done. Revoke rather than
		// leaving a live credential nobody recorded.
		slog.Warn("grant: could not seal the delegated grant; revoking instead of holding", "org_id", req.OrgID)
		s.revokeToken(ctx, cfg, token, req.OrgID)
		out.Revoked = true
		out.Failure = &Failure{
			Code: FailureResealFailed, Retry: false,
			Message: "the grant published but could not be held; it has been revoked",
		}
	}
	return out, nil
}

// Revoke ends a held grant at the provider.
func (s *Service) Revoke(ctx context.Context, req RevokeRequest) (RevokeResponse, error) {
	cfg := s.oauthConfig(ctx)
	if cfg == nil {
		return RevokeResponse{}, ErrUnavailable
	}
	sealer := s.sealer(ctx)
	if sealer == nil {
		return RevokeResponse{Unreadable: true}, nil
	}
	// The anchor is normalized the way the row stored it before the AAD is
	// built, so a caller that spells it with a trailing dot still opens.
	refresh, err := sealer.Open(req.SealedToken,
		GrantAAD(req.OrgID, strings.ToLower(strings.TrimSpace(req.TargetID)), dnsplan.NormalizeName(req.Anchor)))
	if err != nil {
		slog.Error("grant: a held grant could not be opened for revocation — REVOKE BY HAND", "org_id", req.OrgID)
		return RevokeResponse{Unreadable: true}, nil
	}
	s.revokeToken(ctx, cfg, &oauth2.Token{RefreshToken: refresh}, req.OrgID)
	return RevokeResponse{Revoked: true}, nil
}

// GrantAAD binds a sealed refresh token to the exact row that holds it.
//
// 🔴 WITHOUT IT A CIPHERTEXT MOVES BETWEEN ROWS. A sealed token lifted from org
// A's grant and pasted into org B's row would decrypt perfectly and hand B a
// live write credential on A's zone — by a database write alone. The three
// fields are the row's identity and none of them is mutable on a live grant.
//
// The formula lives HERE, inside the credential boundary, rather than being
// passed in: a caller that could choose the AAD could choose to unbind it.
//
// 🔴 BYTE-IDENTICAL TO api-platform's grantAAD, AND IT HAS TO STAY THAT WAY.
// Grants sealed before the cutover are opened by this code afterwards. The
// anchor is lowered and space-trimmed but NOT stripped of a trailing dot —
// api-platform does not strip one either, and adding a "harmless"
// normalization here would make every live grant unopenable, which reports as
// token_unreadable and releases it. Callers pass an anchor already through
// dnsplan.NormalizeName, so the two agree on every real input; the test pins
// the bytes anyway. See TestGrantAADGolden.
func GrantAAD(orgID, targetID, anchor string) string {
	return "cf-dns-grant\x00" + orgID + "\x00" + targetID + "\x00" + strings.ToLower(strings.TrimSpace(anchor))
}

func (s *Service) sealIfPossible(ctx context.Context, token *oauth2.Token, aad string) (string, string, error) {
	if token == nil || token.RefreshToken == "" {
		return "", "", errors.New("grant: the provider returned no refresh token")
	}
	sealer := s.sealer(ctx)
	if sealer == nil {
		return "", "", grantcrypto.ErrNoKeyset
	}
	return sealer.Seal(token.RefreshToken, aad)
}

func (s *Service) exchange(ctx context.Context, cfg *cfoauth.Config, code, verifier string) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, s.httpClient())
	return cfg.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
}

func (s *Service) refresh(ctx context.Context, cfg *cfoauth.Config, refreshToken string) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, s.httpClient())
	return cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
}

// isInvalidGrant reports the provider saying the refresh token is dead. It is
// the one refresh failure that must NOT be retried: retrying spends nothing and
// the grant will never come back.
func isInvalidGrant(err error) bool {
	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) {
		if retrieveErr.ErrorCode == "invalid_grant" {
			return true
		}
		// Some providers answer 400 with a body oauth2 does not parse into
		// ErrorCode. A 400/401 on a refresh is a rejected credential either way;
		// 5xx and transport failures are not.
		return retrieveErr.Response != nil &&
			(retrieveErr.Response.StatusCode == http.StatusBadRequest ||
				retrieveErr.Response.StatusCode == http.StatusUnauthorized)
	}
	return false
}

func publishFailure(err error) *Failure {
	switch {
	case errors.Is(err, dnsplan.ErrAnchorEscape), errors.Is(err, dnsplan.ErrPlanInvalid),
		errors.Is(err, reconcile.ErrConflictingPlan), errors.Is(err, reconcile.ErrNoRecords):
		// A plan defect. Retrying the same plan cannot help.
		return &Failure{Code: FailureProvider, Retry: false, Message: err.Error()}
	case errors.Is(err, dnsplan.ErrPlanPreparing):
		return &Failure{Code: FailurePlanPreparing, Retry: true, Message: err.Error()}
	default:
		// 🔴 EVERYTHING UNKNOWN IS RETRYABLE. The alternative — defaulting to
		// "dead" — releases a working customer credential over a transient
		// provider blip, and a released grant cannot be recovered without
		// sending the customer back through consent.
		return &Failure{Code: FailureProvider, Retry: true, Message: err.Error()}
	}
}

// revokeToken ends a grant at the provider, refresh token first: revoking it
// kills the whole grant, whereas revoking only the access token leaves a
// credential that can mint another.
//
// Every failure is a precise log line and nothing else. The caller has already
// succeeded or failed on its own terms, and a failed revocation is an operator
// task, not a caller outcome.
func (s *Service) revokeToken(ctx context.Context, cfg *cfoauth.Config, token *oauth2.Token, orgID string) {
	if token == nil || cfg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	client := s.httpClient()
	for _, t := range []struct{ value, hint string }{
		{token.RefreshToken, "refresh_token"},
		{token.AccessToken, "access_token"},
	} {
		if t.value == "" {
			continue
		}
		form := url.Values{"token": {t.value}, "token_type_hint": {t.hint}}
		if cfg.AuthMethod != cfoauth.AuthNone {
			form.Set("client_id", cfg.ClientID)
			form.Set("client_secret", cfg.ClientSecret)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.RevokeURL, strings.NewReader(form.Encode()))
		if err != nil {
			slog.Error("grant: token revocation could not be built — REVOKE BY HAND",
				"org_id", orgID, "token_type", t.hint, "error", err)
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			slog.Error("grant: token revocation failed — REVOKE BY HAND",
				"org_id", orgID, "token_type", t.hint, "error", err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			slog.Error("grant: the provider rejected token revocation — REVOKE BY HAND",
				"org_id", orgID, "token_type", t.hint, "status", resp.StatusCode)
		}
	}
}
