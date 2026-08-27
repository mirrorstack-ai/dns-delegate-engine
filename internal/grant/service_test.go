package grant

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsprovider"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/reconcile"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/cfoauth"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/grantcrypto"
)

// 🔴 CROSS-REPOSITORY GOLDEN — DO NOT REGENERATE TO MAKE A FAILURE GO AWAY.
//
// api-platform's grantAAD computes this same string for these same inputs. Every
// grant sealed before the cutover is opened by this code afterwards; a single
// changed byte makes all of them unopenable, which this service reports as
// token_unreadable and the caller acts on by RELEASING the grant. In production
// that is every held grant dying at once, silently, with the customer sent back
// through consent.
//
// Measured against api-platform 032277f9 on 2026-08-28.
const goldenAADSHA256 = "14568cacc22e27e3bec9d1d105d261cdb67d6c10f4dc66a6ed25d471958fdf4e"

func TestGrantAADGolden(t *testing.T) {
	aad := GrantAAD("11111111-2222-4333-8444-555555555555",
		"3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f607", "App.Example.COM ")
	if aad != "cf-dns-grant\x0011111111-2222-4333-8444-555555555555\x003f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f607\x00app.example.com" {
		t.Fatalf("AAD drift: %q", aad)
	}
	sum := sha256.Sum256([]byte(aad))
	if got := hex.EncodeToString(sum[:]); got != goldenAADSHA256 {
		t.Fatalf("AAD drift\n got: %s\nwant: %s", got, goldenAADSHA256)
	}
}

// A ciphertext lifted from one row and pasted into another must not open.
func TestGrantAADBindsToTheRow(t *testing.T) {
	sealer := testSealer(t)
	a := GrantAAD("orgA", "target1", "a.example")
	sealed, _, err := sealer.Seal("refresh-token", a)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	for _, other := range []string{
		GrantAAD("orgB", "target1", "a.example"),
		GrantAAD("orgA", "target2", "a.example"),
		GrantAAD("orgA", "target1", "b.example"),
	} {
		if _, err := sealer.Open(sealed, other); err == nil {
			t.Fatalf("a ciphertext opened under a different row identity: %s", other)
		}
	}
	if got, err := sealer.Open(sealed, a); err != nil || got != "refresh-token" {
		t.Fatalf("the correct row must open: %v %q", err, got)
	}
}

// ─── harness ────────────────────────────────────────────────────────────────

func testSealer(t *testing.T) *grantcrypto.Sealer {
	t.Helper()
	key := make([]byte, grantcrypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	keys, err := grantcrypto.ParseKeyset(fmt.Sprintf(`{"active":"k1","keys":{"k1":%q}}`, base64Std(key)))
	if err != nil {
		t.Fatalf("ParseKeyset: %v", err)
	}
	sealer, err := grantcrypto.NewSealer(keys)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return sealer
}

func base64Std(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var sb strings.Builder
	for i := 0; i < len(b); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], b[i:])
		v := uint(chunk[0])<<16 | uint(chunk[1])<<8 | uint(chunk[2])
		out := []byte{
			alphabet[(v>>18)&0x3f], alphabet[(v>>12)&0x3f],
			alphabet[(v>>6)&0x3f], alphabet[v&0x3f],
		}
		switch n {
		case 1:
			out[2], out[3] = '=', '='
		case 2:
			out[3] = '='
		}
		sb.Write(out)
	}
	return sb.String()
}

type stubOAuth struct{ cfg *cfoauth.Config }

func (s stubOAuth) Config(context.Context) *cfoauth.Config { return s.cfg }

type stubKeys struct{ sealer *grantcrypto.Sealer }

func (s stubKeys) Sealer(context.Context) *grantcrypto.Sealer { return s.sealer }

type recordingProvider struct {
	writes  int
	failErr error
}

func (r *recordingProvider) Name() string { return "stub" }
func (r *recordingProvider) FindZone(context.Context, string, string) (string, error) {
	return "z", nil
}
func (r *recordingProvider) ListRecordsAt(context.Context, string, string, string) ([]dnsprovider.LiveRecord, error) {
	return nil, nil
}
func (r *recordingProvider) CreateRecord(_ context.Context, _, _ string, _ dnsprovider.Desired) (string, error) {
	r.writes++
	if r.failErr != nil {
		return "", r.failErr
	}
	return "id", nil
}
func (r *recordingProvider) PatchRecord(context.Context, string, string, string, dnsprovider.Desired) error {
	r.writes++
	return r.failErr
}
func (r *recordingProvider) SameValue(_, live, desired string) bool { return live == desired }
func (r *recordingProvider) IsDuplicate(error) bool                 { return false }
func (r *recordingProvider) IsAmbiguous(error) bool                 { return false }

// oauthServer answers token, refresh and revoke. It records what it saw.
type oauthServer struct {
	refreshCalls int
	revokeCalls  int
	nextRefresh  string
	tokenStatus  int
	tokenBody    string
}

func newService(t *testing.T, provider dnsprovider.Provider, srv *oauthServer, withKeys bool) (*Service, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/revoke"):
			srv.revokeCalls++
			w.WriteHeader(http.StatusOK)
		default:
			_ = r.ParseForm()
			if r.Form.Get("grant_type") == "refresh_token" {
				srv.refreshCalls++
			}
			if srv.tokenStatus != 0 {
				w.WriteHeader(srv.tokenStatus)
				_, _ = w.Write([]byte(srv.tokenBody))
				return
			}
			refresh := srv.nextRefresh
			if refresh == "" {
				refresh = "refresh-1"
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access-1", "refresh_token": refresh,
				"token_type": "bearer", "expires_in": 3600,
			})
		}
	}))
	t.Cleanup(ts.Close)

	cfg := &cfoauth.Config{
		Config: oauth2.Config{
			ClientID: "cid", ClientSecret: "csec", RedirectURL: "https://account.example/cb",
			Scopes:   []string{"zone.read", "dns.write", "offline_access"},
			Endpoint: oauth2.Endpoint{AuthURL: ts.URL + "/auth", TokenURL: ts.URL + "/token", AuthStyle: oauth2.AuthStyleInParams},
		},
		RevokeURL: ts.URL + "/revoke", AuthMethod: cfoauth.AuthClientSecretPost,
	}
	svc := &Service{
		OAuth:      stubOAuth{cfg: cfg},
		Publisher:  reconcile.Publisher{Provider: provider},
		HTTPClient: ts.Client(),
	}
	if withKeys {
		svc.Keys = stubKeys{sealer: testSealer(t)}
	}
	return svc, ts
}

const (
	testOrg    = "11111111-2222-4333-8444-555555555555"
	testTarget = "3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f607"
	testAnchor = "app.customer-owned.example"
)

func goodPlan() []dnsplan.Record {
	return []dnsplan.Record{{Type: "CNAME", Name: testAnchor, Value: "edge.mirrorstack.ai", Proxied: true}}
}

func baseRequest() PublishRequest {
	return PublishRequest{
		Kind: KindPlatform, OrgID: testOrg, TargetID: testTarget, Anchor: testAnchor,
		Records: goodPlan(), Code: "auth-code", CodeVerifier: "verifier",
	}
}

// ─── tests ──────────────────────────────────────────────────────────────────

// 🔴 The engine refuses an escaping plan BEFORE it exchanges anything. This is
// the property that survives derivation staying in a private repository.
func TestPublishRefusesAnEscapingPlanWithoutTouchingTheProvider(t *testing.T) {
	provider := &recordingProvider{}
	srv := &oauthServer{}
	svc, _ := newService(t, provider, srv, true)

	req := baseRequest()
	req.Records = []dnsplan.Record{{Type: "CNAME", Name: "www.customer-owned.example", Value: "edge.mirrorstack.ai"}}
	_, err := svc.Publish(context.Background(), req)
	if !errors.Is(err, dnsplan.ErrAnchorEscape) {
		t.Fatalf("want ErrAnchorEscape, got %v", err)
	}
	if provider.writes != 0 || srv.revokeCalls != 0 {
		t.Fatal("nothing may be exchanged or written for an escaping plan")
	}
}

// 🔴 The digest check is what stops a buggy or hostile api-platform publishing a
// plan the customer never reviewed — even though api-platform is the side that
// derives it.
func TestPublishRefusesAPlanThatDoesNotReproduceTheReviewedDigest(t *testing.T) {
	provider := &recordingProvider{}
	svc, _ := newService(t, provider, &oauthServer{}, true)

	reviewed, err := dnsplan.NewSnapshot(KindPlatform, testTarget, testAnchor, goodPlan())
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	req := baseRequest()
	req.ExpectedDigest = hex.EncodeToString(reviewed.Digest())
	// Same anchor, different target — inside containment, outside consent.
	req.Records = []dnsplan.Record{{Type: "CNAME", Name: testAnchor, Value: "attacker.example", Proxied: true}}
	if _, err := svc.Publish(context.Background(), req); !errors.Is(err, dnsplan.ErrPlanInvalid) {
		t.Fatalf("want a digest refusal, got %v", err)
	}
	if provider.writes != 0 {
		t.Fatal("a plan that failed the digest must not be written")
	}

	// The matching plan goes through.
	ok := baseRequest()
	ok.ExpectedDigest = hex.EncodeToString(reviewed.Digest())
	if _, err := svc.Publish(context.Background(), ok); err != nil {
		t.Fatalf("the reviewed plan must publish: %v", err)
	}
}

func TestPublishRevokesWhenNotHolding(t *testing.T) {
	provider := &recordingProvider{}
	srv := &oauthServer{}
	svc, _ := newService(t, provider, srv, true)

	out, err := svc.Publish(context.Background(), baseRequest())
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !out.Revoked || out.Held || out.SealedToken != "" {
		t.Fatalf("a non-held grant must be revoked and returned unsealed: %#v", out)
	}
	if srv.revokeCalls == 0 {
		t.Fatal("the provider must have been asked to revoke")
	}
	if len(out.Published) != 1 {
		t.Fatalf("want one published identity, got %#v", out.Published)
	}
}

func TestPublishHoldsAndSealsWhenAsked(t *testing.T) {
	svc, _ := newService(t, &recordingProvider{}, &oauthServer{}, true)
	req := baseRequest()
	req.Hold = true
	out, err := svc.Publish(context.Background(), req)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !out.Held || out.SealedToken == "" || out.KeyID == "" || out.Revoked {
		t.Fatalf("a held grant must come back sealed and unrevoked: %#v", out)
	}
	// And it opens only under this row's identity.
	sealer := testSealer(t)
	if _, err := sealer.Open(out.SealedToken, GrantAAD(testOrg, testTarget, testAnchor)); err != nil {
		t.Fatalf("the sealed grant must open for its own row: %v", err)
	}
}

// 🔴 Hold was asked for and could not be done: revoke rather than leave a live
// credential nobody recorded.
func TestPublishRevokesWhenItCannotHold(t *testing.T) {
	srv := &oauthServer{}
	svc, _ := newService(t, &recordingProvider{}, srv, false) // no keyset
	req := baseRequest()
	req.Hold = true
	out, err := svc.Publish(context.Background(), req)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if out.Held || !out.Revoked || out.Failure == nil || out.Failure.Code != FailureResealFailed {
		t.Fatalf("an unsealable hold must revoke and say so: %#v", out)
	}
	if srv.revokeCalls == 0 {
		t.Fatal("the grant must have been revoked")
	}
}

// 🔴 THE 2026-08-24 BUG. The provider rotates the refresh token on every use, so
// once the refresh returns, the caller's stored token is already dead. A publish
// failure after that point must still hand back the replacement — otherwise the
// grant kills itself on the next pass holding a token the provider replaced.
func TestAFailedPublishAfterARotationStillReturnsTheNewSealedToken(t *testing.T) {
	provider := &recordingProvider{failErr: errors.New("cloudflare 500")}
	srv := &oauthServer{nextRefresh: "refresh-2"}
	svc, _ := newService(t, provider, srv, true)

	sealer := testSealer(t)
	sealed, _, err := sealer.Seal("refresh-1", GrantAAD(testOrg, testTarget, testAnchor))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	req := baseRequest()
	req.Code, req.CodeVerifier = "", ""
	req.SealedToken = sealed
	req.Hold = true

	out, err := svc.Publish(context.Background(), req)
	if err != nil {
		t.Fatalf("a post-rotation failure must NOT be an RPC error: %v", err)
	}
	if out.Failure == nil || !out.Failure.Retry {
		t.Fatalf("a provider blip must be retryable: %#v", out.Failure)
	}
	if !out.Rotated {
		t.Fatal("the rotation must be reported")
	}
	if out.SealedToken == "" {
		t.Fatal("the ROTATED token must come back so the caller can persist it")
	}
	got, err := sealer.Open(out.SealedToken, GrantAAD(testOrg, testTarget, testAnchor))
	if err != nil || got != "refresh-2" {
		t.Fatalf("the returned seal must carry the NEW refresh token, got %q (%v)", got, err)
	}
	if out.Revoked {
		t.Fatal("a held grant must not be revoked over a retryable failure")
	}
}

// A grant we are not holding must not be left alive at the provider after a
// failed publish: an unrecorded live grant is one nothing will ever release.
func TestAFailedPublishRevokesAnUnheldGrant(t *testing.T) {
	srv := &oauthServer{}
	svc, _ := newService(t, &recordingProvider{failErr: errors.New("boom")}, srv, true)
	out, err := svc.Publish(context.Background(), baseRequest())
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !out.Revoked || srv.revokeCalls == 0 {
		t.Fatalf("an unheld grant must be revoked after a failed publish: %#v", out)
	}
}

// 🔴 UNKNOWN MEANS RETRY. Defaulting to "dead" releases a working customer
// credential over a transient blip, and a released grant cannot be recovered
// without sending the customer back through consent.
func TestUnknownPublishFailuresAreRetryable(t *testing.T) {
	f := publishFailure(errors.New("something nobody has seen before"))
	if !f.Retry || f.Code != FailureProvider {
		t.Fatalf("an unrecognised failure must be a retryable provider failure: %#v", f)
	}
	if f := publishFailure(fmt.Errorf("%w: x", dnsplan.ErrAnchorEscape)); f.Retry {
		t.Fatal("a containment refusal is not retryable — the same plan cannot start passing")
	}
	if f := publishFailure(fmt.Errorf("%w: x", reconcile.ErrConflictingPlan)); f.Retry {
		t.Fatal("a conflicting plan is not retryable")
	}
}

// A refresh the provider rejects is a dead grant; a refresh it could not answer
// is not. Confusing the two either strands a customer or destroys their grant.
func TestRefreshFailuresAreClassified(t *testing.T) {
	sealer := testSealer(t)
	sealed, _, _ := sealer.Seal("refresh-1", GrantAAD(testOrg, testTarget, testAnchor))

	for _, tc := range []struct {
		name      string
		status    int
		body      string
		wantCode  string
		wantRetry bool
	}{
		{"provider rejects the token", 400, `{"error":"invalid_grant"}`, FailureInvalidGrant, false},
		{"provider is unwell", 503, `{"error":"temporarily_unavailable"}`, FailureProvider, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := &oauthServer{tokenStatus: tc.status, tokenBody: tc.body}
			svc, _ := newService(t, &recordingProvider{}, srv, true)
			req := baseRequest()
			req.Code, req.CodeVerifier = "", ""
			req.SealedToken = sealed
			out, err := svc.Publish(context.Background(), req)
			if err != nil {
				t.Fatalf("a refresh outcome must not be an RPC error: %v", err)
			}
			if out.Failure == nil || out.Failure.Code != tc.wantCode || out.Failure.Retry != tc.wantRetry {
				t.Fatalf("want %s retry=%v, got %#v", tc.wantCode, tc.wantRetry, out.Failure)
			}
		})
	}
}

func TestAnUnopenableSealIsReportedNotRetried(t *testing.T) {
	svc, _ := newService(t, &recordingProvider{}, &oauthServer{}, true)
	req := baseRequest()
	req.Code, req.CodeVerifier = "", ""
	req.SealedToken = "v1.k1.AAAA.BBBB"
	out, err := svc.Publish(context.Background(), req)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if out.Failure == nil || out.Failure.Code != FailureTokenUnreadable || out.Failure.Retry {
		t.Fatalf("an unopenable seal is a dead grant, not a retry: %#v", out.Failure)
	}
}

func TestPublishRequiresExactlyOneCredentialSource(t *testing.T) {
	svc, _ := newService(t, &recordingProvider{}, &oauthServer{}, true)
	both := baseRequest()
	both.SealedToken = "v1.k1.a.b"
	if _, err := svc.Publish(context.Background(), both); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("both sources must be refused, got %v", err)
	}
	neither := baseRequest()
	neither.Code, neither.CodeVerifier = "", ""
	if _, err := svc.Publish(context.Background(), neither); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("no source must be refused, got %v", err)
	}
}

func TestUnavailableWhenNoOAuthClient(t *testing.T) {
	svc := &Service{OAuth: stubOAuth{}}
	if _, err := svc.Publish(context.Background(), baseRequest()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	if _, err := svc.Authorize(context.Background(), AuthorizeRequest{State: "s", CodeChallenge: "c"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	if caps := svc.Capabilities(context.Background()); caps.Available {
		t.Fatal("capabilities must report unavailable")
	}
}

// The scope list and redirect URL are this service's, so a caller cannot widen
// what a customer is asked to approve.
func TestAuthorizeUsesThisServicesClientNotTheRequest(t *testing.T) {
	svc, _ := newService(t, &recordingProvider{}, &oauthServer{}, true)
	out, err := svc.Authorize(context.Background(), AuthorizeRequest{State: "st4te", CodeChallenge: "chal"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	for _, want := range []string{"state=st4te", "code_challenge=chal", "code_challenge_method=S256", "client_id=cid"} {
		if !strings.Contains(out.AuthorizationURL, want) {
			t.Fatalf("authorization URL missing %q: %s", want, out.AuthorizationURL)
		}
	}
	if !strings.Contains(out.AuthorizationURL, "dns.write") {
		t.Fatal("the scope list must come from this service's configuration")
	}
}

func TestCapabilitiesReportsHoldSeparately(t *testing.T) {
	with, _ := newService(t, &recordingProvider{}, &oauthServer{}, true)
	if caps := with.Capabilities(context.Background()); !caps.Available || !caps.CanHold {
		t.Fatalf("want available+canHold, got %#v", caps)
	}
	without, _ := newService(t, &recordingProvider{}, &oauthServer{}, false)
	if caps := without.Capabilities(context.Background()); !caps.Available || caps.CanHold {
		t.Fatalf("a deployment with no keyset is available but cannot hold: %#v", caps)
	}
}

func TestRevokeOpensAndCallsTheProvider(t *testing.T) {
	srv := &oauthServer{}
	svc, _ := newService(t, &recordingProvider{}, srv, true)
	sealer := testSealer(t)
	sealed, _, _ := sealer.Seal("refresh-1", GrantAAD(testOrg, testTarget, testAnchor))

	out, err := svc.Revoke(context.Background(), RevokeRequest{
		OrgID: testOrg, TargetID: strings.ToUpper(testTarget), Anchor: testAnchor + ".", SealedToken: sealed,
	})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !out.Revoked || out.Unreadable {
		t.Fatalf("want a clean revoke, got %#v", out)
	}
	if srv.revokeCalls == 0 {
		t.Fatal("the provider must have been asked to revoke")
	}
}

func TestRevokeReportsAnUnopenableSealRatherThanFailing(t *testing.T) {
	svc, _ := newService(t, &recordingProvider{}, &oauthServer{}, true)
	out, err := svc.Revoke(context.Background(), RevokeRequest{
		OrgID: testOrg, TargetID: testTarget, Anchor: testAnchor, SealedToken: "v1.k1.AAAA.BBBB",
	})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if out.Revoked || !out.Unreadable {
		t.Fatalf("an unopenable seal must report unreadable so the caller still releases its row: %#v", out)
	}
}
