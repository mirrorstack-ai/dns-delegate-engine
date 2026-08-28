package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/consent"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/derive"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/grant"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/intent"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/sealed"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/cfoauth"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/grantcrypto"
)

func readyDispatcher() *dispatcher {
	return &dispatcher{grants: &grant.Service{
		OAuth: stubOAuth{cfg: &cfoauth.Config{Config: oauth2.Config{
			ClientID: "cid", RedirectURL: "https://account.example/cb", Scopes: []string{"dns.write"},
		}}},
	}}
}

type stubOAuth struct{ cfg *cfoauth.Config }

func (s stubOAuth) Config(context.Context) *cfoauth.Config { return s.cfg }

func TestLambdaHandlerAnswersTheGatewayHealthProbeWithoutDispatching(t *testing.T) {
	// No pool wired: if the probe reached the dispatcher it would report
	// unconfigured, and mirrorstack-infra's health check would read the service
	// as down whenever DATABASE_URL was absent.
	d := &dispatcher{}
	out, err := d.lambdaHandler(context.Background(), json.RawMessage(`{"rawPath":"/dns-delegate/healthz"}`))
	if err != nil {
		t.Fatalf("lambdaHandler: %v", err)
	}
	got, ok := out.(map[string]any)
	if !ok || got["statusCode"] != 200 {
		t.Fatalf("want a static 200 gateway response, got %#v", out)
	}
}

func TestLambdaHandlerReturnsRefusalsInsideTheEnvelope(t *testing.T) {
	// 🔴 A refusal must never be a Lambda FUNCTION error. At the caller a
	// function error is indistinguishable from the engine being unreachable,
	// and the grant lifecycle treats those two differently — one is a retry,
	// the other can release a live customer credential.
	d := &dispatcher{}
	out, err := d.lambdaHandler(context.Background(), json.RawMessage(`{"action":"NoSuchAction"}`))
	if err != nil {
		t.Fatalf("a refusal must not surface as a function error: %v", err)
	}
	body, _ := json.Marshal(out)
	var decoded struct {
		OK    bool `json:"ok"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.OK || decoded.Error.Code != "unknown_action" {
		t.Fatalf("want ok=false code=unknown_action, got %s", body)
	}
}

func TestLambdaHandlerRejectsAMalformedEnvelope(t *testing.T) {
	d := &dispatcher{}
	out, err := d.lambdaHandler(context.Background(), json.RawMessage(`not json`))
	if err != nil {
		t.Fatalf("lambdaHandler: %v", err)
	}
	body, _ := json.Marshal(out)
	var decoded struct {
		OK    bool `json:"ok"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &decoded)
	if decoded.OK || decoded.Error.Code != "invalid_input" {
		t.Fatalf("want ok=false code=invalid_input, got %s", body)
	}
}

func TestHealthIsTruthfulAboutDelegation(t *testing.T) {
	if got := (&dispatcher{}).health(context.Background()); got.OK || got.Delegation != "unconfigured" {
		t.Fatalf("no grant service must report unconfigured: %#v", got)
	}
	if got := (&dispatcher{grants: &grant.Service{}}).health(context.Background()); got.OK || got.Delegation != "unconfigured" {
		t.Fatalf("no OAuth client must report unconfigured: %#v", got)
	}
	// A client without a keyset is a REAL, supported state: grants publish but
	// cannot be held. Reporting it as unhealthy would take a working deployment
	// out of rotation over a capability it does not need for the console lane.
	if got := readyDispatcher().health(context.Background()); !got.OK || got.Delegation != "no-keyset" {
		t.Fatalf("a client without a keyset is healthy but cannot hold: %#v", got)
	}
}

// 🔴 Retiring the deprecated surface must not present as an outage.
//
// health reads whichever surface is wired, preferring the intent one. Both
// resolve the same two credentials from the same two loaders, so the answers are
// identical today and the branch is a no-op — which is exactly why nothing else
// would catch it breaking. The day somebody deletes d.grants, a healthy
// deployment must not start answering "unconfigured" and get pulled out of
// rotation by mirrorstack-infra's probe.
func TestHealthSurvivesTheDeprecatedServiceBeingRemoved(t *testing.T) {
	oauth := stubOAuth{cfg: &cfoauth.Config{Config: oauth2.Config{ClientID: "cid"}}}

	intentsOnly := &dispatcher{intents: &intent.Service{OAuth: oauth}}
	if got := intentsOnly.health(context.Background()); !got.OK || got.Delegation != "no-keyset" {
		t.Fatalf("the intent surface alone must report a healthy no-keyset deployment: %#v", got)
	}

	held := &dispatcher{intents: &intent.Service{OAuth: oauth, Keys: stubKeys{sealer: newSealer(t)}}}
	if got := held.health(context.Background()); !got.OK || got.Delegation != "ready" {
		t.Fatalf("a client and a keyset must report ready: %#v", got)
	}

	if got := (&dispatcher{intents: &intent.Service{}}).health(context.Background()); got.OK ||
		got.Delegation != "unconfigured" {
		t.Fatalf("an intent surface with no OAuth client must report unconfigured: %#v", got)
	}
}

// 🔴 EVERY INTENT ACTION MUST BE REACHABLE. A missing case is not a compile
// error and not a panic — it is an `unknown_action` refusal, which api-platform
// maps to a hard failure. A lane that was wired end to end in internal/intent
// and forgotten here would be dead on arrival with no signal anywhere but this
// table.
//
// With no intent service wired, each one must answer with INTENT's own
// unavailable sentinel: that proves both that the case exists and that it is
// routed to the right service, which a bare "unavailable" string could not.
func TestEveryIntentActionIsDispatched(t *testing.T) {
	actions := []string{
		"AddOrgPlatformDomain",
		"AddOrgAppDomain",
		"AddAppDomain",
		"BindAppToOrgAppDomain",
		"Verify",
		"IntentAuthorize",
		"Complete",
		"Advance",
		"Describe",
		"Orphans",
		"Release",
		"IntentCapabilities",
	}
	d := &dispatcher{}
	for _, action := range actions {
		_, err := d.dispatch(context.Background(), action, nil)
		if errors.Is(err, errUnknownAction) {
			t.Errorf("%s is not in the dispatcher switch", action)
			continue
		}
		if !errors.Is(err, intent.ErrUnavailable) {
			t.Errorf("%s: want intent.ErrUnavailable with no service wired, got %v", action, err)
		}
		if got := errorCode(err); got != "unavailable" {
			t.Errorf("%s: want code unavailable, got %q", action, got)
		}
	}
}

// 🔴 ADDITIVE, NOT REPLACING. api-platform calls these five today. Removing or
// renaming one takes production down, and the failure would be a version skew
// that only shows up under live traffic — this table is the cheapest place to
// find out instead.
func TestTheDeprecatedActionsAreStillDispatched(t *testing.T) {
	d := &dispatcher{}

	for _, action := range []string{"Health", "Capabilities"} {
		if _, err := d.dispatch(context.Background(), action, nil); err != nil {
			t.Errorf("%s must still answer without an error, got %v", action, err)
		}
	}
	// Capabilities with no service is a zero response and NOT a refusal, which
	// is what it has always been. A caller reads Available:false from it.
	out, err := d.dispatch(context.Background(), "Capabilities", nil)
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if _, ok := out.(grant.CapabilitiesResponse); !ok {
		t.Fatalf("Capabilities must keep answering grant.CapabilitiesResponse, got %T", out)
	}

	for _, action := range []string{"Authorize", "Publish", "Revoke"} {
		_, err := d.dispatch(context.Background(), action, nil)
		if errors.Is(err, errUnknownAction) {
			t.Errorf("%s was removed; api-platform calls it today", action)
			continue
		}
		if !errors.Is(err, grant.ErrUnavailable) {
			t.Errorf("%s: want grant.ErrUnavailable, got %v", action, err)
		}
	}
}

// 🔴 THE TWO AUTHORIZE ACTIONS ARE DIFFERENT ACTS AND MUST STAY DIFFERENT NAMES.
//
// Legacy Authorize accepts the OAuth state as a request field; IntentAuthorize
// mints it, and refuses without a live ownership proof and — on the wildcard
// lane — an acknowledged consent page. A caller that reached the wrong one would
// be authorized with none of those checks and would get no error saying so.
//
// The second half of this test is that silent downgrade, written out: the SAME
// legacy payload succeeds on one action and is refused on the other. If the two
// were ever aliased, the refusal below would become an authorization URL.
func TestTheTwoAuthorizeActionsCannotBeConfused(t *testing.T) {
	empty := &dispatcher{}

	_, legacyErr := empty.dispatch(context.Background(), "Authorize", nil)
	if !errors.Is(legacyErr, grant.ErrUnavailable) || errors.Is(legacyErr, intent.ErrUnavailable) {
		t.Fatalf("Authorize must route to the deprecated grant surface, got %v", legacyErr)
	}
	_, intentErr := empty.dispatch(context.Background(), "IntentAuthorize", nil)
	if !errors.Is(intentErr, intent.ErrUnavailable) || errors.Is(intentErr, grant.ErrUnavailable) {
		t.Fatalf("IntentAuthorize must route to the intent surface, got %v", intentErr)
	}

	// A legacy payload: a caller-minted state and a PKCE challenge, and no
	// registration anywhere.
	payload := json.RawMessage(`{"state":"caller-minted","codeChallenge":"nBeK4c"}`)

	legacy := readyDispatcher()
	out, err := legacy.dispatch(context.Background(), "Authorize", payload)
	if err != nil {
		t.Fatalf("the deprecated Authorize must keep accepting a caller-minted state: %v", err)
	}
	if got, ok := out.(grant.AuthorizeResponse); !ok || got.AuthorizationURL == "" {
		t.Fatalf("want a legacy authorization URL, got %#v", out)
	}

	intents, _ := intentDispatcher(t)
	if _, err := intents.dispatch(context.Background(), "IntentAuthorize", payload); err == nil {
		t.Fatal("🔴 IntentAuthorize accepted a legacy caller-minted state — the two actions have been aliased")
	} else if got := errorCode(err); got != "invalid_request" {
		t.Fatalf("want invalid_request for a payload carrying no registration, got %q (%v)", got, err)
	}
}

// 🔴 decodeAnd must hand an action the INVOCATION's context.
//
// An earlier version substituted context.Background(), so the Lambda deadline
// never reached the provider call: a write that outran it was killed with its
// HTTP request in flight, and the caller was left with a transport failure
// carrying nothing about whether Cloudflare had applied it. A cancelled context
// arriving intact is what lets cloudflare.Client.IsAmbiguous classify the
// failure — it fails toward ambiguous — so reconcile re-reads rather than
// guessing.
func TestDecodeAndPassesTheInvocationContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	probe := &ctxProbe{}
	if _, err := decodeAnd(ctx, nil, probe, errors.New("unwired"), (*ctxProbe).run); err != nil {
		t.Fatalf("decodeAnd: %v", err)
	}
	if probe.seen == nil {
		t.Fatal("the action was never called")
	}
	if probe.seen.Err() == nil {
		t.Fatal("🔴 the action received a fresh context: a Lambda deadline would never reach a provider call")
	}
}

type ctxProbe struct{ seen context.Context }

type probeRequest struct{}
type probeResponse struct{}

func (p *ctxProbe) run(ctx context.Context, _ probeRequest) (probeResponse, error) {
	p.seen = ctx
	return probeResponse{}, nil
}

// 🔴 Every error code the caller acts on. `unavailable` and `invalid_request`
// mean nothing was consumed; a plan refusal means retrying cannot help; anything
// unrecognised must fall through to `internal`, which the caller treats as a
// retry and never as a reason to release a grant.
func TestErrorCodesAreTheCallersContract(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{errUnknownAction, "unknown_action"},
		{fmt.Errorf("%w: x", errInvalidInput), "invalid_request"},
		{fmt.Errorf("%w: x", grant.ErrInvalidRequest), "invalid_request"},
		{grant.ErrUnavailable, "unavailable"},
		{fmt.Errorf("%w: x", dnsplan.ErrAnchorEscape), "anchor_escape"},
		{fmt.Errorf("%w: x", dnsplan.ErrPlanChanged), "plan_changed"},
		{fmt.Errorf("%w: x", dnsplan.ErrPlanPreparing), "plan_preparing"},
		{fmt.Errorf("%w: x", dnsplan.ErrPlanInvalid), "plan_invalid"},
		{errors.New("something new"), "internal"},

		// The intent surface's own vocabulary.
		{intent.ErrUnavailable, "unavailable"},
		{fmt.Errorf("%w: x", intent.ErrInvalidRequest), "invalid_request"},
		{fmt.Errorf("%w: x", intent.ErrNotProven), "not_proven"},
		{fmt.Errorf("%w: x", intent.ErrConsentRequired), "consent_required"},
		{fmt.Errorf("%w: x", lane.ErrInvalid), "invalid_request"},

		// The shapes the intent service actually produces, not just the bare
		// sentinels: each of these is a real wrapping from internal/intent, and
		// each one matches a broader case further down errorCode.
		{fmt.Errorf("%w: %w", intent.ErrInvalidRequest, sealed.ErrExpired), "state_expired"},
		{fmt.Errorf("%w: %w", intent.ErrInvalidRequest, sealed.ErrInvalidEnvelope), "invalid_request"},
		{fmt.Errorf("%w: %w", intent.ErrUnavailable, derive.ErrConfig), "unavailable"},
		{fmt.Errorf("%w: %w", intent.ErrInvalidRequest, derive.ErrDerive), "invalid_request"},

		// Sentinels with no case of their own. `internal` is the SAFE answer:
		// the caller retries, which is harmless, instead of giving up on a
		// domain. If a case is ever added for one of these, this row is where to
		// record what the caller should do instead.
		{fmt.Errorf("%w: x", consent.ErrConsent), "internal"},
	}
	for _, tc := range cases {
		if got := errorCode(tc.err); got != tc.want {
			t.Errorf("%v -> %q, want %q", tc.err, got, tc.want)
		}
	}
	// ErrAnchorEscape wraps ErrPlanInvalid, so ordering inside errorCode is
	// load-bearing: the specific code must win.
	if errorCode(fmt.Errorf("%w: x", dnsplan.ErrAnchorEscape)) == "plan_invalid" {
		t.Error("an anchor escape must not be flattened into plan_invalid")
	}
	// 🔴 The same trap, three more times. Each of these travels INSIDE the
	// broader sentinel it must not collapse into, so getting the order wrong
	// breaks no build and raises no error — it just answers a coarser code.
	if got := errorCode(fmt.Errorf("%w: %w", intent.ErrInvalidRequest, sealed.ErrExpired)); got != "state_expired" {
		t.Errorf("a stale consent screen must not be flattened into %q: it is normal, not a bug", got)
	}
	if got := errorCode(fmt.Errorf("%w: %w", intent.ErrUnavailable, derive.ErrConfig)); got == "invalid_request" {
		t.Error("an incomplete deployment configuration must not be reported as the caller's bad request")
	}
	if errorCode(fmt.Errorf("%w: x", intent.ErrNotProven)) == "invalid_request" {
		t.Error("a missing ownership TXT is not a malformed request; the two need different screens")
	}
}

func TestHTTPHealthzIsUngatedAndReadyzIsNot(t *testing.T) {
	h := readyDispatcher().httpHandler("s3cret")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz must not need a credential, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/readyz must be gated, got %d", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req.Header.Set("X-MS-Internal-Secret", "s3cret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz with the secret must pass, got %d", rec.Code)
	}
}

// ─── the consent page route ─────────────────────────────────────────────────

func TestConsentPageIsGatedLikeEveryOtherRoute(t *testing.T) {
	d, sealer := intentDispatcher(t)
	h := d.httpHandler("s3cret")

	target := consentURL(registrationFor(t, sealer, lane.OrgAppDomain, "example.net"), "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("the consent page must be behind the internal secret, got %d", rec.Code)
	}
}

func TestConsentPageRefusalsAreSeparatedByAudience(t *testing.T) {
	d, sealer := intentDispatcher(t)
	h := d.httpHandler("s3cret")

	if got := gatedGet(h, "/consent").Code; got != http.StatusBadRequest {
		t.Errorf("a request with no registration is the caller's fault: want 400, got %d", got)
	}
	if got := gatedGet(h, consentURL("not-an-envelope", "")).Code; got != http.StatusBadRequest {
		t.Errorf("an envelope this deployment cannot open is the caller's fault: want 400, got %d", got)
	}
	// 🔴 The closed lanes publish a listable set, so a console can show it and
	// this page must refuse. Rendering it would tell a customer their
	// four-record, 24-hour grant is a standing wildcard.
	closed := registrationFor(t, sealer, lane.OrgPlatformDomain, "example.com")
	if got := gatedGet(h, consentURL(closed, "")).Code; got != http.StatusBadRequest {
		t.Errorf("org_platform_domain has no consent page: want 400, got %d", got)
	}

	// A deployment that cannot open envelopes at all is OURS, not the caller's.
	unwired := &dispatcher{intents: &intent.Service{}}
	if got := gatedGet(unwired.httpHandler("s3cret"), consentURL("anything", "")).Code; got != http.StatusServiceUnavailable {
		t.Errorf("a deployment with no keyset is unavailable, not a bad request: got %d", got)
	}
	if got := gatedGet((&dispatcher{}).httpHandler("s3cret"), consentURL("anything", "")).Code; got != http.StatusServiceUnavailable {
		t.Errorf("no intent surface wired must be 503, got %d", got)
	}
}

func TestConsentPageRendersTheWildcardGrant(t *testing.T) {
	d, sealer := intentDispatcher(t)
	h := d.httpHandler("s3cret")

	rec := gatedGet(h, consentURL(registrationFor(t, sealer, lane.OrgAppDomain, "example.net"), ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"example.net", "*.example.net", "_mirrorstack-challenge.example.net"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page must name %q", want)
		}
	}

	// 🔴 THE PAGE MUST NOT CARRY AN ACKNOWLEDGEMENT. Being shown the page and
	// agreeing to it are two events. If rendering minted a token, everything
	// holding the internal secret — the private half included — would hold a
	// customer's agreement to a standing wildcard without a customer having read
	// a word of it. `msack1-` is internal/consent's acknowledgement prefix.
	if strings.Contains(body, "msack1-") {
		t.Error("🔴 rendering the consent page minted an acknowledgement")
	}

	header := rec.Result().Header
	// The page loads nothing, and this header is what makes a browser enforce it.
	if csp := header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("want a default-src 'none' policy, got %q", csp)
	}
	if ct := header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("want text/html, got %q", ct)
	}
	if header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("want nosniff")
	}
	// 🔴 The page names the anchor and every value we would write beneath it.
	if cc := header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("a shared cache holding this page would serve somebody else's zone: got %q", cc)
	}
}

// A supplied reference is used verbatim, so the same page can be rendered twice
// and diffed; an absent one is minted, which is safe precisely because a nonce
// alone authorizes nothing — it is only the index an acknowledgement would be
// bound to, and this route mints no acknowledgement.
func TestConsentPageUsesTheSuppliedReference(t *testing.T) {
	d, sealer := intentDispatcher(t)
	h := d.httpHandler("s3cret")
	registration := registrationFor(t, sealer, lane.OrgAppDomain, "example.net")

	const reference = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	rec := gatedGet(h, consentURL(registration, reference))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), reference) {
		t.Error("the supplied reference must appear on the page an acknowledgement is bound to")
	}

	first := gatedGet(h, consentURL(registration, "")).Body.String()
	second := gatedGet(h, consentURL(registration, "")).Body.String()
	if first == second {
		t.Error("a minted reference must be fresh per render")
	}
}

// ─── fixtures ───────────────────────────────────────────────────────────────

// testIdentity is a canonical 36-character hyphenated UUID, which is the only
// form lane.ValidateIdentity accepts and therefore the only form a sealed
// registration can be opened with.
const testIdentity = "11111111-2222-3333-4444-555555555555"

func intentDispatcher(t *testing.T) (*dispatcher, *grantcrypto.Sealer) {
	t.Helper()
	sealer := newSealer(t)
	return &dispatcher{intents: &intent.Service{
		OAuth: stubOAuth{cfg: &cfoauth.Config{Config: oauth2.Config{
			ClientID: "cid", RedirectURL: "https://account.example/cb", Scopes: []string{"dns.write"},
		}}},
		Keys: stubKeys{sealer: sealer},
		Derive: derive.Config{
			OrgRoutingTarget:  "connect.mirrorstack.ai",
			AppRoutingTarget:  "connect.mirrorstack.app",
			DCVDelegationUUID: "a1b2c3d4e5f60718",
			ReservedSuffixes:  []string{"mirrorstack.ai", "mirrorstack.app"},
		},
		// No Resolver and no relays: rendering the consent page reaches neither,
		// and a fixture that supplied them would hide it if that ever changed.
	}}, sealer
}

func registrationFor(t *testing.T, s *grantcrypto.Sealer, l lane.Lane, anchor string) string {
	t.Helper()
	envelope, _, err := sealed.SealRegistration(s, sealed.Registration{
		Lane: l, Identity: testIdentity, Anchor: anchor, IssuedAt: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("SealRegistration: %v", err)
	}
	return envelope
}

// consentURL builds the route's query with proper escaping: a sealed envelope is
// base64 and can carry characters a hand-built query string would corrupt.
func consentURL(registration, nonce string) string {
	values := url.Values{"registration": {registration}}
	if nonce != "" {
		values.Set("nonce", nonce)
	}
	return "/consent?" + values.Encode()
}

func gatedGet(h http.Handler, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("X-MS-Internal-Secret", "s3cret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func newSealer(t *testing.T) *grantcrypto.Sealer {
	t.Helper()
	raw := make([]byte, grantcrypto.KeySize)
	for i := range raw {
		raw[i] = byte(i*7 + 1)
	}
	keys, err := grantcrypto.ParseKeyset(fmt.Sprintf(
		`{"active":"k1","keys":{"k1":%q}}`, base64.StdEncoding.EncodeToString(raw)))
	if err != nil {
		t.Fatalf("ParseKeyset: %v", err)
	}
	sealer, err := grantcrypto.NewSealer(keys)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return sealer
}

type stubKeys struct{ sealer *grantcrypto.Sealer }

func (s stubKeys) Sealer(context.Context) *grantcrypto.Sealer { return s.sealer }
