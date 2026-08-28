package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
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
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/observe"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/relay"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/sealed"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/cfedge"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/cfoauth"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/grantcrypto"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/testsupport"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/testsupport/derivefixture"
)

func readyDispatcher() *dispatcher {
	return &dispatcher{grants: &grant.Service{
		OAuth: testsupport.StubOAuth{Cfg: &cfoauth.Config{Config: oauth2.Config{
			ClientID: "cid", RedirectURL: "https://account.example/cb", Scopes: []string{"dns.write"},
		}}},
	}}
}

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

// 🔴 THE DEPLOYED COMMIT IS WHAT MAKES EVERY OTHER CLAIM CHECKABLE.
//
// docs/DESIGN.md §4 says health() publishes it, and the reason is that nothing
// in this repository is a fact about a RUNNING service until a reader can tell
// that the code they audited is the code answering them. So it must be on the
// wire, on every answer — a deployment that is refusing traffic is exactly when
// somebody needs to know which code is refusing — and it must degrade to
// "unknown" rather than to something plausible. A wrong-but-well-formed sha is
// worse than none: it gets looked up, missed, and either discredits the whole
// surface or sends an auditor to the wrong tree.
//
// `go test` passes no -ldflags, so this binary IS the unstamped case, which is
// the half of the contract Go can pin. TestPublishWorkflowStampsTheCommit pins
// the other half.
func TestHealthPublishesTheDeployedCommit(t *testing.T) {
	if commit != "unknown" {
		t.Fatalf("an unstamped build must report %q, got %q", "unknown", commit)
	}

	// Healthy and unhealthy alike.
	for _, d := range []*dispatcher{{}, readyDispatcher()} {
		if got := d.health(context.Background()).Commit; got != commit {
			t.Errorf("health must carry the build stamp on every answer, got %q", got)
		}
	}

	// On the WIRE, not merely on the struct: DESIGN §4's claim is about what a
	// caller can read, and a field with no JSON tag publishes nothing.
	body, err := json.Marshal(readyDispatcher().health(context.Background()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["commit"] != "unknown" {
		t.Errorf("want commit on the health envelope, got %s", body)
	}
}

// 🔴 THE STAMP IS ONLY REAL IF THE WORKFLOW PASSES IT, AND NOTHING IN GO CHECKS
// THAT.
//
// `commit` defaults to "unknown" and is set by the linker at the one build that
// produces a deployed artifact. Delete the -X from publish.yml and every test
// above still passes, `make check` still passes, the deploy still succeeds — and
// production reports "unknown" forever while docs/DESIGN.md §4 quietly becomes
// false. This is the arming path, asserted from the only place it can be.
func TestPublishWorkflowStampsTheCommit(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/publish.yml")
	if err != nil {
		t.Fatalf("read publish.yml: %v", err)
	}
	if !strings.Contains(string(raw), "-X main.commit=$GITHUB_SHA") {
		t.Error("publish.yml no longer stamps main.commit: the deployed build would report \"unknown\", " +
			"and a reader could not tell that the code they audited is the code running")
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
	oauth := testsupport.StubOAuth{Cfg: &cfoauth.Config{Config: oauth2.Config{ClientID: "cid"}}}

	intentsOnly := &dispatcher{intents: &intent.Service{OAuth: oauth}}
	if got := intentsOnly.health(context.Background()); !got.OK || got.Delegation != "no-keyset" {
		t.Fatalf("the intent surface alone must report a healthy no-keyset deployment: %#v", got)
	}

	held := &dispatcher{intents: &intent.Service{OAuth: oauth, Keys: testsupport.StubKeys{Held: newSealer(t)}}}
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

// `route.writes` is DERIVED from each action's response type rather than
// declared, so this test is not cross-checking one hand-written list against
// another — it pins the fact the derivation rests on: intent.PassResponse is
// returned by exactly the actions that can reach a customer's zone.
//
// It fails if an action starts or stops returning PassResponse, which is the
// change that would silently reclassify it.
func TestTheWritingActionsAreExactlyTheDeclaredSet(t *testing.T) {
	want := map[string]bool{
		"Complete": true, "Advance": true, "BindAppToOrgAppDomain": true,
		// The one action whose writing is invisible in its type, and the reason
		// the record-list surface is worth replacing.
		actionPublish: true,
	}
	for name, r := range routes {
		if r.writes != want[name] {
			t.Errorf("%q: writes=%v, want %v", name, r.writes, want[name])
		}
	}
}

func TestTheDeprecatedActionsAreExactlyTheLegacyFour(t *testing.T) {
	want := map[string]bool{"Capabilities": true, "Authorize": true, actionPublish: true, "Revoke": true}
	for name, r := range routes {
		if r.deprecated != want[name] {
			t.Errorf("%q: deprecated=%v, want %v", name, r.deprecated, want[name])
		}
	}
	if len(want) != 4 {
		t.Fatalf("the legacy surface is four actions, not %d", len(want))
	}
}

// Every route must be reachable, and an action this build does not implement
// must refuse rather than answer. A nil handler in the table would panic on the
// first real invocation instead.
func TestEveryRouteIsReachableAndUnknownIsRefused(t *testing.T) {
	d := &dispatcher{}
	for name, r := range routes {
		if r.handle == nil {
			t.Fatalf("%q has no handler", name)
		}
		// With no service wired, every action must return a refusal rather than
		// panic. The refusal itself is the surface's own sentinel, which
		// TestErrorCodesAreTheCallersContract covers.
		if _, err := d.dispatch(t.Context(), name, nil); err == nil && name != "Health" && name != "Capabilities" {
			t.Errorf("%q answered with no service wired; it must refuse", name)
		}
	}
	if _, err := d.dispatch(t.Context(), "NoSuchAction", nil); !errors.Is(err, errUnknownAction) {
		t.Fatalf("an unimplemented action must be errUnknownAction, got %v", err)
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

	target := consentURL(registrationFor(t, sealer, lane.OrgAppDomain, "example.net"))
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
	if got := gatedGet(h, consentURL("not-an-envelope")).Code; got != http.StatusBadRequest {
		t.Errorf("an envelope this deployment cannot open is the caller's fault: want 400, got %d", got)
	}
	// 🔴 The closed lanes publish a listable set, so a console can show it and
	// this page must refuse. Rendering it would tell a customer their
	// four-record, 24-hour grant is a standing wildcard.
	closed := registrationFor(t, sealer, lane.OrgPlatformDomain, "example.com")
	if got := gatedGet(h, consentURL(closed)).Code; got != http.StatusBadRequest {
		t.Errorf("org_platform_domain has no consent page: want 400, got %d", got)
	}

	// A deployment that cannot open envelopes at all is OURS, not the caller's.
	unwired := &dispatcher{intents: &intent.Service{}}
	if got := gatedGet(unwired.httpHandler("s3cret"), consentURL("anything")).Code; got != http.StatusServiceUnavailable {
		t.Errorf("a deployment with no keyset is unavailable, not a bad request: got %d", got)
	}
	if got := gatedGet((&dispatcher{}).httpHandler("s3cret"), consentURL("anything")).Code; got != http.StatusServiceUnavailable {
		t.Errorf("no intent surface wired must be 503, got %d", got)
	}
}

func TestConsentPageRendersTheWildcardGrant(t *testing.T) {
	d, sealer := intentDispatcher(t)
	h := d.httpHandler("s3cret")

	rec := gatedGet(h, consentURL(registrationFor(t, sealer, lane.OrgAppDomain, "example.net")))
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

// 🔴 THE REFERENCE THE PAGE IS BOUND TO COMES OUT OF THE SEALED REGISTRATION,
// AND THE REQUESTER CANNOT CHOOSE IT.
//
// An acknowledgement is a MAC over (reference, anchor). If the reference came
// off the URL, the requester would hold both halves of that pair, and one
// agreement — given once, by one customer, on one screen — would satisfy every
// later authorization on that anchor forever. Sealing it makes the
// acknowledgement specific to the registration this deployment minted.
//
// The failure mode is silent, which is why this is a test rather than a comment:
// a page rendered against a chosen reference is byte-identical in shape to a
// correct one, and every other assertion in this file would still pass.
func TestConsentPageReferenceIsSealedAndUnchoosable(t *testing.T) {
	d, sealer := intentDispatcher(t)
	h := d.httpHandler("s3cret")
	registration := registrationFor(t, sealer, lane.OrgAppDomain, "example.net")

	rec := gatedGet(h, consentURL(registration))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), testConsentReference) {
		t.Fatal("the page must print the reference sealed into the registration")
	}

	// Stable across renders: it is sealed, not minted per request. A customer who
	// reloads the screen must not be agreeing to a different reference than the
	// one Authorize will verify their acknowledgement against.
	if first, second := gatedGet(h, consentURL(registration)).Body.String(),
		gatedGet(h, consentURL(registration)).Body.String(); first != second {
		t.Error("the sealed reference must not change between renders")
	}

	// 🔴 And a reference on the URL must not be honoured. This is the exact
	// regression: `?nonce=` used to select it.
	chosen := "00112233445566778899aabbccddeeff"
	body := gatedGet(h, consentURL(registration)+"&nonce="+chosen).Body.String()
	if strings.Contains(body, chosen) {
		t.Error("🔴 the route honoured a requester-chosen reference: one acknowledgement would replay forever")
	}
	if !strings.Contains(body, testConsentReference) {
		t.Error("the sealed reference must survive a nonce on the query string")
	}
}

// 🔴 A LANE-2 REGISTRATION WITH NO SEALED REFERENCE IS REFUSED, NOT RENDERED.
//
// Such an envelope was minted by a build without this control. Rendering it
// would show a customer the disclosure, take their agreement, and then refuse
// the acknowledgement at Authorize with nothing anywhere saying why.
func TestConsentPageRefusesARegistrationWithNoSealedReference(t *testing.T) {
	d, sealer := intentDispatcher(t)
	h := d.httpHandler("s3cret")

	unreferenced := sealRegistration(t, sealer, lane.OrgAppDomain, "example.net", "")
	if got := gatedGet(h, consentURL(unreferenced)).Code; got != http.StatusBadRequest {
		t.Errorf("a registration carrying no consent reference must be refused: want 400, got %d", got)
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
		OAuth: testsupport.StubOAuth{Cfg: &cfoauth.Config{Config: oauth2.Config{
			ClientID: "cid", RedirectURL: "https://account.example/cb", Scopes: []string{"dns.write"},
		}}},
		Keys:   testsupport.StubKeys{Held: sealer},
		Derive: derivefixture.Config(),
		// No Resolver and no relays: rendering the consent page reaches neither,
		// and a fixture that supplied them would hide it if that ever changed.
	}}, sealer
}

// testConsentReference is a 32-hex-character reference, the only shape
// sealed.Registration accepts. Fixed rather than minted so a test can assert the
// page carries THIS value and not merely some value.
const testConsentReference = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

// registrationFor mirrors what the register intent seals: a consent reference on
// the lane that has a consent page, and none on the lanes that publish a closed,
// listable set. Sealing one on every lane would hide the refusal below.
func registrationFor(t *testing.T, s *grantcrypto.Sealer, l lane.Lane, anchor string) string {
	t.Helper()
	reference := ""
	if consent.Required(l) {
		reference = testConsentReference
	}
	return sealRegistration(t, s, l, anchor, reference)
}

func sealRegistration(
	t *testing.T, s *grantcrypto.Sealer, l lane.Lane, anchor, reference string,
) string {
	t.Helper()
	envelope, _, err := sealed.SealRegistration(s, sealed.Registration{
		Lane: l, Identity: testIdentity, Anchor: anchor,
		ConsentNonce: reference, IssuedAt: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("SealRegistration: %v", err)
	}
	return envelope
}

// consentURL builds the route's query with proper escaping: a sealed envelope is
// base64 and can carry characters a hand-built query string would corrupt.
//
// It takes ONE argument on purpose. The reference an acknowledgement is MACed
// over rides inside the registration, so there is no second parameter for a
// caller to choose — see TestConsentPageReferenceIsSealedAndUnchoosable.
func consentURL(registration string) string {
	return "/consent?" + url.Values{"registration": {registration}}.Encode()
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
	key := make([]byte, grantcrypto.KeySize)
	for i := range key {
		key[i] = byte(i*7 + 1)
	}
	return testsupport.SealerWithKey(t, "k1", key)
}

// 🔴 A deployment that cannot reach enough vantage points to meet its own
// threshold verifies nothing: every proof reads `unknown` and every
// authorization is refused. It is out of service whether or not it admits it,
// and mirrorstack-infra's probe is what acts on the admission.
func TestHealthFailsWhenTooFewVantagePointsAreReachable(t *testing.T) {
	// Two vantage points, both of which must agree: the rule a customer would
	// have read from Capabilities before authorizing.
	svc := func(reach intent.ReachProbe) *dispatcher {
		return &dispatcher{intents: &intent.Service{
			OAuth: testsupport.StubOAuth{Cfg: &cfoauth.Config{Config: oauth2.Config{ClientID: "cid"}}},
			Keys:  testsupport.StubKeys{Held: newSealer(t)},
			Resolver: observe.Quorum{
				Resolvers: []observe.Resolver{unusedResolver{}, unusedResolver{}},
				Threshold: 2,
			},
			Reach: reach,
		}}
	}

	got := svc(stubReach{threshold: 2, reachable: 1}).health(context.Background())
	if got.OK {
		t.Fatalf("1 reachable vantage point under a threshold of 2 must fail health: %#v", got)
	}
	if got.Resolution == nil || got.Resolution.Threshold != 2 || !got.Resolution.Reachability.Degraded {
		t.Fatalf("health must carry the reading it refused on: %#v", got.Resolution)
	}
	// 🔴 And the rule is republished whole. A degraded deployment reports a
	// threshold it cannot meet; it never reports one it can.
	if got.Resolution.Vantages != 2 {
		t.Fatalf("resolution %#v; the declared rule must survive the failure unchanged", got.Resolution)
	}

	if got := svc(stubReach{threshold: 2, reachable: 2}).health(context.Background()); !got.OK {
		t.Fatalf("a deployment that can meet its own threshold is healthy: %#v", got)
	}

	// Unmeasured is not unreachable. Failing health over a probe nobody wired
	// would take out every deployment running as this service did before it.
	if got := svc(nil).health(context.Background()); !got.OK {
		t.Fatalf("an unmeasured deployment must stay in rotation: %#v", got)
	}
}

// stubReach is a measurement a test dictates; the vantage points are only as
// real as the count.
type stubReach struct {
	threshold int
	reachable int
}

func (s stubReach) Reach(context.Context) observe.Reach {
	out := observe.Reach{Threshold: s.threshold, CheckedAt: time.Unix(1_700_000_000, 0)}
	for i := range s.threshold {
		out.Vantages = append(out.Vantages, observe.Reachability{
			Vantage:   fmt.Sprintf("192.0.2.%d:53", i+1),
			Reachable: i < s.reachable,
		})
	}
	return out
}

// unusedResolver exists so Capabilities has a resolver to report a policy from.
// No test in this package resolves a name.
type unusedResolver struct{}

func (unusedResolver) LookupCNAME(context.Context, string) (string, error) {
	panic("no test here resolves a name")
}

func (unusedResolver) LookupTXT(context.Context, string) ([]string, error) {
	panic("no test here resolves a name")
}

// 🔴 AN UNCONFIGURED EDGE IS WIRED AS NIL, WHICH internal/relay REPORTS AS "NOT
// YET". Anything else would put a warning on every pass of a deployment nobody
// had finished configuring — and a fake reader would be worse still, since an
// invented serving proof is published into a customer's zone, and an invented
// delegation identifier is a record 6 aimed at a name Cloudflare never wrote to.
func TestTheEdgeReadsAreWiredOnlyWhenBothAZoneAndACredentialAreNamed(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"nothing set":         {},
		"zones but no token":  {edgeOrgZoneEnv: "org-zone", edgeAppZoneEnv: "app-zone"},
		"a token but no zone": {cfedge.TokenEnv: "ms-token"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(edgeOrgZoneEnv, env[edgeOrgZoneEnv])
			t.Setenv(edgeAppZoneEnv, env[edgeAppZoneEnv])
			t.Setenv(cfedge.TokenEnv, env[cfedge.TokenEnv])
			t.Setenv(cfedge.SecretIDEnv, "")
			edge, delegation := edgeReaders()
			// Both nil, and both UNTYPED nil: a typed nil pointer is non-nil
			// through an interface and would fail every pass instead of
			// falling back.
			if edge != nil || delegation != nil {
				t.Fatalf("want nil readers, got %#v / %#v", edge, delegation)
			}
		})
	}

	t.Setenv(edgeOrgZoneEnv, "org-zone")
	t.Setenv(edgeAppZoneEnv, "app-zone")
	t.Setenv(cfedge.TokenEnv, "ms-token")
	t.Setenv(cfedge.SecretIDEnv, "")
	edge, delegation := edgeReaders()
	if delegation == nil {
		t.Fatal("a wired credential must also read the DCV delegation identifier")
	}
	reporter, ok := edge.(relay.EdgeZoneReporter)
	if !ok {
		t.Fatalf("a wired reader must be able to name its zones, got %T", edge)
	}
	// The two zones must arrive from the two variables, not one from both: the
	// swap has no symptom other than hosts that never start serving.
	if zones := reporter.EdgeZones(); zones.OrgPlatform != "org-zone" || zones.App != "app-zone" {
		t.Fatalf("the per-lane zones are mis-wired: %#v", zones)
	}
}

// 🔴 THE ACKNOWLEDGEMENT IS PRODUCED BY POSTING BACK WHAT THE PAGE CARRIED, AND
// BY NOTHING ELSE. A registration alone must never be enough: that is the bare
// `ConsentAck` this design exists to not have, and holding one would let anything
// able to reach this route mint a customer's agreement to a standing wildcard.
func TestOnlyTheChallengeOffTheServedPageMintsAnAcknowledgement(t *testing.T) {
	d, sealer := intentDispatcher(t)
	h := d.httpHandler("s3cret")
	registration := registrationFor(t, sealer, lane.OrgAppDomain, "example.net")

	page := gatedGet(h, consentURL(registration))
	if page.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", page.Code, page.Body.String())
	}
	challenge := challengeFrom(t, page.Body.String())

	// Nothing but the challenge redeems: no field, an empty one, and one invented
	// by whoever is asking.
	for _, form := range []url.Values{
		{},
		{"challenge": {""}},
		{"challenge": {"mschal1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
	} {
		if got := gatedPost(h, consentURL(registration), form).Code; got != http.StatusBadRequest {
			t.Errorf("the form %v must not acknowledge: want 400, got %d", form, got)
		}
	}

	rec := gatedPost(h, consentURL(registration), url.Values{"challenge": {challenge}})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var answer struct {
		OK       bool `json:"ok"`
		Response struct {
			ConsentToken string `json:"consentToken"`
		} `json:"response"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !answer.OK || !consent.Verify(sealer, testConsentReference, "example.net", answer.Response.ConsentToken) {
		t.Fatalf("the acknowledgement must be the one IntentAuthorize checks: %q", answer.Response.ConsentToken)
	}
	// 🔴 It is credential-shaped, and a shared cache holding it would hand
	// somebody else's agreement to the next request.
	if cc := rec.Result().Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("want no-store on the acknowledgement, got %q", cc)
	}
}

func TestAcknowledgingIsGatedLikeEveryOtherRoute(t *testing.T) {
	d, sealer := intentDispatcher(t)
	h := d.httpHandler("s3cret")
	target := consentURL(registrationFor(t, sealer, lane.OrgAppDomain, "example.net"))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, target, strings.NewReader("challenge=x")))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("acknowledging must be behind the internal secret, got %d", rec.Code)
	}
	if got := gatedPost(h, "/consent", url.Values{"challenge": {"x"}}).Code; got != http.StatusBadRequest {
		t.Errorf("a POST with no registration is the caller's fault: want 400, got %d", got)
	}
}

// 🔴 NEITHER HALF OF THE CONSENT FLOW IS A WIRE ACTION, AND NEITHER MAY BECOME
// ONE. This Lambda is IAM-gated, so an entry in `routes` is something
// MirrorStack's private half can call; with "serve the page" and "acknowledge it"
// both on that surface, the private half holds a customer's agreement to a
// standing wildcard with no customer involved and the control is gone. The
// failure is silent — adding a route breaks no test that exists — which is why
// this one names both spellings.
func TestNoWireActionServesOrAcknowledgesTheConsentPage(t *testing.T) {
	d, _ := intentDispatcher(t)
	for _, action := range []string{"ConsentPage", "ConsentAck", "AcknowledgeConsent", "Consent"} {
		if _, err := d.dispatch(context.Background(), action, nil); !errors.Is(err, errUnknownAction) {
			t.Errorf("🔴 %q is dispatchable: the consent flow must live only on the page's own route", action)
		}
	}
	for action := range routes {
		if strings.Contains(action, "onsent") {
			t.Errorf("🔴 the route table names %q", action)
		}
	}
}

// The consent route is reachable on the transport a real deployment has: API
// Gateway, mapped at a path with a stage in front of it. Everything else keeps
// the static probe, because mirrorstack-infra maps that at a path this file does
// not know.
func TestTheGatewayServesTheConsentPathAndProbesEverythingElse(t *testing.T) {
	d, sealer := intentDispatcher(t)
	d.web = d.httpHandler("s3cret")
	registration := registrationFor(t, sealer, lane.OrgAppDomain, "example.net")

	page := gatewayCall(t, d, "GET", "/dns-delegate/consent",
		url.Values{"registration": {registration}}.Encode(), "")
	if page["statusCode"] != http.StatusOK {
		t.Fatalf("the gateway must serve the consent page, got %#v", page)
	}
	body, _ := page["body"].(string)
	if !strings.Contains(body, "*.example.net") {
		t.Fatal("the gateway served something other than the consent page")
	}

	ack := gatewayCall(t, d, "POST", "/dns-delegate/consent",
		url.Values{"registration": {registration}}.Encode(),
		url.Values{"challenge": {challengeFrom(t, body)}}.Encode())
	if ack["statusCode"] != http.StatusOK {
		t.Fatalf("the gateway must serve the acknowledgement, got %#v", ack)
	}

	// 🔴 Unchanged for every other path: the probe answers 200 without touching
	// the dispatcher, whatever stage or base path infra puts in front of it.
	probe := gatewayCall(t, d, "GET", "/dns-delegate/healthz", "", "")
	if probe["statusCode"] != http.StatusOK || probe["body"] != `{"ok":true}` {
		t.Fatalf("the health probe must keep its static answer, got %#v", probe)
	}
	// And the gate rides along: a gateway route is not a way around it.
	unsecreted := &dispatcher{intents: d.intents, web: d.httpHandler("s3cret")}
	got := unsecretedGatewayCall(t, unsecreted, "/dns-delegate/consent",
		url.Values{"registration": {registration}}.Encode())
	if got["statusCode"] != http.StatusUnauthorized {
		t.Fatalf("the internal secret must gate the gateway route too, got %#v", got)
	}
}

func gatedPost(h http.Handler, target string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("X-MS-Internal-Secret", "s3cret")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func gatewayCall(t *testing.T, d *dispatcher, method, path, query, body string) map[string]any {
	t.Helper()
	return invokeGateway(t, d, gatewayPayload(t, method, path, query, body, map[string]string{
		"x-ms-internal-secret": "s3cret",
		"content-type":         "application/x-www-form-urlencoded",
	}))
}

func unsecretedGatewayCall(t *testing.T, d *dispatcher, path, query string) map[string]any {
	t.Helper()
	return invokeGateway(t, d, gatewayPayload(t, "GET", path, query, "", nil))
}

func invokeGateway(t *testing.T, d *dispatcher, payload json.RawMessage) map[string]any {
	t.Helper()
	out, err := d.lambdaHandler(context.Background(), payload)
	if err != nil {
		t.Fatalf("lambdaHandler: %v", err)
	}
	got, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("want a gateway response, got %#v", out)
	}
	return got
}

// gatewayPayload is an API Gateway payload format 2.0 request, built here rather
// than imported so this file states the shape it decodes.
func gatewayPayload(
	t *testing.T, method, path, query, body string, headers map[string]string,
) json.RawMessage {
	t.Helper()
	event := map[string]any{
		"rawPath":        path,
		"rawQueryString": query,
		"headers":        headers,
		"body":           body,
		"requestContext": map[string]any{"http": map[string]any{"method": method}},
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return encoded
}

// challengeFrom reads the one hidden input off the served page: what a test
// posts back is what a browser would.
var challengeValue = regexp.MustCompile(`name="challenge" value="([^"]+)"`)

func challengeFrom(t *testing.T, page string) string {
	t.Helper()
	match := challengeValue.FindStringSubmatch(page)
	if len(match) != 2 {
		t.Fatal("the served page carries no challenge, so nobody could acknowledge it")
	}
	return match[1]
}
