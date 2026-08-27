package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/grant"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/cfoauth"
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
