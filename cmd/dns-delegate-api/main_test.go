package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubPinger struct{ err error }

func (s stubPinger) Ping(context.Context) error { return s.err }

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

func TestHealthIsTruthfulAboutTheDatabase(t *testing.T) {
	cases := []struct {
		name string
		db   pinger
		want string
	}{
		{"no pool", nil, "unconfigured"},
		{"unreachable", stubPinger{err: errors.New("dial")}, "unreachable"},
		{"reachable", stubPinger{}, "ok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &dispatcher{}
			if tc.db != nil {
				d.db = tc.db
			}
			got := d.health(context.Background())
			if got.Database != tc.want {
				t.Fatalf("want %q, got %q", tc.want, got.Database)
			}
			if got.OK != (tc.want == "ok") {
				t.Fatalf("ok=%v disagrees with database=%q", got.OK, got.Database)
			}
		})
	}
}

func TestHTTPHealthzIsUngatedAndReadyzIsNot(t *testing.T) {
	d := &dispatcher{db: stubPinger{}}
	h := d.httpHandler("s3cret")

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
