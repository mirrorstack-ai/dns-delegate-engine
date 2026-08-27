package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func serve(t *testing.T, secret, header string) *httptest.ResponseRecorder {
	t.Helper()
	reached := false
	h := InternalSecret(secret)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if header != "" {
		req.Header.Set(headerInternalSecret, header)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK != reached {
		t.Fatalf("handler reached=%v but status=%d", reached, rec.Code)
	}
	return rec
}

func TestInternalSecretRefusesWhenUnconfigured(t *testing.T) {
	// The fail-OPEN reading of an empty secret is how an internal service ends
	// up answering the internet. Even a matching empty header must not pass.
	for _, header := range []string{"", "anything"} {
		if got := serve(t, "", header).Code; got != http.StatusServiceUnavailable {
			t.Fatalf("empty secret with header %q: want 503, got %d", header, got)
		}
	}
}

func TestInternalSecretRefusesMismatch(t *testing.T) {
	for _, header := range []string{"", "wrong", "s3cretx", "s3cre"} {
		if got := serve(t, "s3cret", header).Code; got != http.StatusUnauthorized {
			t.Fatalf("header %q: want 401, got %d", header, got)
		}
	}
}

func TestInternalSecretAdmitsMatch(t *testing.T) {
	if got := serve(t, "s3cret", "s3cret").Code; got != http.StatusOK {
		t.Fatalf("want 200, got %d", got)
	}
}
