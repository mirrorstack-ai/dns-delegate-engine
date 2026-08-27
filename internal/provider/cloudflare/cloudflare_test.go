package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsprovider"
)

func serverFor(t *testing.T, h http.HandlerFunc) Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return Client{Base: srv.URL, HTTPClient: srv.Client()}
}

func TestFindZonePicksTheMostSpecificAuthorizedZone(t *testing.T) {
	var asked []string
	c := serverFor(t, func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		asked = append(asked, name)
		if name == "customer-owned.example" {
			_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"zoneA"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"success":true,"result":[]}`)
	})
	id, err := c.FindZone(context.Background(), "tok", "shop.customer-owned.example")
	if err != nil {
		t.Fatalf("FindZone: %v", err)
	}
	if id != "zoneA" {
		t.Fatalf("want zoneA, got %q", id)
	}
	// Most specific first: a parent zone would let a write land beside records
	// the plan never named.
	if asked[0] != "shop.customer-owned.example" {
		t.Fatalf("the most specific name must be tried first, got %v", asked)
	}
}

func TestFindZoneFailsWhenNoZoneIsAuthorized(t *testing.T) {
	c := serverFor(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"success":true,"result":[]}`)
	})
	if _, err := c.FindZone(context.Background(), "tok", "shop.example.test"); err == nil {
		t.Fatal("an unauthorized zone must be an error, not an empty id")
	}
}

func TestTokenTravelsAsABearerAndIsNotInTheBody(t *testing.T) {
	var auth, body string
	c := serverFor(t, func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		_, _ = io.WriteString(w, `{"success":true,"result":{"id":"rec1"}}`)
	})
	_, err := c.CreateRecord(context.Background(), "s3cret-token", "z", dnsprovider.Desired{
		Type: "CNAME", Name: "a.example", Value: "b.example",
	})
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	if auth != "Bearer s3cret-token" {
		t.Fatalf("token must ride the Authorization header, got %q", auth)
	}
	if strings.Contains(body, "s3cret-token") {
		t.Fatal("the token must never appear in a request body")
	}
}

// 🔴 A TXT value must go out quoted and a quoted read-back must compare equal.
// Getting the pair wrong either publishes literal quote characters or reads
// every already-correct record as missing and rewrites it on every pass.
func TestTXTQuotingIsIdempotentAndComparesUnquoted(t *testing.T) {
	var sent recordInput
	c := serverFor(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&sent)
		_, _ = io.WriteString(w, `{"success":true,"result":{"id":"rec1"}}`)
	})
	for _, given := range []string{"hello-value", `"hello-value"`, "  hello-value  "} {
		if _, err := c.CreateRecord(context.Background(), "t", "z", dnsprovider.Desired{
			Type: "TXT", Name: "_x.example", Value: given,
		}); err != nil {
			t.Fatalf("CreateRecord: %v", err)
		}
		if sent.Content != `"hello-value"` {
			t.Fatalf("input %q produced content %q", given, sent.Content)
		}
	}
	if !c.SameValue("TXT", `"hello-value"`, "hello-value") {
		t.Fatal("a quoted read-back must compare equal to the unquoted desired value")
	}
	if c.SameValue("TXT", `"other"`, "hello-value") {
		t.Fatal("different payloads must not compare equal")
	}
}

func TestSameValueForCNAMEIgnoresCaseAndTheRootDot(t *testing.T) {
	c := Client{}
	if !c.SameValue("CNAME", "Edge.MirrorStack.ai.", "edge.mirrorstack.ai") {
		t.Fatal("CNAME comparison must fold case and the root dot")
	}
	if c.SameValue("CNAME", "elsewhere.example", "edge.mirrorstack.ai") {
		t.Fatal("different targets must not compare equal")
	}
}

func TestPatchUsesPATCHSoCustomerOwnedFieldsSurvive(t *testing.T) {
	var method string
	c := serverFor(t, func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		_, _ = io.WriteString(w, `{"success":true}`)
	})
	if err := c.PatchRecord(context.Background(), "t", "z", "rec1", dnsprovider.Desired{
		Type: "CNAME", Name: "a.example", Value: "b.example",
	}); err != nil {
		t.Fatalf("PatchRecord: %v", err)
	}
	// PUT would drop the customer's comment and tags on their own record.
	if method != http.MethodPatch {
		t.Fatalf("want PATCH, got %s", method)
	}
}

func TestCreatePayloadCarriesNoReadOnlyFields(t *testing.T) {
	var raw map[string]any
	c := serverFor(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&raw)
		_, _ = io.WriteString(w, `{"success":true,"result":{"id":"rec1"}}`)
	})
	if _, err := c.CreateRecord(context.Background(), "t", "z", dnsprovider.Desired{
		Type: "CNAME", Name: "a.example", Value: "b.example", Proxied: true,
	}); err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	if _, present := raw["id"]; present {
		t.Fatal("a read-only field leaked into the write payload")
	}
	if raw["proxied"] != true {
		t.Fatalf("proxied must be sent explicitly, got %#v", raw["proxied"])
	}
}

func TestIsDuplicateMatchesCloudflaresCodes(t *testing.T) {
	c := Client{}
	for _, code := range []int{81057, 81058} {
		if !c.IsDuplicate(&APIError{Code: code}) {
			t.Fatalf("code %d must be a duplicate", code)
		}
	}
	if c.IsDuplicate(&APIError{Code: 1004}) {
		t.Fatal("an unrelated code must not read as a duplicate")
	}
	if c.IsDuplicate(errors.New("boom")) {
		t.Fatal("a non-API error is not a duplicate")
	}
}

// 🔴 Fail TOWARD ambiguous. Claiming certainty about an error we do not
// recognise makes the reconciler treat a possibly-applied write as definitively
// failed.
func TestIsAmbiguousFailsTowardAmbiguous(t *testing.T) {
	c := Client{}
	if !c.IsAmbiguous(errors.New("transport reset")) {
		t.Fatal("an unrecognised error must be ambiguous")
	}
	for _, status := range []int{http.StatusRequestTimeout, http.StatusTooManyRequests, 500, 502, 503, 504} {
		if !c.IsAmbiguous(&APIError{Status: status}) {
			t.Fatalf("status %d must be ambiguous", status)
		}
	}
	for _, status := range []int{400, 401, 403, 404, 409} {
		if c.IsAmbiguous(&APIError{Status: status}) {
			t.Fatalf("status %d is a definitive rejection, not ambiguous", status)
		}
	}
}

func TestAPIErrorCarriesCloudflaresCodeNotItsMessageText(t *testing.T) {
	c := serverFor(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":81057,"message":"Record already exists."}]}`)
	})
	_, err := c.CreateRecord(context.Background(), "t", "z", dnsprovider.Desired{
		Type: "TXT", Name: "a.example", Value: "v",
	})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != 81057 {
		t.Fatalf("want a typed APIError with the numeric code, got %v", err)
	}
	if !c.IsDuplicate(err) {
		t.Fatal("the classifier must work through the returned error")
	}
}

func TestListRecordsProjectsOntoTheProviderShape(t *testing.T) {
	c := serverFor(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"success":true,"result":[
			{"id":"r1","type":"CNAME","name":"a.example","content":"b.example","proxied":true},
			{"id":"r2","type":"TXT","name":"a.example","content":"\"v\"","proxied":false}]}`)
	})
	rows, err := c.ListRecordsAt(context.Background(), "t", "z", "a.example")
	if err != nil {
		t.Fatalf("ListRecordsAt: %v", err)
	}
	if len(rows) != 2 || rows[0].ID != "r1" || !rows[0].Proxied || rows[1].Value != `"v"` {
		t.Fatalf("unexpected projection: %#v", rows)
	}
}

// The interface is the contract; this is a compile-time assertion with a name,
// so a future adapter has an obvious place to copy.
func TestClientSatisfiesTheProviderInterface(t *testing.T) {
	var _ dnsprovider.Provider = Client{}
	if (Client{}).Name() != "cloudflare" {
		t.Fatal("provider name is stored on grant rows and must stay stable")
	}
}
