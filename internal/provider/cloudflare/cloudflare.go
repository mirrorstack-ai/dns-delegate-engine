// Package cloudflare adapts Cloudflare's DNS API to dnsprovider.Provider.
//
// Everything here is transport and vocabulary. The rules that bound what a
// delegated credential can do to a customer's zone live in internal/reconcile,
// above the interface this package implements.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsprovider"
)

// APIBase is Cloudflare's v4 API root.
const APIBase = "https://api.cloudflare.com/client/v4"

// Client implements dnsprovider.Provider against Cloudflare.
//
// Tokens are transient bearer credentials passed per call. They are never
// stored on the Client and never logged.
type Client struct {
	Base       string
	HTTPClient *http.Client
}

var _ dnsprovider.Provider = Client{}

// Name identifies this provider in logs and in stored grant rows.
func (c Client) Name() string { return "cloudflare" }

func (c Client) base() string {
	if c.Base != "" {
		return strings.TrimRight(c.Base, "/")
	}
	return APIBase
}

func (c Client) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// APIError carries Cloudflare's numeric error code so callers can act on a
// specific outcome without matching on message text.
type APIError struct {
	Method  string
	Code    int
	Message string
	Status  int
}

func (e *APIError) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("cloudflare: DNS %s failed: %s (code %d)", e.Method, e.Message, e.Code)
	}
	return fmt.Sprintf("cloudflare: DNS %s failed with status %d", e.Method, e.Status)
}

type apiErrorBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// record is Cloudflare's read shape.
type record struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}

// recordInput is the WRITABLE shape. Kept separate from record so read-only
// response fields such as id can never leak into a create/update payload —
// Cloudflare rejects them on some API versions.
type recordInput struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}

// FindZone walks the hostname's parents until an authorized zone answers. The
// most specific zone wins, which matters: picking a parent zone would let a
// write land beside records the plan never named.
func (c Client) FindZone(ctx context.Context, token, hostname string) (string, error) {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(hostname), "."), ".")
	for i := 0; i < len(labels)-1; i++ {
		name := strings.Join(labels[i:], ".")
		var env struct {
			Success bool           `json:"success"`
			Errors  []apiErrorBody `json:"errors"`
			Result  []struct {
				ID string `json:"id"`
			} `json:"result"`
		}
		path := "/zones?" + url.Values{"name": {name}}.Encode()
		if err := c.do(ctx, token, http.MethodGet, path, nil, &env); err != nil {
			return "", err
		}
		if len(env.Result) > 0 {
			return env.Result[0].ID, nil
		}
	}
	return "", fmt.Errorf("cloudflare: no authorized zone contains %q", hostname)
}

// ListRecordsAt returns every record at exactly one owner name.
func (c Client) ListRecordsAt(ctx context.Context, token, zoneID, name string) ([]dnsprovider.LiveRecord, error) {
	var env struct {
		Success bool           `json:"success"`
		Errors  []apiErrorBody `json:"errors"`
		Result  []record       `json:"result"`
	}
	path := "/zones/" + zoneID + "/dns_records?" + url.Values{"name": {name}}.Encode()
	if err := c.do(ctx, token, http.MethodGet, path, nil, &env); err != nil {
		return nil, err
	}
	out := make([]dnsprovider.LiveRecord, 0, len(env.Result))
	for _, row := range env.Result {
		out = append(out, dnsprovider.LiveRecord{
			ID: row.ID, Type: row.Type, Name: row.Name, Value: row.Content, Proxied: row.Proxied,
		})
	}
	return out, nil
}

// CreateRecord adds a record.
func (c Client) CreateRecord(ctx context.Context, token, zoneID string, want dnsprovider.Desired) (string, error) {
	var env struct {
		Success bool           `json:"success"`
		Errors  []apiErrorBody `json:"errors"`
		Result  record         `json:"result"`
	}
	if err := c.do(ctx, token, http.MethodPost, "/zones/"+zoneID+"/dns_records", input(want), &env); err != nil {
		return "", err
	}
	if env.Result.ID == "" {
		return "", fmt.Errorf("cloudflare: create DNS record returned no id")
	}
	return env.Result.ID, nil
}

// PatchRecord partially updates one record.
//
// PATCH, not PUT, so fields we do not own — the customer's comment and tags on
// their own zone — survive the write.
func (c Client) PatchRecord(ctx context.Context, token, zoneID, id string, want dnsprovider.Desired) error {
	var env struct {
		Success bool           `json:"success"`
		Errors  []apiErrorBody `json:"errors"`
	}
	return c.do(ctx, token, http.MethodPatch, "/zones/"+zoneID+"/dns_records/"+id, input(want), &env)
}

// SameValue compares a live value with a desired one.
func (c Client) SameValue(recordType, live, desired string) bool {
	if strings.EqualFold(strings.TrimSpace(recordType), "CNAME") {
		return strings.EqualFold(strings.TrimSuffix(live, "."), strings.TrimSuffix(desired, "."))
	}
	// Cloudflare returns TXT content quoted on some API paths. Compare the
	// unquoted payloads so a quoted read is not mistaken for "missing" — a
	// quote-sensitive comparison reads every already-correct record as absent
	// and rewrites it on every pass.
	return trimTXTQuotes(live) == trimTXTQuotes(desired)
}

// IsDuplicate reports Cloudflare's "this record already exists" family. 81057
// and 81058 prove only that something raced the create, not that the existing
// row is the desired one.
func (c Client) IsDuplicate(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && (apiErr.Code == 81057 || apiErr.Code == 81058)
}

// IsAmbiguous distinguishes a definitive rejection from a response that may have
// been produced after the mutation committed.
//
// 🔴 IT FAILS TOWARD AMBIGUOUS. Transport, response-read and decode failures do
// not prove whether Cloudflare applied the request, so anything that is not a
// decoded API error is ambiguous by default. Claiming certainty here would let
// the reconciler treat a possibly-applied write as definitively failed.
func (c Client) IsAmbiguous(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return true
	}
	return apiErr.Status == http.StatusRequestTimeout ||
		apiErr.Status == http.StatusTooManyRequests ||
		apiErr.Status >= http.StatusInternalServerError
}

func input(want dnsprovider.Desired) recordInput {
	content := want.Value
	if strings.EqualFold(strings.TrimSpace(want.Type), "TXT") {
		content = quoteTXTValue(content)
	}
	return recordInput{Type: want.Type, Name: want.Name, Content: content, Proxied: want.Proxied, TTL: 1}
}

// quoteTXTValue writes a TXT value in DNS presentation form, which is the form
// Cloudflare's own dashboard states a TXT value takes.
//
// MEASURED 2026-08-24 on a live zone, both ways, because publishing a wrong DCV
// value fails silently and costs a certificate:
//
//	POST content: hello-value    -> stored 'hello-value'   -> served "hello-value"
//	POST content: "hello-value"  -> stored '"hello-value"' -> served "hello-value"
//
// Identical on the wire: Cloudflare treats the quotes as the presentation
// wrapper, so the CA, the resolver and the customer all see the same value
// either way. What changes is the API round-trip form, which is why this is safe
// only alongside SameValue comparing through trimTXTQuotes.
//
// Idempotent on an ALREADY-quoted value, which matters because the value can
// arrive from three places that disagree: Cloudflare's own API read-back, a
// provider's validation record, and a customer who typed the quotes by hand.
// Double-wrapping would publish a value containing literal quote characters.
func quoteTXTValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return v
	}
	return `"` + trimTXTQuotes(v) + `"`
}

// trimTXTQuotes strips one layer of surrounding double quotes. Inner quotes are
// left alone — only the DNS presentation wrapper goes.
func trimTXTQuotes(v string) string {
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		return v[1 : len(v)-1]
	}
	return v
}

func (c Client) do(ctx context.Context, token, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("cloudflare: encode DNS request: %w", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base()+path, reader)
	if err != nil {
		return fmt.Errorf("cloudflare: build DNS request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: DNS request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("cloudflare: read DNS response: %w", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("cloudflare: decode DNS response: %w", err)
	}
	var status struct {
		Success bool           `json:"success"`
		Errors  []apiErrorBody `json:"errors"`
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		return fmt.Errorf("cloudflare: decode DNS status: %w", err)
	}
	if status.Success {
		return nil
	}
	if len(status.Errors) > 0 {
		return &APIError{Method: method, Code: status.Errors[0].Code, Message: status.Errors[0].Message, Status: resp.StatusCode}
	}
	return &APIError{Method: method, Status: resp.StatusCode}
}
