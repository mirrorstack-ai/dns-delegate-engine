package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
)

// edgeAPIBase is Cloudflare's v4 API root.
//
// Deliberately a second copy of the constant in internal/provider/cloudflare
// rather than an import of it. That package is the CUSTOMER-credential path: its
// every call takes the customer's delegated token as an argument. This file is
// the MIRRORSTACK-credential path. Keeping them from importing each other is
// what makes "the customer's token is never sent to our zone" a property you can
// check by reading the imports, and one shared URL string is a cheap price.
const edgeAPIBase = "https://api.cloudflare.com/client/v4"

// maxEdgeResponse bounds the upstream body this reader will hold in memory.
//
// Base is overridable and the response is untrusted input in the same sense
// internal/sealed's stored envelope is: it is read BEFORE anything about it has
// been established, so an endpoint that answers with an endless body must not be
// able to turn one pass of the loop into an allocation. A custom hostname
// listing filtered to ONE hostname is a few kilobytes; this is generous by
// orders of magnitude and still finite. Exceeding it is a refusal, not a silent
// truncation — a truncated JSON body that happened to parse would be an answer
// nobody sent.
const maxEdgeResponse = 1 << 20 // 1 MiB

// TokenSource yields MirrorStack's own Cloudflare zone credential for one call.
//
// A function rather than a string so the token can be re-read from Secrets
// Manager on a TTL and rotate underneath a running process — the same reason
// internal/shared/grantcrypto and internal/shared/cfoauth resolve their secrets
// at request time instead of at deploy time.
type TokenSource func(ctx context.Context) (string, error)

// StaticToken adapts a token already in hand. Intended for local runs and tests;
// production reads a rotating secret.
func StaticToken(token string) TokenSource {
	return func(context.Context) (string, error) { return token, nil }
}

// Edge reads record 7 — the serving proof — from Cloudflare for SaaS.
//
// 🔴 ZoneID IS MIRRORSTACK'S ZONE, AND Token IS MIRRORSTACK'S TOKEN.
//
// A custom hostname is an object in OUR zone, and reading it needs the SSL and
// Certificates permission on that zone. A customer's delegated grant carries
// zone.read and dns.write on the ONE zone they picked — their own — so it could
// not perform this read even if it were offered it. There is no field on this
// struct that a customer credential belongs in.
type Edge struct {
	// ZoneID is the MirrorStack SaaS zone holding the custom hostname. The org
	// lane and the app lane use different zones; the caller supplies the right
	// one for the lane.
	ZoneID string

	// Token resolves MirrorStack's zone credential. Nil is a configuration
	// error, not a wait — see ServingProof.
	Token TokenSource

	// Base overrides the API root. Tests point it at an httptest server.
	Base string

	// HTTPClient overrides the default client.
	HTTPClient *http.Client
}

var _ EdgeHostnames = Edge{}

// customHostname is Cloudflare's read shape, reduced to the two fields this
// service reads. Everything else in the object — the certificate's status, its
// pending validation records, the hostname id — is deliberately absent: this
// service is stateless and re-reads, so an id it does not decode is an id it
// cannot accidentally start storing.
type customHostname struct {
	Hostname              string `json:"hostname"`
	OwnershipVerification struct {
		Type  string `json:"type"`
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"ownership_verification"`
}

// ServingProof reads the _cf-custom-hostname TXT for one host.
//
// 🔴 RECORD 7 IS A SECOND, SEPARATE PROOF, READ BY THE EDGE AND NOT BY A
// CERTIFICATE AUTHORITY. MISSING IT PRODUCES A 526 WHILE THE CERTIFICATE STATUS
// READS ACTIVE — the hardest shape of this failure to diagnose, because DNS, the
// certificate and the console all read healthy.
//
// The two underscore records answer to different readers and fail at different
// times, and describing them with one word names the wrong blocker:
//
//	_acme-challenge       a certificate authority reads it, via the delegation.
//	                      Missing → a renewal fails months later, silently.
//	_cf-custom-hostname   the edge reads it, before it will route at all.
//	                      Missing → 526 now, with the certificate healthy.
//
// Their waits differ too. Cloudflare mints this proof when the custom hostname
// is CREATED, and mints the certificate challenge only after that host's routing
// record resolves. So on an early pass this is ready and the certificate record
// is not; on a later one both are.
//
// ready=false with a nil error is the normal early state: the custom hostname
// does not exist yet, or exists and Cloudflare has not asked for a proof. The
// only errors this method returns are a failed call and a missing credential. A
// record Cloudflare's own contract says it cannot return is refused one level
// up, by the free ServingProof in relay.go, so the refusal holds for every
// implementation of EdgeHostnames rather than for this one.
func (e Edge) ServingProof(ctx context.Context, host string) (dnsplan.Record, bool, error) {
	host = dnsplan.NormalizeName(host)
	if host == "" || len(host) > dnsplan.MaxDNSName {
		return dnsplan.Record{}, false, fmt.Errorf("relay: %q is not a DNS name", host)
	}
	if strings.TrimSpace(e.ZoneID) == "" {
		return dnsplan.Record{}, false, fmt.Errorf("relay: no MirrorStack zone configured for the serving proof")
	}
	// A missing token is a configuration fault reported as a fault. Reporting it
	// as not-ready would be indistinguishable from Cloudflare being slow — and
	// would stay indistinguishable forever, which is the shape of green signal
	// that costs the most to diagnose.
	if e.Token == nil {
		return dnsplan.Record{}, false, fmt.Errorf("relay: no MirrorStack zone credential configured for the serving proof")
	}
	token, err := e.Token(ctx)
	if err != nil {
		return dnsplan.Record{}, false, fmt.Errorf("relay: resolve the MirrorStack zone credential: %w", err)
	}
	if strings.TrimSpace(token) == "" {
		return dnsplan.Record{}, false, fmt.Errorf("relay: the MirrorStack zone credential is empty")
	}

	var env struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result []customHostname `json:"result"`
	}
	path := "/zones/" + url.PathEscape(strings.TrimSpace(e.ZoneID)) +
		"/custom_hostnames?" + url.Values{"hostname": {host}}.Encode()
	if err := e.get(ctx, token, path, &env); err != nil {
		return dnsplan.Record{}, false, err
	}
	if !env.Success {
		if len(env.Errors) > 0 {
			return dnsplan.Record{}, false, fmt.Errorf("relay: read custom hostname %q: %s (code %d)",
				host, env.Errors[0].Message, env.Errors[0].Code)
		}
		return dnsplan.Record{}, false, fmt.Errorf("relay: read custom hostname %q failed", host)
	}

	// The hostname query parameter is a FILTER, not a lookup, and Cloudflare has
	// treated it as a prefix match. Taking result[0] would bind this host's plan
	// to a neighbouring hostname's proof, so the exact match is made here.
	for _, found := range env.Result {
		if dnsplan.NormalizeName(found.Hostname) != host {
			continue
		}
		record, ready := servingProofRecord(found)
		return record, ready, nil
	}
	// No custom hostname for this host yet. Ordinary: it is created only after
	// the customer's own ownership TXT verifies in public DNS.
	return dnsplan.Record{}, false, nil
}

// servingProofRecord reads one custom hostname's ownership_verification and
// answers the one question this file is entitled to answer about it: has
// Cloudflare minted a proof yet.
//
// 🔴 CLOUDFLARE KEEPS THIS OBJECT PRESENT WITH EMPTY STRINGS once the proof is
// no longer required, and this was MEASURED on a live host rather than guessed
// at. An unguarded read of it produces a record with no name — which normalizes
// to the empty string and, at any publisher that does not re-check, lands as a
// write against the customer's zone APEX. The object being present proves
// nothing; only a non-empty name AND a non-empty value do. That is Cloudflare's
// wire shape, which is why the WAIT is decided here.
//
// Note also that ownership_verification is a TOP-LEVEL field, a sibling of ssl
// rather than a member of it. api-platform read the ssl object alone and went
// months without ever parsing this proof, which is the same shape of bug read
// from the other side.
//
// 🔴 WHETHER THE RECORD MAY BE PUBLISHED IS NOT DECIDED HERE. The type, the
// _cf-custom-hostname name beneath the host that was asked for, and the bound on
// the value are checked by the free ServingProof in relay.go, above this
// interface, so they hold for any edge implementation and not only for this one.
// Cloudflare's HTTP alternative, for instance, arrives in its own field
// (ownership_verification_http) and never as a type here — but it is relay.go
// that refuses a non-TXT, because an adapter cannot opt out of a rule it never
// sees.
func servingProofRecord(found customHostname) (dnsplan.Record, bool) {
	proof := found.OwnershipVerification
	if strings.TrimSpace(proof.Name) == "" || strings.TrimSpace(proof.Value) == "" {
		return dnsplan.Record{}, false
	}
	return relayedRecord(proof.Type, proof.Name, proof.Value), true
}

func (e Edge) base() string {
	if e.Base != "" {
		return strings.TrimRight(e.Base, "/")
	}
	return edgeAPIBase
}

func (e Edge) client() *http.Client {
	if e.HTTPClient != nil {
		return e.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// get performs the one read this file makes.
//
// There is no post, patch or delete here, and that is not an accident of what
// was needed: a custom hostname belongs to api-platform's lifecycle, and this
// service is the half that holds credentials. Giving it a write method against
// MirrorStack's own zone would put the two halves back together.
func (e Edge) get(ctx context.Context, token, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.base()+path, nil)
	if err != nil {
		return fmt.Errorf("relay: build custom hostname request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client().Do(req)
	if err != nil {
		return fmt.Errorf("relay: custom hostname request failed: %w", err)
	}
	defer resp.Body.Close()
	// One byte past the bound, so a body AT the limit is told apart from one
	// that was cut off at it.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxEdgeResponse+1))
	if err != nil {
		return fmt.Errorf("relay: read custom hostname response: %w", err)
	}
	if len(raw) > maxEdgeResponse {
		return fmt.Errorf("relay: custom hostname response is longer than %d bytes (status %d)",
			maxEdgeResponse, resp.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		// The status code is reported without the body. A response this service
		// could not parse is the last place to start echoing bytes returned by a
		// call that carried a credential.
		return fmt.Errorf("relay: decode custom hostname response (status %d): %w", resp.StatusCode, err)
	}
	return nil
}
