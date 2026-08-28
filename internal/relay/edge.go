package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/cfedge"
)

// edgeAPIBase is Cloudflare's v4 API root. Deliberately a second copy of the
// constant in internal/provider/cloudflare rather than an import: that package is
// the CUSTOMER-credential path and this file is the MIRRORSTACK-credential path,
// so keeping them from importing each other makes "the customer's token is never
// sent to our zone" a property you can check by reading the imports.
const edgeAPIBase = "https://api.cloudflare.com/client/v4"

// maxEdgeResponse bounds the upstream body a read will hold in memory. Base
// is overridable and the response is untrusted input read BEFORE anything about it
// has been established, so an endpoint that answers with an endless body must not
// turn one pass of the loop into an allocation. Exceeding it is a refusal, not a
// silent truncation — a truncated JSON body that happened to parse would be an
// answer nobody sent.
const maxEdgeResponse = 1 << 20 // 1 MiB

// EdgeZones names the MirrorStack zone each lane's custom hostnames live in.
//
// 🔴 ONE ZONE ID CANNOT SERVE THREE LANES. MirrorStack's org zone and its
// app/SaaS zone are separate, and a lane's routing target says which — lane 1 is
// CNAMEd into the org zone and lanes 2 and 3 into the app zone (docs/DESIGN.md
// §6, records 2 through 4). One id against all three reads two lanes out of a
// zone holding none of their custom hostnames and finds nothing, which is
// spelled exactly like the ordinary "Cloudflare has not minted it yet".
//
// Both ids are reported through IntentCapabilities, per lane, so which zone a
// deployment reads for which lane is answerable from outside it.
type EdgeZones struct {
	// OrgPlatform holds the account/api/apps/cdn custom hostnames: lane 1.
	OrgPlatform string

	// App holds every app hostname: lanes 2 and 3.
	App string
}

// Configured reports whether any zone is named at all.
func (z EdgeZones) Configured() bool {
	return strings.TrimSpace(z.OrgPlatform) != "" || strings.TrimSpace(z.App) != ""
}

// ForLane picks the zone this lane's serving proof is read from.
//
// 🔴 THE LANE SELECTS, NEVER THE HOSTNAME. A hostname is the customer's string
// and it carries no zone in it: inferring one would mean matching a customer's
// name against a table and picking a MirrorStack zone from the result, so a
// customer could choose which of our zones we authenticate against. The lane is
// fixed by the entry point (internal/intent) and is inside the ownership HMAC.
//
// An unrecognised lane is refused rather than defaulted, on lane.Parse's rule: a
// defaulted lane picks a zone the customer never consented to anything in.
func (z EdgeZones) ForLane(l lane.Lane) (string, error) {
	var zoneID string
	switch l {
	case lane.OrgPlatformDomain:
		zoneID = strings.TrimSpace(z.OrgPlatform)
	case lane.OrgAppDomain, lane.AppDomain:
		zoneID = strings.TrimSpace(z.App)
	default:
		return "", fmt.Errorf("relay: no MirrorStack zone is defined for lane %q", l)
	}
	if zoneID == "" {
		return "", fmt.Errorf("relay: no MirrorStack zone is configured for lane %q, so its serving proof cannot be read", l)
	}
	return zoneID, nil
}

// Edge reads record 7 — the serving proof — from Cloudflare for SaaS.
//
// 🔴 Zones ARE MIRRORSTACK'S ZONES, AND Token IS MIRRORSTACK'S TOKEN. Reading a
// custom hostname in OUR zone needs the SSL and Certificates permission there,
// which a customer's delegated grant — zone.read and dns.write on the one zone
// they picked — could not perform even if it were offered it. Token is a
// cfedge.Source, whose Token is a defined type: the customer's plain-string
// credential does not fit in any field on this struct.
type Edge struct {
	// Zones is the per-lane zone table. See EdgeZones.
	Zones EdgeZones

	// Token resolves MirrorStack's own Cloudflare credential.
	Token cfedge.Source

	// Base overrides the API root. Tests point it at an httptest server.
	Base string

	// HTTPClient overrides the default client.
	HTTPClient *http.Client
}

var (
	_ EdgeHostnames    = Edge{}
	_ EdgeZoneReporter = Edge{}
)

// EdgeZones reports the zone table this reader was configured with, so
// IntentCapabilities publishes what is ACTUALLY read rather than a second copy
// of the same environment variables. See EdgeZoneReporter in relay.go.
func (e Edge) EdgeZones() EdgeZones { return e.Zones }

// customHostname is Cloudflare's read shape, reduced to the two fields this
// service reads. The certificate's status, its pending validation records and the
// hostname id are deliberately absent: this service is stateless and re-reads, so
// an id it does not decode is an id it cannot accidentally start storing.
type customHostname struct {
	Hostname              string `json:"hostname"`
	OwnershipVerification struct {
		Type  string `json:"type"`
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"ownership_verification"`
}

// ServingProof reads the _cf-custom-hostname TXT for one host on one lane.
//
// 🔴 RECORD 7 IS A SECOND, SEPARATE PROOF, READ BY THE EDGE AND NOT BY A
// CERTIFICATE AUTHORITY. MISSING IT PRODUCES A 526 WHILE THE CERTIFICATE STATUS
// READS ACTIVE — the hardest shape of this failure to diagnose, because DNS, the
// certificate and the console all read healthy. _acme-challenge is read by a
// certificate authority instead and fails the other way: missing, a renewal fails
// months later, silently (docs/RECORDS.md, "serving"). The waits differ too —
// Cloudflare mints this proof when the custom hostname is CREATED, and mints the
// certificate challenge only after that host's routing record resolves, so on an
// early pass this is ready and the certificate record is not.
//
// ready=false with a nil error is the normal early state: the custom hostname
// does not exist yet, exists with no proof asked for, or this deployment holds no
// edge credential (cfedge.ErrNotConfigured). The only errors are a failed call, a
// credential that could not be READ, and a lane with no zone. A record
// Cloudflare's own contract says it cannot return is refused one level up, by the
// free ServingProof in relay.go, so that refusal holds for every implementation
// of EdgeHostnames rather than for this one.
func (e Edge) ServingProof(ctx context.Context, l lane.Lane, host string) (dnsplan.Record, bool, error) {
	host = dnsplan.NormalizeName(host)
	if host == "" || len(host) > dnsplan.MaxDNSName {
		return dnsplan.Record{}, false, fmt.Errorf("relay: %q is not a DNS name", host)
	}
	zoneID, err := e.Zones.ForLane(l)
	if err != nil {
		return dnsplan.Record{}, false, err
	}
	token, held, err := edgeCredential(ctx, e.Token)
	if err != nil {
		return dnsplan.Record{}, false, err
	}
	if !held {
		// Nothing to read WITH is the same answer to the customer as nothing to
		// read: the proof is not available yet. cfedge logs which it was.
		return dnsplan.Record{}, false, nil
	}

	var env struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result []customHostname `json:"result"`
	}
	path := "/zones/" + url.PathEscape(zoneID) +
		"/custom_hostnames?" + url.Values{"hostname": {host}}.Encode()
	if err := edgeAPIFor(e.Base, e.HTTPClient, "custom hostname").get(ctx, token, path, &env); err != nil {
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
// ownership_verification is also a TOP-LEVEL field, a sibling of ssl rather than a
// member of it: api-platform read the ssl object alone and went months without
// ever parsing this proof, the same shape of bug from the other side.
//
// Whether the record may be PUBLISHED is not decided here: the type, the
// _cf-custom-hostname name beneath the host asked for, and the bound on the value
// are checked by the free ServingProof in relay.go. Cloudflare's HTTP alternative
// arrives in its own field (ownership_verification_http) and never as a type here,
// but it is still relay.go that refuses a non-TXT.
func servingProofRecord(found customHostname) (dnsplan.Record, bool) {
	proof := found.OwnershipVerification
	if strings.TrimSpace(proof.Name) == "" || strings.TrimSpace(proof.Value) == "" {
		return dnsplan.Record{}, false
	}
	return relayedRecord(proof.Type, proof.Name, proof.Value), true
}

// edgeCredential resolves MirrorStack's own Cloudflare token for one read.
//
// 🔴 held=false WITH A NIL ERROR IS "THIS DEPLOYMENT HOLDS NONE", NOT A FAULT.
// Every caller answers it with an absent result — a serving proof that is not
// available yet, a delegation identifier that falls back to the configured one —
// while a token that could not be READ stays an error. Collapsing the two would
// make a deployment nobody finished look like one whose IAM policy is wrong; see
// cfedge.ErrNotConfigured.
//
// A nil source is neither: the binary passes a nil INTERFACE when it has no
// credential, so a reader holding a nil Source is a wiring mistake.
func edgeCredential(ctx context.Context, src cfedge.Source) (cfedge.Token, bool, error) {
	if src == nil {
		return "", false, fmt.Errorf("relay: no MirrorStack zone credential is wired")
	}
	token, err := src(ctx)
	switch {
	case errors.Is(err, cfedge.ErrNotConfigured):
		return "", false, nil
	case err != nil:
		return "", false, fmt.Errorf("relay: resolve the MirrorStack zone credential: %w", err)
	}
	// A source that returns a blank token and NO error is a fault reported as a
	// fault. Reported as absent it would be indistinguishable from Cloudflare
	// being slow — and would stay indistinguishable forever.
	if strings.TrimSpace(string(token)) == "" {
		return "", false, fmt.Errorf("relay: the MirrorStack zone credential is empty")
	}
	return token, true, nil
}

// edgeAPI is the read half of Cloudflare's API under MirrorStack's own token.
// Shared by both readers in this package so the credential reaches the wire in
// exactly one place; `what` names the read in every error it can produce.
type edgeAPI struct {
	base   string
	client *http.Client
	what   string
}

func edgeAPIFor(base string, client *http.Client, what string) edgeAPI {
	if base == "" {
		base = edgeAPIBase
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return edgeAPI{base: strings.TrimRight(base, "/"), client: client, what: what}
}

// get performs the one kind of call this package makes. There is no post, patch
// or delete here, and that is not an accident of what was needed: a custom
// hostname belongs to api-platform's lifecycle, and giving the half that holds
// credentials a write method against MirrorStack's own zone would put the two
// halves back together.
//
// This is also the ONLY place the token is converted back to a string. Everywhere
// else it is a cfedge.Token, which redacts itself under every fmt verb.
func (a edgeAPI) get(ctx context.Context, token cfedge.Token, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+path, nil)
	if err != nil {
		return fmt.Errorf("relay: build %s request: %w", a.what, err)
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("relay: %s request failed: %w", a.what, err)
	}
	defer resp.Body.Close()
	// One byte past the bound, so a body AT the limit is told apart from one
	// that was cut off at it.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxEdgeResponse+1))
	if err != nil {
		return fmt.Errorf("relay: read %s response: %w", a.what, err)
	}
	if len(raw) > maxEdgeResponse {
		return fmt.Errorf("relay: %s response is longer than %d bytes (status %d)",
			a.what, maxEdgeResponse, resp.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		// The status code is reported without the body. A response this service
		// could not parse is the last place to start echoing bytes returned by a
		// call that carried a credential.
		return fmt.Errorf("relay: decode %s response (status %d): %w", a.what, resp.StatusCode, err)
	}
	return nil
}
