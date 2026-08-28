package relay

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/cfedge"
)

// DCVDelegations is Cloudflare, read for the uuid half of record 6's value: the
// per-zone identifier a delegated certificate validation points at
// (docs/DESIGN.md §6).
//
// 🔴 THE IDENTIFIER IS PER ZONE, SO IT IS PER LANE. MirrorStack's org zone and
// its app/SaaS zone are separate zones with separate identifiers, so one value
// covering all three lanes is right for at most one of them — the same reason
// EdgeZones exists, and the lane selects here for the same reason it selects
// there.
//
// ok=false with a nil error means "this deployment cannot ask", which every
// caller answers by falling back to its configured value. Record 6 is derivable
// with no Cloudflare credential at all and must stay that way.
type DCVDelegations interface {
	DelegationUUID(ctx context.Context, l lane.Lane) (uuid string, ok bool, err error)
}

// DelegationUUID reads the delegation identifier for one lane through d, and
// bounds what comes back. A nil d reports none, as a nil CertificateAuthority
// reports no records.
//
// 🔴 THE BOUND IS ABOVE THE INTERFACE, as every relayed bound in this package
// is: the identifier becomes ONE LABEL inside a name published in a customer's
// zone, so an answer carrying a dot would aim record 6 at a domain Cloudflare
// never named.
func DelegationUUID(ctx context.Context, d DCVDelegations, l lane.Lane) (string, bool, error) {
	if d == nil {
		return "", false, nil
	}
	uuid, ok, err := d.DelegationUUID(ctx, l)
	if err != nil || !ok {
		return "", false, err
	}
	label, err := lane.ValidateSlug(uuid)
	if err != nil {
		return "", false, fmt.Errorf("%w: the DCV delegation identifier for lane %q is not one DNS label: %w",
			ErrUnexpectedRecord, l, err)
	}
	return label, true, nil
}

// delegationTTL and delegationFailureTTL cache one zone's answer.
//
// The identifier is fixed for the life of a zone, so the positive half is about
// call volume rather than freshness; the negative half is the one that matters,
// bounding how often an unreadable Cloudflare is asked again. Same pair as
// cfedge.Loader, for the same reason.
const (
	delegationTTL        = 5 * time.Minute
	delegationFailureTTL = 30 * time.Second
)

// DCV reads Cloudflare's DCV delegation identifier for MirrorStack's own zones,
// with MirrorStack's own token.
//
//	GET /zones/{zone_id}/dcv_delegation/uuid
//
// 🔴 IT EXISTS TO RETIRE A HAND-SET VALUE. CF_ORG_DCV_DELEGATION_UUID was
// somebody's reading of a dashboard applied to both zones, and record 6 is
// published on the first pass and never republished — so a wrong label is a
// certificate that never issues, with the record looking right in the customer's
// zone indefinitely (derive.DCVTarget).
//
// 🔴 Zones AND Token ARE MIRRORSTACK'S, exactly as on Edge: this endpoint
// describes OUR zone, and a customer's delegated grant could not read it if it
// were offered it. Token is a cfedge.Source, so the customer's plain-string
// credential does not fit in any field on this struct.
type DCV struct {
	// Zones is the per-lane zone table Edge reads custom hostnames from: the
	// identifier belongs to the zone whose hostnames it validates.
	Zones EdgeZones

	// Token resolves MirrorStack's own Cloudflare credential.
	Token cfedge.Source

	// Base overrides the API root. Tests point it at an httptest server.
	Base string

	// HTTPClient overrides the default client.
	HTTPClient *http.Client

	mu      sync.Mutex
	entries map[string]dcvEntry
}

var _ DCVDelegations = (*DCV)(nil)

// NewDCV builds a reader over the same zone table and credential as the Edge
// reader — one Cloudflare account, one token, two reads.
func NewDCV(zones EdgeZones, token cfedge.Source) *DCV {
	return &DCV{Zones: zones, Token: token}
}

// dcvEntry is one zone's remembered answer. The error is remembered rather than
// recomputed so a refusal keeps its own words for the negative window.
type dcvEntry struct {
	uuid string
	err  error
	at   time.Time
}

// DelegationUUID reads the identifier for l's zone, at most once per TTL.
//
// A lane with no zone reports none rather than failing: unlike the serving
// proof, record 6 is derivable without ever reaching Cloudflare, so an
// unconfigured lane falls back instead of taking a pass down.
func (d *DCV) DelegationUUID(ctx context.Context, l lane.Lane) (string, bool, error) {
	zoneID, err := d.Zones.ForLane(l)
	if err != nil {
		return "", false, nil
	}
	token, held, err := edgeCredential(ctx, d.Token)
	if err != nil {
		return "", false, err
	}
	if !held {
		return "", false, nil
	}

	// The lock is held across the call, as cfedge.Loader holds its own: two
	// passes starting together make one request rather than two.
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if entry, ok := d.entries[zoneID]; ok {
		switch {
		case entry.err == nil && now.Sub(entry.at) < delegationTTL:
			return entry.uuid, true, nil
		case entry.err != nil && now.Sub(entry.at) < delegationFailureTTL:
			return "", false, entry.err
		}
	}
	uuid, err := d.read(ctx, token, zoneID)
	if d.entries == nil {
		d.entries = make(map[string]dcvEntry, 2)
	}
	d.entries[zoneID] = dcvEntry{uuid: uuid, err: err, at: now}
	if err != nil {
		return "", false, err
	}
	return uuid, true, nil
}

// read makes the one call. The endpoint answers with a uuid and nothing else —
// no target, no hostname — which is why it settles what the middle label is and
// settles nothing about the form around it; see derive.DCVTarget.
func (d *DCV) read(ctx context.Context, token cfedge.Token, zoneID string) (string, error) {
	var env struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result struct {
			UUID string `json:"uuid"`
		} `json:"result"`
	}
	path := "/zones/" + url.PathEscape(zoneID) + "/dcv_delegation/uuid"
	if err := edgeAPIFor(d.Base, d.HTTPClient, "dcv delegation").get(ctx, token, path, &env); err != nil {
		return "", err
	}
	if !env.Success {
		if len(env.Errors) > 0 {
			return "", fmt.Errorf("relay: read the DCV delegation identifier for zone %s: %s (code %d)",
				zoneID, env.Errors[0].Message, env.Errors[0].Code)
		}
		return "", fmt.Errorf("relay: read the DCV delegation identifier for zone %s failed", zoneID)
	}
	// An empty identifier is refused rather than reported as absent: Cloudflare's
	// own contract says this zone has one, so a blank is a claim it cannot make,
	// and a caller that read it as "not configured" would fall back silently.
	uuid := strings.TrimSpace(env.Result.UUID)
	if uuid == "" {
		return "", fmt.Errorf("%w: zone %s reported no DCV delegation identifier", ErrUnexpectedRecord, zoneID)
	}
	return uuid, nil
}
