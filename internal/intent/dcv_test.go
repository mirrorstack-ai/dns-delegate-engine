package intent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/relay"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/cfedge"
)

// The tests below close the oldest question in this repository: record 6's
// middle label was a hand-set environment variable nobody had ever checked
// against Cloudflare. It is now read, per zone, and these pin which value wins.
//
// 🔴 NO TEST HERE REACHES A CLOUDFLARE ACCOUNT. The delegation endpoint is an
// httptest.Server.

// cloudflareUUID is what the fake Cloudflare returns, deliberately unequal to
// testDCVUUID: a test where the two agreed would pass with the override missing.
const cloudflareUUID = "b0dd15c0ffee0042"

// delegationServer wires a real relay.NewDCV at an httptest server answering
// every zone with uuid. The whole path is under test — HTTP, envelope, label
// bound — rather than a fake standing in for it.
func delegationServer(t *testing.T, uuid string) relay.DCVDelegations {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/dcv_delegation/uuid") {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, fmt.Sprintf(`{"success":true,"result":{"uuid":%q}}`, uuid))
	}))
	t.Cleanup(srv.Close)
	d := relay.NewDCV(
		relay.EdgeZones{OrgPlatform: "org-zone-id", App: "app-zone-id"},
		cfedge.Static("ms-zone-token"),
	)
	d.Base, d.HTTPClient = srv.URL, srv.Client()
	return d
}

// failingDelegation is a Cloudflare this deployment cannot reach.
type failingDelegation struct{ err error }

func (f failingDelegation) DelegationUUID(context.Context, lane.Lane) (string, bool, error) {
	return "", false, f.err
}

// captureLogs redirects the default logger for one test and returns what was
// written. The disagreement is only useful if somebody can SEE it.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

// dcvTargets returns the value of every record 6 in a registration's records.
func dcvTargets(records []RecordView) []string {
	var out []string
	for _, record := range records {
		if strings.HasPrefix(record.Name, "_acme-challenge.") {
			out = append(out, record.Value)
		}
	}
	return out
}

// 🔴 THE FETCHED IDENTIFIER WINS. A hand-set value silently overriding the
// provider's is how record 6 came to point at a name nobody had verified, and
// record 6 is published on the first pass and never republished.
func TestTheFetchedDelegationIdentifierBeatsTheConfiguredOne(t *testing.T) {
	h := newHarness(t)
	h.svc.Delegation = delegationServer(t, cloudflareUUID)

	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	targets := dcvTargets(out.Records)
	if len(targets) != 4 {
		t.Fatalf("lane 1 derives four certificate pointers, got %v", targets)
	}
	for _, target := range targets {
		if !strings.Contains(target, "."+cloudflareUUID+".dcv.cloudflare.com") {
			t.Fatalf("record 6 must carry the identifier Cloudflare named: %q", target)
		}
		if strings.Contains(target, testDCVUUID) {
			t.Fatalf("the configured identifier must lose: %q", target)
		}
	}

	// And a reader outside the process can tell which one won.
	for _, l := range h.svc.Capabilities(t.Context()).Lanes {
		if l.DCVDelegationSource != DCVFromCloudflare {
			t.Fatalf("lane %s must report a verified identifier, got %q", l.Lane, l.DCVDelegationSource)
		}
		if l.DCVDelegationUUID != cloudflareUUID {
			t.Fatalf("lane %s must publish the identifier in force, got %q", l.Lane, l.DCVDelegationUUID)
		}
	}
	// The top-level field stays the CONFIGURED one, so the pair reads as what
	// the environment says against what is actually in force.
	if caps := h.svc.Capabilities(t.Context()); caps.DCVDelegationUUID != testDCVUUID {
		t.Fatalf("the top-level identifier is the configured fallback, got %q", caps.DCVDelegationUUID)
	}
}

// A disagreement that is merely resolved correctly still leaves the environment
// wrong, and the next thing derived from it wrong too.
func TestADisagreeingConfiguredIdentifierIsLoggedLoudly(t *testing.T) {
	h := newHarness(t)
	h.svc.Delegation = delegationServer(t, cloudflareUUID)
	logs := captureLogs(t)

	h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)

	written := logs.String()
	if !strings.Contains(written, "level=ERROR") {
		t.Fatalf("a disagreement must be logged at ERROR, got: %s", written)
	}
	if !strings.Contains(written, testDCVUUID) || !strings.Contains(written, cloudflareUUID) {
		t.Fatalf("the log line must name both values, got: %s", written)
	}

	// Agreement is silent: a line on every pass would bury the one that matters.
	agreeing := newHarness(t)
	agreeing.svc.Delegation = delegationServer(t, testDCVUUID)
	quiet := captureLogs(t)
	agreeing.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	if strings.Contains(quiet.String(), "level=ERROR") {
		t.Fatalf("an agreeing identifier must log nothing, got: %s", quiet.String())
	}
}

// 🔴 AN UNREACHABLE CLOUDFLARE IS A FALLBACK, NOT A FAILED PASS. Record 6 is
// derivable with no Cloudflare credential at all; making a read failure fatal
// would stop a lane publishing everything else it can derive.
func TestAnUnreachableCloudflareFallsBackToTheConfiguredIdentifier(t *testing.T) {
	h := newHarness(t)
	h.svc.Delegation = failingDelegation{err: errors.New("cloudflare 502")}
	logs := captureLogs(t)

	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	targets := dcvTargets(out.Records)
	if len(targets) != 4 {
		t.Fatalf("the pointers must still be derived, got %v", targets)
	}
	for _, target := range targets {
		if !strings.Contains(target, "."+testDCVUUID+".dcv.cloudflare.com") {
			t.Fatalf("the configured identifier must stand: %q", target)
		}
	}
	if !strings.Contains(logs.String(), "cloudflare 502") {
		t.Fatalf("a failed read must be reported, got: %s", logs.String())
	}
	for _, l := range h.svc.Capabilities(t.Context()).Lanes {
		if l.DCVDelegationSource != DCVFromConfig || l.DCVDelegationUUID != testDCVUUID {
			t.Fatalf("lane %s must report a hand-set identifier, got %q / %q",
				l.Lane, l.DCVDelegationSource, l.DCVDelegationUUID)
		}
	}
}

// An answer Cloudflare's own contract says it cannot give is refused, and the
// refusal lands as the same fallback: a record 6 aimed at a label with a dot in
// it would point at a domain Cloudflare never named.
func TestAnImpossibleDelegationIdentifierFallsBackRatherThanBeingPublished(t *testing.T) {
	h := newHarness(t)
	h.svc.Delegation = delegationServer(t, "abc.example.com")

	out := h.register(t, lane.AppDomain, testApp, appHostname)
	for _, target := range dcvTargets(out.Records) {
		if !strings.Contains(target, "."+testDCVUUID+".dcv.cloudflare.com") {
			t.Fatalf("a refused identifier must not reach a customer's zone: %q", target)
		}
	}
}

// 🔴 THE DEPLOYMENT THAT WAS NEVER TOLD ABOUT CLOUDFLARE BEHAVES EXACTLY AS
// BEFORE. The read is an override, not a requirement.
func TestAnUnwiredDeploymentDerivesFromTheConfiguredIdentifier(t *testing.T) {
	h := newHarness(t)
	if h.svc.Delegation != nil {
		t.Fatal("the fixture must be unwired, as a deployment holding no credential is")
	}
	out := h.register(t, lane.AppDomain, testApp, appHostname)
	want := appHostname + "." + testDCVUUID + ".dcv.cloudflare.com"
	if targets := dcvTargets(out.Records); len(targets) != 1 || targets[0] != want {
		t.Fatalf("want the configured pointer %q, got %v", want, targets)
	}
	for _, l := range h.svc.Capabilities(t.Context()).Lanes {
		if l.DCVDelegationSource != DCVFromConfig {
			t.Fatalf("lane %s must report the configured source, got %q", l.Lane, l.DCVDelegationSource)
		}
	}

	// And with nothing configured either, the lane reports no identifier at all
	// rather than inventing one — the state Capabilities.ConfigError names.
	h.svc.Derive.DCVDelegationUUID = ""
	caps := h.svc.Capabilities(t.Context())
	if caps.ConfigError == "" {
		t.Fatal("a deployment that can derive no certificate pointer must say so")
	}
	for _, l := range caps.Lanes {
		if l.DCVDelegationSource != "" || l.DCVDelegationUUID != "" {
			t.Fatalf("lane %s must claim no identifier, got %q / %q",
				l.Lane, l.DCVDelegationSource, l.DCVDelegationUUID)
		}
	}
}

// The read replaces the configured value even when there was none: a deployment
// that sets no variable at all is CONFIGURED, and must not report otherwise.
func TestAFetchedIdentifierAloneIsAValidConfiguration(t *testing.T) {
	h := newHarness(t)
	h.svc.Derive.DCVDelegationUUID = ""
	h.svc.Delegation = delegationServer(t, cloudflareUUID)

	caps := h.svc.Capabilities(t.Context())
	if caps.ConfigError != "" {
		t.Fatalf("an identifier read from Cloudflare is a configured one: %s", caps.ConfigError)
	}
	out := h.register(t, lane.AppDomain, testApp, appHostname)
	want := appHostname + "." + cloudflareUUID + ".dcv.cloudflare.com"
	if targets := dcvTargets(out.Records); len(targets) != 1 || targets[0] != want {
		t.Fatalf("want %q, got %v", want, targets)
	}
}

// 🔴 A CHANGE OF DELEGATION SOURCE MUST READ AS `plan_changed`, NEVER
// `plan_invalid`.
//
// Record 6's value is inside the digest the customer authorized against, so
// deriving the identifier from Cloudflare after an earlier pass used the
// configured one genuinely changes the plan. The caller's contract says
// plan_invalid means "this is a bug and retrying cannot help", and a caller that
// believes it may abandon the domain — over a configuration that is now MORE
// correct than it was.
func TestAChangeOfDelegationSourceAsksForReauthorizationRatherThanReportingABug(t *testing.T) {
	h := newHarness(t)
	h.svc.Derive.DCVDelegationUUID = "configured0000ab"
	h.svc.Derive.DCVDelegationUUIDApp = "configured0000ab"

	out := h.register(t, lane.OrgPlatformDomain, testOrg, platformDomain)
	h.publishProof(t, out)
	staleDigest := out.Digest

	// Cloudflare now answers, and disagrees with the environment.
	h.svc.Delegation = delegationServer(t, "fromcloudflare00")

	state := h.authorize(t, out)
	_, err := h.svc.Complete(t.Context(), CompleteRequest{
		State: state, Code: "code", CodeVerifier: "chal-verifier", ExpectDigest: staleDigest,
	})
	if err == nil {
		t.Fatal("a digest taken under the old identifier must not publish")
	}
	if !errors.Is(err, dnsplan.ErrPlanChanged) {
		t.Fatalf("want ErrPlanChanged so the caller re-renders; got %v", err)
	}
	if errors.Is(err, dnsplan.ErrPlanInvalid) && !errors.Is(err, dnsplan.ErrPlanChanged) {
		t.Fatal("plan_invalid tells the caller this cannot be retried, which is wrong here")
	}
}
