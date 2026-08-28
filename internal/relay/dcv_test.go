package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/cfedge"
)

// 🔴 NO TEST IN THIS FILE REACHES A CLOUDFLARE ACCOUNT. The delegation endpoint
// is an httptest.Server, which is what makes "the identifier we publish is the
// one Cloudflare named" checkable by somebody who does not work here.

func dcvFor(t *testing.T, h http.HandlerFunc) *DCV {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	d := NewDCV(testZones, cfedge.Static("ms-zone-token"))
	d.Base, d.HTTPClient = srv.URL, srv.Client()
	return d
}

func dcvBody(uuid string) string {
	return fmt.Sprintf(`{"success":true,"errors":[],"result":{"uuid":%q}}`, uuid)
}

// 🔴 THE IDENTIFIER IS PER ZONE, SO THE LANE MUST SELECT ONE. Lanes 2 and 3
// share the app zone and lane 1 does not, so a reader that asked one zone for
// all three would publish the org zone's identifier under every app hostname —
// a record 6 that resolves, and a certificate that never issues.
func TestTheDelegationIdentifierIsReadPerZone(t *testing.T) {
	var paths []string
	d := dcvFor(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		uuid := "orgzoneident"
		if strings.Contains(r.URL.Path, testZones.App) {
			uuid = "appzoneident"
		}
		_, _ = io.WriteString(w, dcvBody(uuid))
	})
	want := map[lane.Lane]string{
		lane.OrgPlatformDomain: "orgzoneident",
		lane.OrgAppDomain:      "appzoneident",
		lane.AppDomain:         "appzoneident",
	}
	for l, uuid := range want {
		got, ok, err := DelegationUUID(context.Background(), d, l)
		if err != nil || !ok {
			t.Fatalf("%s: DelegationUUID = %q, ok=%v, err=%v", l, got, ok, err)
		}
		if got != uuid {
			t.Fatalf("%s: want the identifier of its own zone %q, got %q", l, uuid, got)
		}
	}
	// One read per ZONE, not per lane: the answer is fixed for the life of a
	// zone, and the two app lanes read the same one.
	if len(paths) != 2 {
		t.Fatalf("want one read per zone, got %d: %v", len(paths), paths)
	}
	for _, path := range paths {
		if !strings.HasSuffix(path, "/dcv_delegation/uuid") {
			t.Fatalf("the read must be the delegation endpoint, got %q", path)
		}
	}
}

// The credential rides the Authorization header and appears nowhere a log or a
// proxy access line would keep it, as it does for the serving proof.
func TestTheDelegationReadSendsMirrorStacksOwnToken(t *testing.T) {
	var auth, target string
	d := dcvFor(t, func(w http.ResponseWriter, r *http.Request) {
		auth, target = r.Header.Get("Authorization"), r.URL.String()
		_, _ = io.WriteString(w, dcvBody("orgzoneident"))
	})
	if _, _, err := DelegationUUID(context.Background(), d, lane.OrgPlatformDomain); err != nil {
		t.Fatalf("DelegationUUID: %v", err)
	}
	if auth != "Bearer ms-zone-token" {
		t.Fatalf("the zone credential must ride the Authorization header, got %q", auth)
	}
	if strings.Contains(target, "ms-zone-token") {
		t.Fatalf("the credential must never appear in a URL, got %q", target)
	}
	if !strings.Contains(target, "/zones/"+testZones.OrgPlatform+"/") {
		t.Fatalf("the read must be against MirrorStack's own zone, got %q", target)
	}
}

// A second pass inside the TTL must not spend another call, and a refusal must
// not be retried on every pass either — the negative half is the one that
// matters, since an unreadable Cloudflare is asked by every lane of every
// registration.
func TestOneZoneIsReadOncePerWindow(t *testing.T) {
	calls := 0
	d := dcvFor(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = io.WriteString(w, dcvBody("orgzoneident"))
	})
	for range 3 {
		if _, ok, err := DelegationUUID(context.Background(), d, lane.OrgPlatformDomain); !ok || err != nil {
			t.Fatalf("DelegationUUID: ok=%v err=%v", ok, err)
		}
	}
	if calls != 1 {
		t.Fatalf("want one call inside the TTL, got %d", calls)
	}

	failing := dcvFor(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":9109,"message":"Unauthorized"}]}`)
	})
	calls = 0
	var last error
	for range 3 {
		_, _, last = DelegationUUID(context.Background(), failing, lane.OrgPlatformDomain)
	}
	if calls != 1 {
		t.Fatalf("want one call inside the failure window, got %d", calls)
	}
	if last == nil || !strings.Contains(last.Error(), "Unauthorized") {
		// Remembered rather than recomputed: the remembered answer must keep its
		// own words, so a repeated refusal still names what Cloudflare said.
		t.Fatalf("the remembered refusal must keep Cloudflare's words, got %v", last)
	}
}

// 🔴 THE FALLBACK IS QUIET AND THE FAULT IS NOT. A deployment with no zone and
// no credential simply has no answer, which the caller replaces with its
// configured one; a credential it cannot READ is a fault, and reported as one.
func TestAnUnaskableDelegationIsAbsentRatherThanAFailure(t *testing.T) {
	ctx := context.Background()
	if uuid, ok, err := DelegationUUID(ctx, nil, lane.OrgPlatformDomain); uuid != "" || ok || err != nil {
		t.Fatalf("a nil reader must report none, got %q ok=%v err=%v", uuid, ok, err)
	}
	for name, d := range map[string]*DCV{
		"no zone for this lane": NewDCV(EdgeZones{App: "z"}, cfedge.Static("t")),
		"no credential at all":  NewDCV(testZones, cfedge.Static("")),
	} {
		uuid, ok, err := DelegationUUID(ctx, d, lane.OrgPlatformDomain)
		if uuid != "" || ok || err != nil {
			t.Fatalf("%s: want a quiet absence, got %q ok=%v err=%v", name, uuid, ok, err)
		}
	}
	for name, d := range map[string]*DCV{
		"no token source": NewDCV(testZones, nil),
		"a failing source": NewDCV(testZones, func(context.Context) (cfedge.Token, error) {
			return "", errors.New("secret unavailable")
		}),
	} {
		if _, ok, err := DelegationUUID(ctx, d, lane.OrgPlatformDomain); ok || err == nil {
			t.Fatalf("%s: want a refusal, got ok=%v err=%v", name, ok, err)
		}
	}
}

// 🔴 THE IDENTIFIER BECOMES ONE LABEL IN A CUSTOMER'S ZONE. An answer carrying a
// dot would move record 6's target to a domain Cloudflare never named, so what
// cannot be a label is refused above the interface — loudly, since a refusal the
// caller turns into "keep the configured value" is exactly the outcome wanted and
// a silent drop is not.
func TestADelegationIdentifierThatCannotBeALabelIsRefused(t *testing.T) {
	for name, body := range map[string]string{
		"a dotted answer":   dcvBody("abc.dcv.cloudflare.com"),
		"an underscore":     dcvBody("_abc"),
		"a wildcard":        dcvBody("*"),
		"an over-long one":  dcvBody(strings.Repeat("a", 64)),
		"an empty uuid":     dcvBody(""),
		"no result at all":  `{"success":true}`,
		"a failed envelope": `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`,
	} {
		d := dcvFor(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, body)
		})
		uuid, ok, err := DelegationUUID(context.Background(), d, lane.OrgPlatformDomain)
		if err == nil || ok || uuid != "" {
			t.Fatalf("%s: want a refusal, got %q ok=%v err=%v", name, uuid, ok, err)
		}
	}
}

// Cloudflare's own form is accepted as readily as the 16-hex one observed today:
// pinning the length or the alphabet would refuse a value Cloudflare itself
// handed us. Case is folded, because a DNS label is case-insensitive and the
// plan digest is not.
func TestADelegationIdentifierIsTakenInWhateverShapeCloudflareSends(t *testing.T) {
	for name, sent := range map[string]string{
		"the 16-hex form observed today": "6126b8722afa32ca",
		"a canonical hyphenated uuid":    "3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f607",
		"uppercase, which DNS folds":     "6126B8722AFA32CA",
	} {
		d := dcvFor(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, dcvBody(sent))
		})
		got, ok, err := DelegationUUID(context.Background(), d, lane.OrgPlatformDomain)
		if err != nil || !ok {
			t.Fatalf("%s: DelegationUUID: ok=%v err=%v", name, ok, err)
		}
		if got != strings.ToLower(sent) {
			t.Fatalf("%s: want %q, got %q", name, strings.ToLower(sent), got)
		}
	}
}
