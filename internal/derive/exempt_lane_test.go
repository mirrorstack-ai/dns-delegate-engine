package derive_test

import (
	"strings"
	"testing"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/derive"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
)

// 🔴 THE EXEMPTION IS PER LANE, AND THAT IS THE POINT.
//
// Lane 1's hostnames live in the ORG zone and lane 2's in the APP zone, each
// with its own DCV delegation identifier. The staging entries deliberately CROSS
// those zones — an app-zone name on the org lane and an org-zone name on the app
// lane — because that is the only configuration in which selecting the wrong
// zone's identifier is visible. Shared, it would be right by accident.
func cfg() derive.Config {
	return derive.Config{
		OrgRoutingTarget:     "connect.mirrorstack.ai",
		AppRoutingTarget:     "connect.mirrorstack.app",
		DCVDelegationUUID:    "6126b8722afa32ca",
		DCVDelegationUUIDApp: "b5ed627ae082aa51",
		ReservedSuffixes:     []string{"mirrorstack.ai", "mirrorstack.app"},
		ExemptHostsOrgPlatform: []string{
			"studio.mirrorstack.ai", "studio-tw.mirrorstack.ai", "platform.mirrorstack.app",
		},
		ExemptHostsOrgApp: []string{
			"studio.mirrorstack.app", "studio-tw.mirrorstack.app", "app.mirrorstack.ai",
		},
	}
}

func TestEachLaneAdmitsOnlyItsOwnExemptions(t *testing.T) {
	c := cfg()
	tests := []struct {
		name    string
		l       lane.Lane
		domain  string
		admit   bool
		because string
	}{
		{"org lane, its own org-zone host", lane.OrgPlatformDomain, "studio.mirrorstack.ai", true, ""},
		{"org lane, its own CROSS-zone host", lane.OrgPlatformDomain, "platform.mirrorstack.app", true,
			"an app-zone name on the org lane is the cross-zone probe"},
		{"app lane, its own app-zone host", lane.OrgAppDomain, "studio.mirrorstack.app", true, ""},
		{"app lane, its own CROSS-zone host", lane.OrgAppDomain, "app.mirrorstack.ai", true,
			"an org-zone name on the app lane is the mirror probe"},

		// The halves must NOT be interchangeable.
		{"org lane refuses the APP lane's entry", lane.OrgPlatformDomain, "app.mirrorstack.ai", false,
			"a flat list would admit this and lose the per-zone property"},
		{"app lane refuses the ORG lane's entry", lane.OrgAppDomain, "platform.mirrorstack.app", false, ""},

		// Lane 3 is exempted from nothing.
		{"app_domain lane is exempted from nothing", lane.AppDomain, "studio.mirrorstack.ai", false, ""},

		// Everything not listed stays reserved.
		{"an unlisted MirrorStack name stays reserved", lane.OrgPlatformDomain, "secret.mirrorstack.ai", false, ""},
		{"the subtree beneath an entry stays reserved", lane.OrgPlatformDomain, "api.platform.mirrorstack.app", false,
			"exact match, never a suffix"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.Registration(tc.l, "11111111-1111-1111-1111-111111111111", tc.domain, "msv1-x")
			if tc.admit && err != nil {
				t.Fatalf("%q refused on %s: %v — %s", tc.domain, tc.l, err, tc.because)
			}
			if !tc.admit && err == nil {
				t.Fatalf("%q ADMITTED on %s, which it must not be — %s", tc.domain, tc.l, tc.because)
			}
		})
	}
}

// The cross-zone entries are only worth having if each lane then derives its own
// zone's identifier. If both lanes shared one, the probe would pass while
// proving nothing.
//
// 🔴 THE TWO LANES ARE PROBED THROUGH DIFFERENT FUNCTIONS, AND THAT IS NOT AN
// INCONSISTENCY IN THE TEST. Lane 2 derives NO certificate pointer at
// registration — `_acme-challenge.*.example.net` is not a name anybody can
// publish — so its record 6 is minted per app by BindApp at deploy time. Probing
// it through Registration would assert the absence of a record that is correctly
// absent, and pass for the wrong reason.
func TestTheCrossZoneEntriesDeriveTheirOwnZonesIdentifier(t *testing.T) {
	c := cfg()

	// Lane 1: an APP-zone name on the ORG lane must still take the ORG uuid.
	org, err := c.Registration(lane.OrgPlatformDomain,
		"11111111-1111-1111-1111-111111111111", "platform.mirrorstack.app", "msv1-x")
	if err != nil {
		t.Fatalf("org lane: %v", err)
	}
	if !recordsMention(org, "6126b8722afa32ca") {
		t.Error("the org lane did not derive the ORG zone's delegation identifier")
	}
	if recordsMention(org, "b5ed627ae082aa51") {
		t.Error("the org lane derived the APP zone's identifier — record 6 would aim at a namespace Cloudflare never writes for these hosts")
	}

	// Lane 2: an ORG-zone name on the APP lane must still take the APP uuid,
	// via the per-app pointer.
	app, err := c.BindApp("app.mirrorstack.ai", "probe")
	if err != nil {
		t.Fatalf("app lane BindApp: %v", err)
	}
	if !recordsMention(app, "b5ed627ae082aa51") {
		t.Error("the app lane did not derive the APP zone's delegation identifier")
	}
	if recordsMention(app, "6126b8722afa32ca") {
		t.Error("the app lane derived the ORG zone's identifier")
	}
}

// BindApp runs on lane 2 by construction, so it must honour lane 2's list and
// nothing else — otherwise an app could be bound under a parent the org lane
// exempted, which is a different zone.
func TestBindAppHonoursTheAppLaneList(t *testing.T) {
	c := cfg()
	if _, err := c.BindApp("app.mirrorstack.ai", "probe"); err != nil {
		t.Errorf("lane 2's own entry was refused by BindApp: %v", err)
	}
	if _, err := c.BindApp("platform.mirrorstack.app", "probe"); err == nil {
		t.Error("BindApp admitted the ORG lane's entry — the lists are not interchangeable")
	}
	if _, err := c.BindApp("secret.mirrorstack.ai", "probe"); err == nil {
		t.Error("BindApp admitted an unlisted MirrorStack name")
	}
}

func recordsMention(p derive.Plan, needle string) bool {
	for _, it := range p.Items {
		if strings.Contains(it.Record.Value, needle) {
			return true
		}
	}
	return false
}
