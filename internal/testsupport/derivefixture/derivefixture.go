// Package derivefixture is the derive.Config every package above internal/derive
// derives its test plans from. It is a package of its own because internal/derive
// imports internal/proof, and a fixture package that imports derive could not be
// imported by either one's own tests.
package derivefixture

import "github.com/mirrorstack-ai/dns-delegate-engine/internal/derive"

const (
	// The routing targets are MirrorStack's own names, which is what they are in
	// production too — a routing target is never a customer domain.
	OrgRoutingTarget = "connect.mirrorstack.ai"
	AppRoutingTarget = "connect.mirrorstack.app"

	// DCVDelegationUUID is a placeholder in the shape Cloudflare actually returns:
	// 16 hexadecimal characters, NOT a 36-character UUID.
	DCVDelegationUUID = "0123456789abcdef"
)

// Config is the deployment vocabulary a test plan is derived under.
func Config() derive.Config {
	return derive.Config{
		OrgRoutingTarget:  OrgRoutingTarget,
		AppRoutingTarget:  AppRoutingTarget,
		DCVDelegationUUID: DCVDelegationUUID,
		ReservedSuffixes:  []string{"mirrorstack.ai", "mirrorstack.app"},
	}
}
