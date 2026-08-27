// Package dnsplan holds the authorization boundary for a delegated DNS write:
// the record set, its normalization rules, the anchor-containment check that
// bounds what a customer grant can ever touch, and the digest that binds what
// an operator reviewed to what is published.
//
// Nothing in this package talks to a DNS provider, a database, or the network.
// It is pure data and pure rules, so the safety properties this service claims
// can be read, and tested, without a Cloudflare account.
package dnsplan

// Record is a single DNS record in a plan.
//
// 🔴 THE JSON TAGS AND FIELD ORDER ARE PART OF THE STORED DIGEST.
//
// api-platform persists a SHA-256 over a marshalled envelope containing these
// records, computed before the customer authorizes and re-checked after. A
// reordered field, a renamed tag, or an added `omitempty` changes the bytes and
// invalidates every in-flight attempt — the customer's consent screen would
// stop matching the plan and the publish would be refused.
//
// The mirror of this type is api-platform's
// internal/applications/deploy/hostprovider.DNSRecord. TestGoldenDigest in both
// repositories pins the same fixture to the same hex, so a drift on either side
// fails a build rather than a customer's connect.
type Record struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`

	// Proxied is Cloudflare's orange cloud, and it lives HERE rather than one
	// level up so it survives the trip to the publisher. It used to be dropped
	// on the way, which meant the reconciler wrote every record DNS-only and
	// would actively revert a routing record the console had just told the
	// customer to proxy.
	//
	// NOT `omitempty`: a routing record that must stay grey is exactly the
	// `false` case, and omitting it makes an absent field indistinguishable
	// from "grey on purpose".
	Proxied bool `json:"proxied"`
}
