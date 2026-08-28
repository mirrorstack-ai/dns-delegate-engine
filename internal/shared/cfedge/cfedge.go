// Package cfedge holds MirrorStack's OWN Cloudflare API token — the credential
// internal/relay reads record 7, the serving proof, from MirrorStack's zones
// with (docs/DESIGN.md §6).
//
// 🔴 IT IS NOT A CUSTOMER'S GRANT AND MUST NEVER REACH A CUSTOMER'S ZONE. A
// customer's credential travels everywhere in this service as a plain `string`
// — internal/dnsprovider takes `token string` on every method — so this one is a
// DEFINED TYPE instead: neither can be passed where the other is wanted without
// a conversion somebody had to write and a reviewer can grep for, which makes
// the rule a compiler error rather than a comment.
package cfedge

import (
	"context"
	"errors"
)

// ErrNotConfigured means this deployment names no edge token at all — the state
// of every dev box, and of a fresh environment whose secret is still the empty
// placeholder CDK created.
//
// 🔴 IT IS NOT A FAULT, AND THE DIFFERENCE DECIDES WHAT A CUSTOMER SEES.
// internal/relay turns it into "the proof is not available yet" and everything
// else the loader returns into a warning on the pass, so a deployment that was
// never finished stays quiet while one whose secret cannot be READ says so.
var ErrNotConfigured = errors.New("cfedge: no MirrorStack Cloudflare token is configured")

// Token is MirrorStack's own Cloudflare API token.
type Token string

// String redacts, so the token cannot reach a log line or an error string
// through %s, %q or %v. Reaching the wire takes an explicit string(token), which
// happens once, in internal/relay.
func (Token) String() string { return "[redacted]" }

// Source yields the token for one call. A function rather than a value so it can
// be re-read on a TTL and rotate underneath a running process; see Loader.
type Source func(ctx context.Context) (Token, error)

// Static adapts a token already in hand. Local runs and tests; production reads
// a rotating secret.
func Static(token Token) Source {
	return func(context.Context) (Token, error) {
		if token == "" {
			return "", ErrNotConfigured
		}
		return token, nil
	}
}
