// Package testsupport holds the fixtures more than one package's tests need: a
// deterministic keyset, the two loader stubs, and the one resolver error that
// means "this name does not resolve".
//
// 🔴 NOTHING HERE IS REACHABLE FROM THE SERVICE. No production file imports it,
// it opens no connection and reads no secret — the property every package here
// claims, that its safety is checkable without a network, a database or a
// Cloudflare account, has to hold for the fixtures too.
//
// It imports neither internal/derive nor anything above it, because
// internal/derive imports internal/proof and a fixture package reaching for
// either could not be imported by the other one's tests. The shared derive.Config
// fixture lives in internal/testsupport/derivefixture for that reason.
package testsupport

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/cfoauth"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/grantcrypto"
)

// Keyset builds a keyset document from key ids, the FIRST of which is active.
// Each key's material is derived from its own id rather than from its position,
// so a rotation fixture can reorder the ids and the only thing that moves is
// which key is active.
func Keyset(tb testing.TB, ids ...string) string {
	tb.Helper()
	if len(ids) == 0 {
		tb.Fatal("a keyset needs at least one key")
	}
	entries := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			tb.Fatal("a key id must not be empty")
		}
		raw := make([]byte, grantcrypto.KeySize)
		for i := range raw {
			raw[i] = id[i%len(id)] ^ byte(i)
		}
		entries = append(entries, fmt.Sprintf("%q:%q", id, base64.StdEncoding.EncodeToString(raw)))
	}
	return fmt.Sprintf(`{"active":%q,"keys":{%s}}`, ids[0], strings.Join(entries, ","))
}

// Sealer is Keyset, parsed.
func Sealer(tb testing.TB, ids ...string) *grantcrypto.Sealer {
	tb.Helper()
	return SealerFrom(tb, Keyset(tb, ids...))
}

// GoldenKeyset is 32 bytes 0x00…0x1f under the key id "golden", written out
// rather than randomized so a reader can regenerate every golden MAC in this
// repository with any HKDF/HMAC tool.
//
// 🔴 internal/proof AND internal/consent BOTH MINT UNDER IT, which is what makes
// their golden values a test of the HKDF domain separation between the two
// rather than of two different keys.
func GoldenKeyset(tb testing.TB) string {
	tb.Helper()
	raw := make([]byte, grantcrypto.KeySize)
	for i := range raw {
		raw[i] = byte(i)
	}
	return `{"active":"golden","keys":{"golden":"` + base64.StdEncoding.EncodeToString(raw) + `"}}`
}

// SealerFrom parses one keyset document. The JSON shape is the deployed secret's,
// built inline: a fixture that read a file or a secret store could fail for a
// reason with nothing to do with sealing.
func SealerFrom(tb testing.TB, document string) *grantcrypto.Sealer {
	tb.Helper()
	keys, err := grantcrypto.ParseKeyset(document)
	if err != nil {
		tb.Fatalf("ParseKeyset: %v", err)
	}
	sealer, err := grantcrypto.NewSealer(keys)
	if err != nil {
		tb.Fatalf("NewSealer: %v", err)
	}
	return sealer
}

// SealerWithKey builds a one-key sealer from material the caller spells out, for
// the fixtures whose exact bytes are pinned by a golden envelope or a pasted
// ciphertext.
func SealerWithKey(tb testing.TB, id string, key []byte) *grantcrypto.Sealer {
	tb.Helper()
	return SealerFrom(tb, fmt.Sprintf(`{"active":%q,"keys":{%q:%q}}`,
		id, id, base64.StdEncoding.EncodeToString(key)))
}

// StubKeys hands out one sealer. A zero StubKeys hands out none, which is a real
// state rather than a contrivance: the loaders re-read their secret on a TTL, so
// a retired key or a secret store that starts refusing looks exactly like this
// from inside one call.
type StubKeys struct{ Held *grantcrypto.Sealer }

// Sealer implements the keyset loader the services take.
func (s StubKeys) Sealer(context.Context) *grantcrypto.Sealer { return s.Held }

// StubOAuth hands out one OAuth client configuration, or none.
type StubOAuth struct{ Cfg *cfoauth.Config }

// Config implements the OAuth loader the services take.
func (s StubOAuth) Config(context.Context) *cfoauth.Config { return s.Cfg }

// NotFound is how a resolver spells NXDOMAIN, and also "the name exists but holds
// no record of this type". internal/observe recognises exactly this and nothing
// else as absence.
func NotFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}
