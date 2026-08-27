// Package grantcrypto seals the one customer credential this platform stores:
// the Cloudflare refresh token behind a held delegated-DNS grant.
//
// 🔴 IT EXISTS BECAUSE THE ALTERNATIVE WAS MEASURED AND DOES NOT WORK.
// Cloudflare mints a host's DCV TXT only after that host's routing CNAME
// resolves, and the routing CNAME is written by the grant — so the second half
// of a registration's plan comes into existence minutes after the write that
// would have published it. A one-shot token is always already revoked by then.
//
// Everything here is chosen to make holding that credential as boring as
// possible: AES-256-GCM from the standard library, a keyset small enough to
// read in one sitting, and an envelope that carries its own key id so rotation
// never has to find and rewrite old rows.
package grantcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// envelopeVersion prefixes every sealed value. A version that this build does
// not know is refused rather than guessed at: the failure mode of guessing is
// handing a garbled string to Cloudflare as a refresh token.
const envelopeVersion = "v1"

// KeySize is AES-256. Fixed rather than inferred from the key's length, so a
// 16-byte key is a configuration error at load time instead of a quietly weaker
// cipher at seal time.
const KeySize = 32

var (
	// ErrNoKeyset means this deployment was given no keyset. Callers must treat
	// it as "do not hold grants" and fall back to revoking immediately — never
	// as "store it in the clear".
	ErrNoKeyset = errors.New("grantcrypto: no keyset configured")
	// ErrUnknownKey means a sealed value names a key this keyset does not hold.
	// Recoverable only by restoring the key; the grant is otherwise dead and
	// must be released rather than retried forever.
	ErrUnknownKey = errors.New("grantcrypto: sealed value names an unknown key")
	// ErrMalformed covers every shape problem in an envelope.
	ErrMalformed = errors.New("grantcrypto: malformed sealed value")
)

// Keyset is the parsed contents of the secret: several keys, one of them
// active. More than one exists ONLY so a rotation can decrypt what the previous
// key sealed; nothing else reads the inactive ones.
type Keyset struct {
	// Active names the key new values are sealed under.
	Active string
	// Keys maps key id to raw key bytes.
	Keys map[string][]byte
}

// keysetJSON is the on-the-wire shape, kept separate from Keyset so the secret's
// format is one obvious thing to read rather than struct tags scattered through
// the logic.
type keysetJSON struct {
	Active string            `json:"active"`
	Keys   map[string]string `json:"keys"`
}

// ParseKeyset reads the secret payload.
//
// Every refusal is an error rather than a partial keyset. A keyset that loads
// with one bad key would seal fine and fail to open exactly one row, months
// later, with nothing pointing at the cause.
func ParseKeyset(raw string) (*Keyset, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrNoKeyset
	}
	var doc keysetJSON
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, fmt.Errorf("grantcrypto: keyset is not JSON: %w", err)
	}
	doc.Active = strings.TrimSpace(doc.Active)
	if doc.Active == "" {
		return nil, errors.New("grantcrypto: keyset names no active key")
	}
	if len(doc.Keys) == 0 {
		return nil, errors.New("grantcrypto: keyset holds no keys")
	}
	out := &Keyset{Active: doc.Active, Keys: make(map[string][]byte, len(doc.Keys))}
	for id, encoded := range doc.Keys {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, errors.New("grantcrypto: keyset has an unnamed key")
		}
		// 🔴 The key id travels in the CLEAR inside every envelope, so it must
		// not be able to forge envelope structure. A dot would split a
		// three-part envelope into four and make one key's ciphertext parse as
		// another key's nonce.
		if strings.ContainsAny(id, ".") {
			return nil, fmt.Errorf("grantcrypto: key id %q contains the envelope separator", id)
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		if err != nil {
			return nil, fmt.Errorf("grantcrypto: key %q is not base64: %w", id, err)
		}
		if len(key) != KeySize {
			return nil, fmt.Errorf("grantcrypto: key %q is %d bytes, want %d", id, len(key), KeySize)
		}
		out.Keys[id] = key
	}
	if _, ok := out.Keys[out.Active]; !ok {
		return nil, fmt.Errorf("grantcrypto: active key %q is not in the keyset", out.Active)
	}
	return out, nil
}

// Sealer seals and opens values under a keyset.
type Sealer struct{ keys *Keyset }

// NewSealer refuses a nil keyset rather than degrading to a no-op. A no-op
// sealer would write refresh tokens in the clear and look identical from the
// caller's side.
func NewSealer(keys *Keyset) (*Sealer, error) {
	if keys == nil || len(keys.Keys) == 0 {
		return nil, ErrNoKeyset
	}
	return &Sealer{keys: keys}, nil
}

// ActiveKeyID is the key new values are sealed under, recorded beside the
// ciphertext so an operator can answer "is the old key still needed?" with a
// SELECT DISTINCT rather than by decrypting every row.
func (s *Sealer) ActiveKeyID() string { return s.keys.Active }

// Seal encrypts plaintext, binding it to aad.
//
// 🔴 THE AAD IS WHAT STOPS A CIPHERTEXT MOVING BETWEEN ROWS. Without it a
// sealed token lifted from org A's grant and pasted into org B's row would
// decrypt perfectly and hand B a live dns.write credential on A's zone. The
// caller passes the row's identity; this only guarantees it is authenticated.
func (s *Sealer) Seal(plaintext, aad string) (envelope string, keyID string, err error) {
	if plaintext == "" {
		return "", "", errors.New("grantcrypto: refusing to seal an empty value")
	}
	id := s.keys.Active
	gcm, err := s.gcmFor(id)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", "", fmt.Errorf("grantcrypto: nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, []byte(plaintext), []byte(aad))
	return strings.Join([]string{
		envelopeVersion, id,
		base64.RawStdEncoding.EncodeToString(nonce),
		base64.RawStdEncoding.EncodeToString(ct),
	}, "."), id, nil
}

// Open decrypts an envelope, requiring the same aad.
func (s *Sealer) Open(envelope, aad string) (string, error) {
	parts := strings.Split(strings.TrimSpace(envelope), ".")
	if len(parts) != 4 || parts[0] != envelopeVersion {
		return "", ErrMalformed
	}
	gcm, err := s.gcmFor(parts[1])
	if err != nil {
		return "", err
	}
	nonce, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(nonce) != gcm.NonceSize() {
		return "", ErrMalformed
	}
	ct, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return "", ErrMalformed
	}
	out, err := gcm.Open(nil, nonce, ct, []byte(aad))
	if err != nil {
		// Deliberately ONE error for a wrong key, a wrong AAD and a tampered
		// ciphertext. They are all "this value is not usable here", and
		// distinguishing them tells an attacker which half they guessed.
		return "", ErrMalformed
	}
	return string(out), nil
}

func (s *Sealer) gcmFor(id string) (cipher.AEAD, error) {
	key, ok := s.keys.Keys[id]
	if !ok {
		return nil, ErrUnknownKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("grantcrypto: cipher: %w", err)
	}
	return cipher.NewGCM(block)
}
