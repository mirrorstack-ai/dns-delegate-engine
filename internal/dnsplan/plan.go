package dnsplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"unicode/utf8"
)

// Kinds a connect attempt can target. An org has two, with different tables and
// lifecycles, and a callback has to know which one it is holding.
const (
	KindPlatform = "platform"
	KindApp      = "app"

	// Version is the snapshot envelope version. It participates in the digest,
	// so bumping it invalidates in-flight attempts by design.
	Version = int16(1)

	// MaxRecords bounds a single plan. A delegated write is meant to publish
	// one ownership group, not to become a bulk zone-editing primitive.
	MaxRecords = 128

	// MaxRecordIdentity bounds one normalized identity string, so a corrupt or
	// hostile stored row cannot turn a comparison into an allocation attack.
	MaxRecordIdentity = 2048

	// MaxDNSName is the DNS wire limit for a fully-qualified name.
	MaxDNSName = 253
)

// NormalizeName folds the two ways the same name arrives spelled: DNS is
// case-insensitive, and a resolver answer carries the root dot where a provider
// record does not.
//
// 🔴 IT MUST BE IDEMPOTENT. NormalizeName(NormalizeName(x)) == NormalizeName(x),
// for every input, and several things break quietly when it is not.
//
// It was not. Trimming the root dot AFTER trimming space uncovers a space the
// first trim already ran past: "example.com ." became "example.com " — a name
// carrying a trailing space, which then fails to be a suffix of itself. Found by
// FuzzContainsNeverEscapesTheAnchor and by three targets in internal/observe and
// internal/relay, all reporting the same shape from different directions.
//
// The damage was fail-closed but customer-visible. Validate re-normalizes what
// NewSnapshot stored and refuses when the two disagree, so an anchor could pass
// the gate at authorize time and die at publish time — reported as plan_invalid,
// which the caller's contract defines as "this is a bug and retrying cannot
// help", and a caller that believes it may abandon the domain permanently.
//
// The loop also folds a doubled root dot. Neither spelling is a legal DNS name,
// so nothing valid changes shape here and no stored digest moves — TestGoldenDigest
// pins that, and it is a cross-repository contract with api-platform.
func NormalizeName(name string) string {
	name = strings.TrimSpace(name)
	for strings.HasSuffix(name, ".") {
		name = strings.TrimSpace(strings.TrimSuffix(name, "."))
	}
	return strings.ToLower(name)
}

// NormalizeRecords applies the public receipt identity contract and returns the
// exact records passed to a provider. Value remains part of the identity, so
// two TXT rotations at one owner stay distinct.
func NormalizeRecords(records []Record) ([]Record, []string, error) {
	seen := make(map[string]struct{}, len(records))
	out := make([]Record, 0, len(records))
	identities := make([]string, 0, len(records))
	for _, record := range records {
		record.Type = strings.ToUpper(strings.TrimSpace(record.Type))
		record.Name = NormalizeName(record.Name)
		record.Value = strings.TrimSpace(record.Value)
		if (record.Type != "CNAME" && record.Type != "TXT") || record.Name == "" || record.Value == "" {
			return nil, nil, fmt.Errorf("%w: incomplete DNS record in group plan", ErrPlanPreparing)
		}
		// 🔴 EVERY FIELD MUST BE VALID UTF-8, AND THIS IS A DIGEST PROPERTY RATHER
		// THAN A TIDINESS ONE.
		//
		// Digest hashes json.Marshal of the record envelope, and encoding/json
		// SILENTLY REPLACES each invalid UTF-8 byte with U+FFFD instead of
		// failing. So two plans whose values differ — "token-\xff" and
		// "token-\xfe" — marshalled to identical bytes and produced ONE SHA-256.
		// The digest is the thing that binds what a customer reviewed to what
		// gets written; a collision in it is that binding not existing.
		//
		// Found by FuzzDigestIsStableAndBinding. Refusing the input is the fix
		// rather than escaping it: no legitimate DNS record carries invalid
		// UTF-8, and a digest computed over a repaired value would bind the
		// repair rather than the record.
		if !utf8.ValidString(record.Type) || !utf8.ValidString(record.Name) || !utf8.ValidString(record.Value) {
			return nil, nil, fmt.Errorf("%w: DNS record is not valid UTF-8", ErrPlanInvalid)
		}
		identity := record.Type + "|" + record.Name + "|" + record.Value
		// 🔴 BOUNDED HERE, NOT ONLY IN Validate. MaxRecordIdentity was enforced
		// on read and not on write, so an over-long record was accepted at
		// authorize time and refused at publish time — the same accept-then-refuse
		// stranding described on NormalizeName above. A bound that only one of two
		// gates applies is a bound that reports as a bug in the other one.
		if len(identity) > MaxRecordIdentity {
			return nil, nil, fmt.Errorf("%w: record identity is %d bytes, past the %d a plan holds",
				ErrPlanInvalid, len(identity), MaxRecordIdentity)
		}
		if _, ok := seen[identity]; ok {
			continue
		}
		seen[identity] = struct{}{}
		out = append(out, record)
		identities = append(identities, identity)
	}
	return out, identities, nil
}

// Snapshot is the immutable authorization boundary persisted on an attempt row.
// Kind and TargetID bind it to a live resource; the remaining fields bind the
// provider write to exactly what the operator reviewed. The digest catches
// accidental or corrupt partial rewrites before any provider token is exchanged.
type Snapshot struct {
	Version    int16
	Kind       string
	TargetID   string
	Anchor     string
	Records    []Record
	Identities []string
}

// NewSnapshot normalizes a derived plan into the authorization boundary, or
// refuses it.
//
// 🔴 EVERY RECORD MUST SIT AT OR UNDER THE ANCHOR. THIS IS THE WRITE BOUND.
//
// The anchor is the name the org PROVED it owns, and a grant's authority is
// "names under this". Nothing enforced it originally: the plan was trusted to
// only ever derive in-anchor names, which held while a grant lived 24 hours and
// published a fixed set.
//
// An APP-DOMAIN grant is standing — it exists to serve deployments that have not
// happened yet — and Cloudflare's dns_records:edit cannot be narrowed to a
// subtree, so the credential covers the customer's WHOLE zone: apex, www, MX.
// The only thing that can bound what we write is this check, and it belongs
// where every plan is built rather than at each publish site, because the site
// that forgot it would be the one that mattered.
//
// It is belt-and-braces against a derivation bug, not against a hostile caller:
// a plan record naming something outside the proven parent is a defect, and
// refusing the whole plan is the safe answer to it.
func NewSnapshot(kind, targetID, anchor string, records []Record) (Snapshot, error) {
	if kind != KindPlatform && kind != KindApp {
		return Snapshot{}, fmt.Errorf("%w: unknown kind %q", ErrPlanInvalid, kind)
	}
	canonical, ok := CanonicalUUID(targetID)
	if !ok {
		return Snapshot{}, fmt.Errorf("%w: target id is not a canonical uuid", ErrPlanInvalid)
	}
	anchor = NormalizeName(anchor)
	if anchor == "" || len(anchor) > MaxDNSName {
		return Snapshot{}, fmt.Errorf("%w: anchor is not a DNS name", ErrPlanInvalid)
	}
	normalized, identities, err := NormalizeRecords(records)
	if err != nil {
		return Snapshot{}, err
	}
	if len(normalized) == 0 || len(normalized) > MaxRecords {
		return Snapshot{}, fmt.Errorf("%w: %d records", ErrPlanPreparing, len(normalized))
	}
	for _, record := range normalized {
		if Contains(anchor, record.Name) {
			continue
		}
		slog.Error("dnsplan: refusing a delegated plan that names something outside its anchor",
			"anchor", anchor, "record", NormalizeName(record.Name), "kind", kind)
		return Snapshot{}, fmt.Errorf("%w: %q is not at or under %q",
			ErrAnchorEscape, NormalizeName(record.Name), anchor)
	}
	return Snapshot{
		Version: Version, Kind: kind, TargetID: canonical, Anchor: anchor,
		Records: normalized, Identities: identities,
	}, nil
}

// Contains reports whether name sits at or under anchor.
//
// The suffix is matched with a leading dot so `evilexample.com` is not treated
// as being under `example.com`. A wildcard routing record is `*.<anchor>`, which
// is under it and passes.
func Contains(anchor, name string) bool {
	anchor = NormalizeName(anchor)
	name = NormalizeName(name)
	if anchor == "" || name == "" {
		return false
	}
	return name == anchor || strings.HasSuffix(name, "."+anchor)
}

// Digest is the SHA-256 that binds a reviewed plan to a published one.
//
// A struct (rather than a map) gives json.Marshal a stable field order. The
// database stores JSONB records, so completion decodes and re-marshals this same
// typed envelope before comparing. See Record for why the tags are load-bearing.
func (s Snapshot) Digest() []byte {
	payload, err := json.Marshal(struct {
		Version    int16    `json:"version"`
		Kind       string   `json:"kind"`
		TargetID   string   `json:"targetId"`
		Anchor     string   `json:"anchor"`
		Records    []Record `json:"records"`
		Identities []string `json:"identities"`
	}{s.Version, s.Kind, s.TargetID, s.Anchor, s.Records, s.Identities})
	if err != nil {
		return nil // all fields are JSON primitives; retained as a fail-closed guard
	}
	sum := sha256.Sum256(payload)
	return sum[:]
}

// Validate re-derives every invariant from a snapshot read back out of storage
// and checks it against the digest recorded when it was written. A stored row is
// untrusted input: it may have been written by an older version, corrupted, or
// partially rewritten.
func (s Snapshot) Validate(storedDigest []byte) error {
	if s.Version != Version ||
		(s.Kind != KindPlatform && s.Kind != KindApp) ||
		s.Anchor == "" || s.Anchor != NormalizeName(s.Anchor) || len(s.Anchor) > MaxDNSName ||
		len(s.Records) == 0 || len(s.Records) > MaxRecords {
		return fmt.Errorf("%w: stored snapshot envelope", ErrPlanInvalid)
	}
	if _, ok := CanonicalUUID(s.TargetID); !ok {
		return fmt.Errorf("%w: stored target id", ErrPlanInvalid)
	}
	normalized, identities, err := NormalizeRecords(s.Records)
	if err != nil || !equalRecords(normalized, s.Records) || !equalStrings(identities, s.Identities) {
		return fmt.Errorf("%w: stored records are not normalized", ErrPlanInvalid)
	}
	for _, identity := range s.Identities {
		if identity == "" || len(identity) > MaxRecordIdentity {
			return fmt.Errorf("%w: stored identity length", ErrPlanInvalid)
		}
	}
	// Containment is re-checked on read, not only on write. A row written before
	// this rule existed, or by a build without it, must not publish now.
	for _, record := range s.Records {
		if !Contains(s.Anchor, record.Name) {
			slog.Error("dnsplan: stored snapshot names something outside its anchor",
				"anchor", s.Anchor, "record", NormalizeName(record.Name), "kind", s.Kind)
			return fmt.Errorf("%w: %q is not at or under %q",
				ErrAnchorEscape, NormalizeName(record.Name), s.Anchor)
		}
	}
	if digest := s.Digest(); len(digest) == 0 || !bytes.Equal(digest, storedDigest) {
		return fmt.Errorf("%w: digest mismatch", ErrPlanInvalid)
	}
	return nil
}

// CoveredBy reports whether every record the operator reviewed is still in the
// authoritative plan, unchanged. It is the completion-time guard: containment
// rather than equality, because the authoritative plan may legitimately have
// GROWN between review and completion (a sibling row finished preparing), and
// refusing that would strand the customer in a loop. It may never SHRINK or
// MUTATE — that is a plan the operator did not see.
func (s Snapshot) CoveredBy(other Snapshot) bool {
	if s.Version != other.Version || s.Kind != other.Kind ||
		s.TargetID != other.TargetID || s.Anchor != other.Anchor {
		return false
	}
	present := make(map[string]struct{}, len(other.Identities))
	for _, identity := range other.Identities {
		present[identity] = struct{}{}
	}
	for _, identity := range s.Identities {
		if _, ok := present[identity]; !ok {
			return false
		}
	}
	return true
}

// Equal reports exact plan equality.
func (s Snapshot) Equal(other Snapshot) bool {
	return s.Version == other.Version && s.Kind == other.Kind &&
		s.TargetID == other.TargetID && s.Anchor == other.Anchor &&
		equalRecords(s.Records, other.Records) && equalStrings(s.Identities, other.Identities)
}

// AssertReviewed treats the browser list only as an equality ASSERTION.
//
// 🔴 NO BROWSER-SUPPLIED RECORD IS EVER DECODED INTO A PROVIDER WRITE.
//
// Each item must already be in the normalized TYPE|name|value form, and must
// re-normalize to itself. The function's only output is an error: what gets
// written is always the server-derived plan.
func AssertReviewed(reviewed, authoritative []string) error {
	if len(reviewed) == 0 || len(reviewed) != len(authoritative) || len(reviewed) > MaxRecords {
		return fmt.Errorf("%w: reviewed set size", ErrPlanChanged)
	}
	got := append([]string(nil), reviewed...)
	for _, identity := range got {
		if identity == "" || len(identity) > MaxRecordIdentity {
			return fmt.Errorf("%w: reviewed identity length", ErrPlanChanged)
		}
		parts := strings.SplitN(identity, "|", 3)
		if len(parts) != 3 {
			return fmt.Errorf("%w: reviewed identity shape", ErrPlanChanged)
		}
		_, normalized, err := NormalizeRecords([]Record{{
			Type: parts[0], Name: parts[1], Value: parts[2],
		}})
		if err != nil || len(normalized) != 1 || normalized[0] != identity {
			return fmt.Errorf("%w: reviewed identity is not normalized", ErrPlanChanged)
		}
	}
	sort.Strings(got)
	want := append([]string(nil), authoritative...)
	sort.Strings(want)
	for i := 1; i < len(got); i++ {
		if got[i] == got[i-1] {
			return fmt.Errorf("%w: duplicate in reviewed set", ErrPlanChanged)
		}
	}
	if !equalStrings(got, want) {
		return fmt.Errorf("%w: reviewed set differs from authoritative", ErrPlanChanged)
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func equalRecords(left, right []Record) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// CanonicalUUID accepts only the canonical hyphenated form (any case) and
// returns it lowercased.
//
// Deliberately stricter than a general UUID parser: pgtype accepts braced and
// unhyphenated spellings, so "the same" id could arrive in several encodings.
// Since TargetID is inside the digest, two encodings of one id would produce two
// digests and a plan would stop matching itself.
//
// 🔴 EXPORTED SO THERE IS ONE COPY. lane.ValidateIdentity is the other caller,
// and the id is inside the ownership HMAC as well as the digest — a looser
// second copy would mint a proof for a spelling this one refuses.
func CanonicalUUID(s string) (string, bool) {
	if len(s) != 36 {
		return "", false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return "", false
			}
			continue
		}
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return "", false
		}
	}
	return strings.ToLower(s), true
}
