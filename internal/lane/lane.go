// Package lane names the three ways a customer domain can reach MirrorStack, and
// holds the rules every other package in this service validates against.
//
// A lane is not a label: it decides which identity kind a request carries, which
// hostnames are derived under the anchor and how long a credential may be held,
// and it is an input to the ownership proof, so a proof for one lane authorizes
// nothing on another. Nothing here talks to a DNS provider, a database or the
// network — pure data and pure rules, so the bounds this service claims are
// testable without a Cloudflare account. docs/DESIGN.md §2 is the lane table;
// docs/RECORDS.md the records each produces.
package lane

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
)

// ErrInvalid is the single refusal this package returns. ONE error at the
// boundary, as in dnsplan: every check is errors.Is(err, ErrInvalid), so a
// refusal added later cannot slip past a caller that switched on the sentinels
// it knew. Every refusal below means the request is malformed, so there is
// nothing to branch on; the cause travels in the wrapped message.
var ErrInvalid = errors.New("lane: invalid")

// maxLabel is the DNS wire limit for one label. A hostname may be 253 bytes
// (dnsplan.MaxDNSName) but no single label may exceed 63.
const maxLabel = 63

// Lane is one of exactly three ways a domain reaches MirrorStack.
//
// There is no fourth and no default. An unrecognised value is refused, never
// resolved: a defaulted lane silently picks a record set, an identity kind and a
// grant lifetime the customer never consented to.
type Lane string

const (
	// OrgPlatformDomain puts an org's MirrorStack console on a domain it owns.
	// The anchor is the domain and the footprint is the four siblings in
	// PlatformLabels — never the apex.
	OrgPlatformDomain Lane = "org_platform_domain"

	// OrgAppDomain is the parent under which every one of an org's apps is
	// auto-routed at <slug>.<anchor>, behind one wildcard. The only lane whose
	// grant is standing: the records it exists to write belong to apps that do
	// not exist yet.
	OrgAppDomain Lane = "org_app_domain"

	// AppDomain is one arbitrary domain bound to one app.
	//
	// 🔴 THERE IS NO ORGANIZATION ON THIS LANE, AND THAT IS NOT AN OVERSIGHT. The
	// owner may be a person, so any check reaching for an org id finds nothing,
	// and one reading "no org" as "no restriction" is an authorization hole rather
	// than a nil pointer. Identity() answers it once, here.
	AppDomain Lane = "app_domain"
)

// Parse accepts exactly the three lane strings and nothing else: no case
// folding, no trimming, no aliases.
//
// The lane is a byte string inside the ownership proof — HMAC(K, lane‖id‖anchor)
// — so it is a cryptographic input, not a display value. It arrives from
// MirrorStack's own private half, where a second accepted spelling is a defect
// in the caller; guessing would mean one domain carrying two valid proofs.
func Parse(s string) (Lane, error) {
	switch Lane(s) {
	case OrgPlatformDomain, OrgAppDomain, AppDomain:
		return Lane(s), nil
	}
	return "", fmt.Errorf("%w: unknown lane %q", ErrInvalid, Echo(s))
}

// IdentityKind is what the id on a request denotes.
type IdentityKind string

const (
	// IdentityOrg means the id names an organization: lanes 1 and 2.
	IdentityOrg IdentityKind = "org"

	// IdentityApp means the id names an app, whose owner may be a person with no
	// organization anywhere: lane 3, and only lane 3.
	IdentityApp IdentityKind = "app"
)

// Identity reports what kind of id this lane's identity field carries. An
// unrecognised lane returns the empty kind, so a caller that skipped Parse
// cannot fall through into "org".
func (l Lane) Identity() IdentityKind {
	switch l {
	case OrgPlatformDomain, OrgAppDomain:
		return IdentityOrg
	case AppDomain:
		return IdentityApp
	}
	return ""
}

// PlatformLabels is the fixed sibling table for the org platform lane.
//
// 🔴 THE CALLER CANNOT ADD A FIFTH LABEL OR RENAME ONE. Each label becomes a
// hostname inside the customer's own domain and a subject on a publicly-trusted
// certificate; a label supplied on a request would be a caller-chosen name, and
// this design has exactly one of those (see ValidateSlug). `cdn` is the one label
// CertificateHosts excludes.
//
// The honest limit: this is a package-level slice, so it is writable — by code
// in this repository and nowhere else, since the package is internal. Tests pin
// the four strings, so changing them fails a build, not a customer's zone.
var PlatformLabels = []string{"account", "api", "apps", "cdn"}

// Hosts returns the hostnames this lane serves under anchor, in a fresh slice
// the caller may keep and mutate. docs/DESIGN.md §2 has the table.
//
// 🔴 EVERY NAME RETURNED IS AT OR UNDER THE ANCHOR, BY CONSTRUCTION.
// dnsplan.Contains enforces it again before anything is published; deriving a
// name anywhere else would only move the refusal downstream, past a credential
// exchange.
//
// Lane 1 derives the four siblings and NOT the anchor, so an org connecting
// example.com keeps serving its own website at the apex. Lane 2 derives the
// single wildcard, which answers only names the zone holds no record of its own
// for, so what the customer already publishes keeps resolving; per-app hostnames
// are never listed, because the slug picks one and the wildcard routes it, and
// only the certificate records are minted per app, at deploy time. Lane 3
// derives the anchor itself.
//
// The anchor is re-validated rather than trusted, and one that fails returns nil
// rather than four names under no anchor at all. The reserved suffix list is
// deliberately not consulted: Hosts derives, it does not admit, and a reserved
// check run here with an empty list would be the guard that silently protects
// nothing (see ValidateDomain).
func (l Lane) Hosts(anchor string) []string {
	anchor, err := ValidateDomain(anchor, nil)
	if err != nil {
		return nil
	}
	switch l {
	case OrgPlatformDomain:
		hosts := make([]string, 0, len(PlatformLabels))
		for _, label := range PlatformLabels {
			hosts = append(hosts, label+"."+anchor)
		}
		return hosts
	case OrgAppDomain:
		return []string{"*." + anchor}
	case AppDomain:
		return []string{anchor}
	}
	return nil
}

// cdnLabel is the one platform label that owns no AWS certificate record; see
// CertificateHosts.
const cdnLabel = "cdn"

// CertificateHosts are the hostnames under anchor that an AWS certificate is
// requested for: Hosts minus `cdn`, and only on the org platform lane
// (docs/DESIGN.md §6 row 5).
//
// 🔴 THE EXCLUSION LIVES BESIDE PlatformLabels BECAUSE IT NAMES ONE. The CDN
// worker terminates TLS for that hostname before anything reaches API Gateway,
// so no AWS certificate ever covers it — and an exclusion spelled `"cdn"` in
// another package would keep matching nothing after a rename, sending cdn to ACM,
// which never answers for it: one host reported as waiting forever.
func (l Lane) CertificateHosts(anchor string) []string {
	if l != OrgPlatformDomain {
		return nil
	}
	anchor, err := ValidateDomain(anchor, nil)
	if err != nil {
		return nil
	}
	excluded := cdnLabel + "." + anchor
	hosts := l.Hosts(anchor)
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if host == excluded {
			continue
		}
		out = append(out, host)
	}
	return out
}

// Standing is the grant lifetime of a lane held with no fixed expiry. It is the
// zero duration, which is why GrantLifetime never returns zero for anything else.
const Standing = time.Duration(0)

// closedLaneLifetime is how long a credential is held on a lane whose record set
// is finite and fully known when the customer authorizes.
const closedLaneLifetime = 24 * time.Hour

// alreadyExpired is what an unrecognised lane gets. See GrantLifetime.
const alreadyExpired = -1 * time.Second

// GrantLifetime is how long a grant on this lane is held.
//
// Lanes 1 and 3 are CLOSED: their record sets are finite and known when the
// customer authorizes, so the credential is held 24 hours and then gone — only
// possible because record 6 carries no token and never changes, so nothing needs
// republishing on a certificate-renewal clock. Lane 2 is STANDING, its expiry
// sliding forward each time it publishes; docs/RECORDS.md calls that the trade
// to argue with hardest on this repository, and it is.
//
// 🔴 ZERO MEANS STANDING, SO AN UNRECOGNISED LANE MUST NEVER RETURN ZERO. It
// returns a negative duration: a caller that branches on Standing does not take
// the standing branch, and one that forgets to branch computes an expiry in the
// past, holding a grant already dead. No return value here fails open.
func (l Lane) GrantLifetime() time.Duration {
	switch l {
	case OrgPlatformDomain, AppDomain:
		return closedLaneLifetime
	case OrgAppDomain:
		return Standing
	}
	return alreadyExpired
}

// ValidateIdentity accepts ONLY the canonical 36-character hyphenated UUID, in
// any case, and returns it lowercased. It is dnsplan.CanonicalUUID plus this
// package's sentinel: the id is inside the plan digest AND the ownership HMAC,
// so a second, looser copy of the rule would mint a proof for a spelling the
// publish boundary refuses.
//
// Whether the org or app EXISTS is api-platform's question; only the spelling is
// settled here, which is why the nil UUID is accepted: canonical, and it names
// nothing.
func ValidateIdentity(s string) (string, error) {
	canonical, ok := dnsplan.CanonicalUUID(s)
	if !ok {
		return "", fmt.Errorf("%w: identity is not a canonical uuid", ErrInvalid)
	}
	return canonical, nil
}

// ValidateDomain accepts one DNS name and returns it normalized: lowercased,
// with surrounding space and the root dot removed.
//
// At most 253 bytes, at least two labels, every label LDH — letters, digits and
// hyphen, not starting or ending with one — no empty label, no wildcard, no
// underscore label, no all-numeric rightmost label. An internationalized domain
// must arrive as its A-label (`xn--…`): converting one here would produce a name
// the customer did not type and cannot recognise on a consent screen.
//
// The name becomes the ANCHOR — the single bound on everything a delegated
// credential can ever reach — so the rules are about what can be proven and
// derived, not what a resolver would tolerate. A single label is a TLD nobody
// can own; an all-numeric rightmost label is an address wearing a domain's
// shape, and this service publishes no A or AAAA record.
//
// 🔴 A NAME AT OR UNDER A RESERVED SUFFIX IS REFUSED OUTRIGHT: it has no
// customer at the other end, so the ownership proof would be published by us
// (docs/DESIGN.md §1) and this write path would be reusable as a platform-zone
// editor. Matching is on a leading dot (dnsplan.Contains) and one-directional —
// neither a domain merely ending in the same letters nor a name ABOVE a reserved
// suffix, which somebody could genuinely own, is refused.
//
// An empty reserved list reserves nothing, visibly, at the call site. An entry
// PRESENT but normalizing to nothing is different — someone intended protection
// and it evaporated — so it refuses every domain instead: a guard that protects
// nothing while reading like protection is worse than no guard at all.
func ValidateDomain(name string, reserved []string) (string, error) {
	// 🔴 STRUCTURAL ILLEGALITY IS CHECKED ON THE RAW NAME, BEFORE NORMALIZING.
	//
	// This used to lean on NormalizeName preserving the defect; when NormalizeName
	// was made idempotent — as it had to be, because Validate re-normalizes what
	// NewSnapshot stored and a disagreement strands a customer mid-connect —
	// "example.com.." folded away and the refusal evaporated with it. An empty
	// label is illegal however it is spelled, so it is refused on what arrived.
	if strings.Contains(strings.TrimSpace(name), "..") {
		return "", fmt.Errorf("%w: %q has an empty label", ErrInvalid, Echo(strings.TrimSpace(name)))
	}
	normalized := dnsplan.NormalizeName(name)
	if normalized == "" {
		return "", fmt.Errorf("%w: empty domain", ErrInvalid)
	}
	if len(normalized) > dnsplan.MaxDNSName {
		return "", fmt.Errorf("%w: domain is %d bytes, over the %d-byte DNS limit",
			ErrInvalid, len(normalized), dnsplan.MaxDNSName)
	}
	labels := strings.Split(normalized, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%w: %q is a single label, not a domain", ErrInvalid, Echo(normalized))
	}
	for _, label := range labels {
		if reason := labelReason(label); reason != "" {
			return "", fmt.Errorf("%w: %s in %q", ErrInvalid, reason, Echo(normalized))
		}
	}
	if allDigits(labels[len(labels)-1]) {
		return "", fmt.Errorf("%w: %q has an all-numeric rightmost label", ErrInvalid, Echo(normalized))
	}
	// Checked before use, so a malformed entry is reported whichever domain is
	// under inspection; inline, it would surface only for names that matched
	// nothing else.
	suffixes := make([]string, 0, len(reserved))
	for _, entry := range reserved {
		suffix := dnsplan.NormalizeName(entry)
		if suffix == "" {
			slog.Error("lane: refusing every domain because the reserved-suffix list carries an entry that normalizes to nothing")
			return "", fmt.Errorf("%w: the reserved suffix list is malformed", ErrInvalid)
		}
		// A leading dot is the same failure one spelling further out, and suffixes
		// are often WRITTEN with one. NormalizeName trims a trailing root dot and
		// not a leading one, so the entry survives non-empty, the guard above does
		// not fire, and Contains then tests for "..staging.example" — which no DNS
		// name can end in. Found by fuzzing internal/derive. Refused rather than
		// repaired: stripping it would guess at intent; the entry is a NAME.
		if strings.HasPrefix(suffix, ".") {
			slog.Error("lane: refusing every domain because a reserved-suffix entry is written with a leading dot",
				"entry", suffix)
			return "", fmt.Errorf("%w: the reserved suffix %q is written with a leading dot; it must be a name",
				ErrInvalid, Echo(suffix))
		}
		suffixes = append(suffixes, suffix)
	}
	for _, suffix := range suffixes {
		if dnsplan.Contains(suffix, normalized) {
			return "", fmt.Errorf("%w: %q is at or under the reserved suffix %q",
				ErrInvalid, Echo(normalized), Echo(suffix))
		}
	}
	return normalized, nil
}

// ValidateSlug accepts a single LDH label of at most 63 bytes and returns it
// lowercased.
//
// 🔴 THIS IS THE ONE CALLER-CHOSEN STRING ANYWHERE IN THIS DESIGN. Every other
// byte reaching a customer's zone is derived here or relayed from AWS or
// Cloudflare. A slug selects WHICH name under a parent the customer has already
// proven, never WHAT is written there.
//
// 🔴 A DOTTED SLUG DOES NOT ESCAPE THE ANCHOR, WHICH IS PRECISELY WHY IT HAS TO
// BE REFUSED HERE. "a.b" under example.net is still at or under the anchor, so
// dnsplan.Contains passes it and no later check objects. Two things go wrong
// quietly instead: the caller has chosen the SHAPE of a name rather than one
// label, authority this design does not give it, and `*.example.net` matches
// exactly one label, so the app would be handed a hostname the wildcard does not
// route and would simply never serve — a bug with no error in it.
//
// It must equally be unable to spell `_acme-challenge`, `_cf-custom-hostname`,
// `_mirrorstack-challenge` or `_dmarc`: those owners already mean something to a
// certificate authority, to Cloudflare, or to a mail receiver.
//
// Case is folded; DNS is case-insensitive. Nothing else is repaired, because a
// repaired slug is a hostname nobody typed.
func ValidateSlug(s string) (string, error) {
	folded := strings.ToLower(s)
	if strings.Contains(folded, ".") {
		return "", fmt.Errorf("%w: a slug is one label, not a name: %q", ErrInvalid, Echo(folded))
	}
	if reason := labelReason(folded); reason != "" {
		return "", fmt.Errorf("%w: a slug must be one LDH label, got %s: %q", ErrInvalid, reason, Echo(folded))
	}
	return folded, nil
}

// labelReason reports why one DNS label is unacceptable, or "" when it is fine.
// It expects a lowercased label — both callers fold first — since an uppercase
// byte would otherwise be reported as a character outside LDH.
func labelReason(label string) string {
	switch {
	case label == "":
		// A leading dot, a trailing dot and a doubled dot all arrive here, as an
		// empty label between separators. No such name exists in DNS.
		return "an empty label"
	case len(label) > maxLabel:
		return fmt.Sprintf("a label over %d bytes", maxLabel)
	case strings.Contains(label, "*"):
		// A wildcard is a name this service DERIVES — lane 2's `*.<anchor>`, after
		// a proof at that anchor. A caller able to spell one could ask for a record
		// covering every name in the zone.
		return "a wildcard label"
	case strings.Contains(label, "_"):
		// Underscore labels are where the protocols live: _acme-challenge,
		// _cf-custom-hostname, _dmarc, _mirrorstack-challenge. See ValidateSlug.
		return "an underscore label"
	case label[0] == '-':
		return "a label starting with a hyphen"
	case label[len(label)-1] == '-':
		return "a label ending with a hyphen"
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			// Everything else, every non-ASCII byte included. See ValidateDomain on
			// why an A-label is the customer's to supply.
			return "a character outside letters, digits and hyphen"
		}
	}
	return ""
}

// allDigits reports whether every byte of a non-empty label is a decimal digit.
func allDigits(label string) bool {
	if label == "" {
		return false
	}
	for i := 0; i < len(label); i++ {
		if label[i] < '0' || label[i] > '9' {
			return false
		}
	}
	return true
}

// Echo bounds what a refusal quotes back: input is untrusted in size as well as
// content, and an error string gets copied, logged, and copied again. Truncating
// may split a UTF-8 rune; %q renders the stray byte honestly, as an escape.
//
// Exported because internal/derive and internal/consent quote refusals from the
// same untrusted input and had a verbatim copy each.
func Echo(s string) string {
	const max = 64
	if len(s) > max {
		return s[:max] + "…(truncated)"
	}
	return s
}
