// Package lane names the three ways a customer domain can reach MirrorStack, and
// holds the rules every other package in this service validates against.
//
// A lane is not a label. It decides which kind of identity a request carries,
// which hostnames are derived under the anchor, how long a credential may be
// held — and it is an input to the ownership proof the customer publishes, so two
// lanes are two different proofs and a proof for one authorizes nothing on
// another. Making that one small package is what keeps the answer to "which of
// these three am I doing" from being re-decided, differently, in five places.
//
// Nothing here talks to a DNS provider, a database or the network. It is pure
// data and pure rules, so the bounds this service claims can be read, and tested,
// without a Cloudflare account. See docs/DESIGN.md §2 for the lane table and
// docs/RECORDS.md for the records each lane produces.
package lane

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
)

// ErrInvalid is the single refusal this package returns.
//
// Deliberately ONE error at the boundary, for the same reason dnsplan has one:
// every caller's check is then identical — errors.Is(err, ErrInvalid) — and a
// refusal added here later cannot slip past a caller that switched on the set of
// sentinels it happened to know about. The specific cause travels in the wrapped
// message, where logs and tests can read it, and never as a sibling sentinel a
// caller could branch on. There is nothing for a caller to branch on anyway: the
// answer to every refusal below is that the request is malformed.
var ErrInvalid = errors.New("lane: invalid")

// maxLabel is the DNS wire limit for one label. A hostname may be 253 bytes
// (dnsplan.MaxDNSName) but no single label may exceed 63.
const maxLabel = 63

// Lane is one of exactly three ways a domain reaches MirrorStack.
//
// There is no fourth and there is no default. An unrecognised value is refused
// rather than resolved, because a defaulted lane would pick a record set, an
// identity kind and a grant lifetime that the customer never consented to — and
// it would do it silently, since every one of those three looks reasonable on
// its own.
type Lane string

const (
	// OrgPlatformDomain puts an org's MirrorStack console on a domain it owns.
	// The anchor is the domain and the footprint is the four siblings in
	// PlatformLabels — never the apex.
	OrgPlatformDomain Lane = "org_platform_domain"

	// OrgAppDomain is the parent under which every one of an org's apps is
	// auto-routed at <slug>.<anchor>, behind one wildcard. It is the only lane
	// whose grant is standing, because the records it exists to write belong to
	// apps that do not exist yet.
	OrgAppDomain Lane = "org_app_domain"

	// AppDomain is one arbitrary domain bound to one app.
	//
	// 🔴 THERE IS NO ORGANIZATION ON THIS LANE, AND THAT IS NOT AN OVERSIGHT.
	//
	// The owner may be a person. Any check that reaches for an org id here finds
	// nothing, and a check that reads "no org" as "no restriction" is an
	// authorization hole rather than a nil pointer. Identity() answers the
	// question once, here, so no caller has to assume it.
	AppDomain Lane = "app_domain"
)

// Parse accepts exactly the three lane strings and nothing else: no case
// folding, no trimming, no aliases.
//
// The lane is a byte string inside the ownership proof the customer publishes —
// HMAC(K, lane‖id‖anchor) — so it is a cryptographic input rather than a display
// value. It arrives from MirrorStack's own private half, where a second accepted
// spelling of one lane is a defect in the caller; being told so is more useful
// than having it guessed at, and cheaper than discovering later that one domain
// carries two valid proofs.
func Parse(s string) (Lane, error) {
	switch Lane(s) {
	case OrgPlatformDomain, OrgAppDomain, AppDomain:
		return Lane(s), nil
	}
	return "", fmt.Errorf("%w: unknown lane %q", ErrInvalid, echo(s))
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

// Identity reports what kind of id this lane's identity field carries.
//
// An unrecognised lane returns the empty kind, which equals neither constant, so
// a caller that skipped Parse cannot fall through into "org" by default. Lane 3
// is an APP id and may have no organization anywhere — see AppDomain.
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
// 🔴 THE CALLER CANNOT ADD A FIFTH LABEL OR RENAME ONE. THAT IS THE POINT OF IT
// BEING A TABLE HERE.
//
// Each label becomes a hostname inside the customer's own domain and a subject on
// a publicly-trusted certificate. A label supplied on a request would be a
// caller-chosen name, and this design has exactly one of those — the app slug,
// which selects a name under a parent already proven and is validated on its own
// (see ValidateSlug).
//
// `cdn` deliberately owns no AWS certificate record: a content host is terminated
// before the request ever reaches AWS, so it is owed no validation record there.
// That asymmetry lives with the record derivation; this is only the table.
//
// The honest limit: this is a package-level slice, so it is writable — by code in
// this repository and nowhere else, since the package is internal. Tests pin the
// four strings, so changing them fails a build rather than a customer's zone.
var PlatformLabels = []string{"account", "api", "apps", "cdn"}

// Hosts returns the hostnames this lane serves under anchor, in a fresh slice the
// caller may keep and mutate.
//
// 🔴 EVERY NAME RETURNED IS AT OR UNDER THE ANCHOR, BY CONSTRUCTION.
//
// dnsplan.Contains enforces that again before anything is published; deriving a
// name anywhere else would only move the refusal further downstream, into a code
// path that runs after a credential has been exchanged.
//
//   - OrgPlatformDomain — the four siblings from PlatformLabels, and NOT the
//     anchor itself. An org connecting example.com keeps serving its own website
//     at the apex; those four names are the entire footprint.
//   - OrgAppDomain — the single wildcard `*.<anchor>`. A wildcard answers only
//     names for which the zone holds no record of its own, so every host the
//     customer already publishes keeps resolving exactly as it did. The per-app
//     hostnames are not listed here and never need to be: the slug picks one and
//     the wildcard routes it, and only the app's certificate records are minted
//     per app, at deploy time.
//   - AppDomain — the anchor itself, and nothing beneath it. The tightest of the
//     three.
//
// The anchor is re-validated here rather than trusted, and an anchor that fails
// returns nil. A total function that answers nothing for a bad input is the
// legible behaviour: "account." + "" is a name under no anchor at all, and the
// caller that skipped validation would otherwise get four of them. The reserved
// suffix list is deliberately not consulted — Hosts derives, it does not admit,
// and a reserved check run here with an empty list would be the guard that
// silently protects nothing (see ValidateDomain).
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

// Standing is the grant lifetime of a lane whose credential is held with no fixed
// expiry. It is the zero duration, which is why GrantLifetime never returns zero
// for anything else.
const Standing = time.Duration(0)

// closedLaneLifetime is how long a credential is held on a lane whose record set
// is finite and fully known when the customer authorizes.
const closedLaneLifetime = 24 * time.Hour

// alreadyExpired is what an unrecognised lane gets. See GrantLifetime.
const alreadyExpired = -1 * time.Second

// GrantLifetime is how long a grant on this lane is held.
//
// Lanes 1 and 3 are CLOSED: their record sets are finite and known at the moment
// the customer authorizes, so the credential is held 24 hours and then gone. That
// is only possible because record 6 — `_acme-challenge.<host>` pointing at
// Cloudflare's delegated DCV location — carries no token and never changes, so
// nothing has to be republished on a certificate-renewal clock. Lane 2 is
// STANDING, because the records it exists to write belong to apps that do not
// exist yet; its expiry slides forward each time it publishes. docs/RECORDS.md
// says that is the trade to argue with hardest on this repository, and it is.
//
// 🔴 ZERO MEANS STANDING, SO AN UNRECOGNISED LANE MUST NEVER RETURN ZERO.
//
// It returns a negative duration instead. A caller that branches on Standing does
// not take the standing branch, and a caller that forgets to branch adds the
// duration to now and computes an expiry in the past — holding a grant that is
// already dead. There is no value this function can return that fails open, which
// is the property being bought: the dangerous answer here is also the default
// answer of a switch that forgot a case.
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
// any case, and returns it lowercased.
//
// Deliberately stricter than a general UUID parser, for dnsplan's reason: pgtype
// accepts braced and unhyphenated spellings, so "the same" id can arrive in
// several encodings. The id is inside the plan digest AND inside the ownership
// HMAC the customer publishes, so two encodings of one id are two digests and two
// proofs — a registration would quietly stop matching itself, and the customer
// would be told the plan changed.
//
// This function does not ask whether the org or app exists; that is api-platform's
// question and it holds the rows. All that is settled here is the spelling, which
// is why the nil UUID is accepted: it is canonical, and it names nothing.
//
// The rule is duplicated rather than shared because dnsplan's copy is unexported.
// Two copies of one rule drift, and the looser copy is the one that matters — so
// TestValidateIdentityMatchesDnsplanStrictness runs both over one table through
// dnsplan's exported surface and fails if they ever disagree.
func ValidateIdentity(s string) (string, error) {
	if len(s) != 36 {
		return "", fmt.Errorf("%w: identity is not a canonical uuid", ErrInvalid)
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return "", fmt.Errorf("%w: identity is not a canonical uuid", ErrInvalid)
			}
			continue
		}
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return "", fmt.Errorf("%w: identity is not a canonical uuid", ErrInvalid)
		}
	}
	return strings.ToLower(s), nil
}

// ValidateDomain accepts one DNS name and returns it normalized: lowercased, with
// surrounding space and the root dot removed.
//
// At most 253 bytes, at least two labels, every label LDH — letters, digits and
// hyphen, not starting or ending with a hyphen — no empty label, no wildcard, no
// underscore label, and no all-numeric rightmost label. An internationalized
// domain must arrive as its A-label (`xn--…`), which is already LDH: this service
// will not convert one for you, because silently rewriting a customer's domain
// produces a name they did not type and cannot recognise on a consent screen.
//
// The name validated here becomes the ANCHOR — the single bound on everything a
// delegated credential can ever reach — so the rules are about what can be
// proven and derived, not about what a resolver would tolerate. A single label
// is a TLD nobody can own, and an anchor there would make containment meaningless.
// An all-numeric rightmost label is an address wearing a domain's shape, and this
// service publishes no A or AAAA record and has nothing to say about an address.
//
// 🔴 A NAME AT OR UNDER A RESERVED SUFFIX IS REFUSED OUTRIGHT.
//
// A name under a MirrorStack suffix has no customer on the other end of it: the
// ownership proof would be published by us, which is exactly the defect
// docs/DESIGN.md §1 exists to remove. Refusing it here keeps the proof meaningful
// and keeps the customer-grant write path from being reused as a platform-zone
// editor. The suffix is matched with a leading dot (dnsplan.Contains), so a
// reserved "example.com" refuses "example.com" and "account.example.com" and does
// NOT refuse "evilexample.com" — a different domain that merely ends in the same
// letters. The match is one-directional: a name ABOVE a reserved suffix is not
// refused, because that is a domain somebody could genuinely own, and the
// ownership proof is what settles whether they do.
//
// An empty reserved list reserves nothing, and that is a decision the call site
// makes visibly. An entry that is PRESENT but normalizes to nothing is a
// different thing — someone intended protection and it evaporated — so it refuses
// every domain instead of quietly protecting none. A guard that protects nothing
// while reading like protection is worse than no guard at all.
func ValidateDomain(name string, reserved []string) (string, error) {
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
		return "", fmt.Errorf("%w: %q is a single label, not a domain", ErrInvalid, echo(normalized))
	}
	for _, label := range labels {
		if reason := labelReason(label); reason != "" {
			return "", fmt.Errorf("%w: %s in %q", ErrInvalid, reason, echo(normalized))
		}
	}
	if allDigits(labels[len(labels)-1]) {
		return "", fmt.Errorf("%w: %q has an all-numeric rightmost label", ErrInvalid, echo(normalized))
	}
	// The list is checked before it is used, so a malformed entry is reported
	// whichever domain happens to be under inspection. Checking it inline would
	// surface the config defect only for the names that matched nothing else —
	// which is to say, mostly not at all.
	suffixes := make([]string, 0, len(reserved))
	for _, entry := range reserved {
		suffix := dnsplan.NormalizeName(entry)
		if suffix == "" {
			slog.Error("lane: refusing every domain because the reserved-suffix list carries an entry that normalizes to nothing")
			return "", fmt.Errorf("%w: the reserved suffix list is malformed", ErrInvalid)
		}
		suffixes = append(suffixes, suffix)
	}
	for _, suffix := range suffixes {
		if dnsplan.Contains(suffix, normalized) {
			return "", fmt.Errorf("%w: %q is at or under the reserved suffix %q",
				ErrInvalid, echo(normalized), echo(suffix))
		}
	}
	return normalized, nil
}

// ValidateSlug accepts a single LDH label of at most 63 bytes and returns it
// lowercased.
//
// 🔴 THIS IS THE ONE CALLER-CHOSEN STRING ANYWHERE IN THIS DESIGN.
//
// Every other byte that reaches a customer's zone is derived here or relayed from
// AWS or Cloudflare. A slug selects WHICH name under a parent the customer has
// already proven — never WHAT is written there — so the only question this
// function has to answer is whether the caller picked a name or picked a shape.
//
// 🔴 A DOTTED SLUG DOES NOT ESCAPE THE ANCHOR, WHICH IS PRECISELY WHY IT HAS TO
// BE REFUSED HERE.
//
// "a.b" under example.net is a.b.example.net, which is still at or under the
// anchor: dnsplan.Contains passes it and no later check objects. Two things go
// wrong quietly instead. The caller has chosen the shape of a name rather than
// one label, which is authority this design does not give it. And `*.example.net`
// matches exactly one label, so the app would be handed a hostname the wildcard
// does not route and would simply never serve — a bug with no error in it.
//
// It must equally be unable to spell `_acme-challenge`, `_cf-custom-hostname`,
// `_mirrorstack-challenge` or `_dmarc`. Those owners already mean something to a
// certificate authority, to Cloudflare, or to a mail receiver, and a slug that
// could name one would let the caller aim a derived record at a name whose
// meaning it did not choose.
//
// Case is folded, because DNS is case-insensitive and folding is not a change of
// identity. Nothing else is repaired: no trimming, no substitution, no stripping
// of a stray dot. This is the one string a caller chooses, and a repaired slug is
// a hostname nobody typed.
func ValidateSlug(s string) (string, error) {
	folded := strings.ToLower(s)
	if strings.Contains(folded, ".") {
		return "", fmt.Errorf("%w: a slug is one label, not a name: %q", ErrInvalid, echo(folded))
	}
	if reason := labelReason(folded); reason != "" {
		return "", fmt.Errorf("%w: a slug must be one LDH label, got %s: %q", ErrInvalid, reason, echo(folded))
	}
	return folded, nil
}

// labelReason reports why one DNS label is unacceptable, or "" when it is fine.
//
// It expects a label that has already been lowercased — both callers fold first —
// because an uppercase byte would otherwise be reported as a character outside
// LDH, which is true and unhelpful.
func labelReason(label string) string {
	switch {
	case label == "":
		// A leading dot, a trailing dot and a doubled dot all arrive here, as an
		// empty label between two separators. No such name exists in DNS.
		return "an empty label"
	case len(label) > maxLabel:
		return fmt.Sprintf("a label over %d bytes", maxLabel)
	case strings.Contains(label, "*"):
		// A wildcard is a name this service DERIVES — lane 2's `*.<anchor>`, once,
		// after a proof at that anchor. A caller able to spell one could ask for a
		// record covering every name in the zone.
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

// echo bounds what a refusal quotes back at the caller.
//
// Caller input is untrusted in size as well as in content, and an error string is
// somewhere a value gets copied, logged, and copied again. Truncating may split a
// UTF-8 rune; %q renders the stray byte as an escape, which is honest about what
// arrived.
func echo(s string) string {
	const max = 64
	if len(s) > max {
		return s[:max] + "…(truncated)"
	}
	return s
}
