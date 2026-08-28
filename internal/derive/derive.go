// Package derive turns an intent — a lane, an identity and a domain — into the
// exact set of DNS records this service will write into a customer's zone, and
// the one record it will not.
//
// 🔴 THIS IS THE PACKAGE THE REBUILD EXISTS FOR. The API being replaced took
// `Publish(records)`: containment (internal/dnsplan) bounds a record's NAME and
// nothing bounds its VALUE, so with every check here passing the private half
// could aim a customer's own session host at somebody else's origin, or hand a
// stranger a publicly-trusted certificate for the customer's hostname by
// publishing a third party's ACME token — which the never-replace rule cannot
// stop, because TXT records always ADD beside each other and a CA accepts any of
// several at one owner. docs/DESIGN.md §1.
//
// Afterwards the private half names a domain and an intent and cannot name a
// record: every value reaching a customer's zone is computed below, relayed
// verbatim from AWS or Cloudflare by internal/relay, or published by the
// customer. Nothing here touches a provider, a resolver, a database or the
// network, and nothing holds a key — the proof's VALUE comes from internal/proof
// — so the whole answer to "what will MirrorStack put in my zone" is readable
// and testable without a Cloudflare account.
//
// docs/DESIGN.md §6 is the record table this implements; docs/RECORDS.md says
// what each row does and what deleting it breaks.
package derive

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/proof"
)

// ErrDerive is the single refusal this package returns. ONE error at the
// boundary, as in dnsplan and lane: every check is errors.Is(err, ErrDerive), so
// a refusal added later cannot slip past a caller that switched on the sentinels
// it knew. The cause travels in the wrapped text.
var ErrDerive = errors.New("derive: cannot derive a plan")

// ErrConfig is the deployment-configuration refusal: this process has not been
// told what a derived record should point at. It WRAPS ErrDerive, as
// dnsplan.ErrAnchorEscape wraps dnsplan.ErrPlanInvalid, so the boundary check
// stays one answer while an operator can still tell their own misconfiguration
// from a malformed request out of the private half.
var ErrConfig = fmt.Errorf("%w: the deployment's routing configuration is incomplete", ErrDerive)

// Purpose is why a record is in a plan: customer-facing, not internal
// bookkeeping — what a console renders beside each row and what `describe`
// reports. The vocabulary is closed and deliberately small.
type Purpose string

const (
	// PurposeOwnership is record 1: the TXT proving the customer controls the
	// anchor. One per registration, at the anchor, never published by us.
	PurposeOwnership Purpose = "ownership"

	// PurposeRouting is records 2, 3 and 4: the CNAMEs that carry traffic, and
	// the only kind a browser ever follows. Deleting one takes that hostname down
	// immediately and visibly; deleting any other row here fails later, quietly,
	// or not at all. A console must not render all five kinds identically.
	PurposeRouting Purpose = "routing"

	// PurposeCertACM is record 5: the CNAME validating an AWS certificate. Lane 1
	// only; its value is a token AWS chooses, relayed rather than derived and
	// absent until AWS has answered.
	PurposeCertACM Purpose = "acm"

	// PurposeCertDCV is record 6: the pointer at Cloudflare's delegated DCV
	// location. Derived here, carries no token, never changes. See DCVTarget.
	PurposeCertDCV Purpose = "dcv"

	// PurposeServing is record 7: Cloudflare's second, separate proof, read by
	// the edge before it will route a name. Relayed, never derived. Its absence
	// is a 526 while the certificate reads healthy, hence its own purpose.
	PurposeServing Purpose = "serving"
)

// Source is WHO writes a record. It is the safety property of this package.
type Source string

const (
	// SourceDerived is computed here from the lane, the anchor and this
	// deployment's configuration. Every byte of it is in this file.
	SourceDerived Source = "derived"

	// SourceRelayed is read from AWS or Cloudflare under MirrorStack's OWN
	// credentials and republished verbatim (internal/relay): this service derives
	// THAT a proof must exist and WHY, not its bytes. It gets no shortcut for
	// coming from somewhere trusted — same containment, same never-delete rule.
	SourceRelayed Source = "relayed"

	// SourceCustomer is published by the customer, by hand, in their own zone.
	//
	// 🔴 A SourceCustomer RECORD IS NEVER PUBLISHED BY THIS SERVICE, AND THAT IS
	// THE FIX FOR THE UNPROVEN ANCHOR. The ownership proof — the only such record
	// today — used to sit inside the set we published, gated on a public lookup
	// of that same record, so the proof was satisfied by our own write. Marking
	// the source beats special-casing one name at each publish site: the property
	// survives a second record ever needing it.
	SourceCustomer Source = "customer"
)

// Item is one record in a plan, with what a person needs to decide whether they
// are willing to have it in their zone.
type Item struct {
	// Record is exactly what is written, or exactly what the customer is asked to
	// write. No second representation for the manual path, so the hand-published
	// list and the list this service reasons about cannot drift.
	Record dnsplan.Record

	// Purpose and Source: what is it for, and who put it there.
	Purpose Purpose
	Source  Source

	// Host is the hostname this record SERVES, not the record's own name:
	// `_acme-challenge.api.example.com` serves `api.example.com`. A console
	// groups by it. Empty for the ownership proof, anchored above every host.
	Host string

	// Explain is one sentence a customer's developer reads to know why the row is
	// here and what breaks if they delete it. It names the CONSEQUENCE and says
	// WHEN — "immediately" and "silently, months from now" are different risks.
	Explain string
}

// Plan is everything one intent produces.
//
// 🔴 THE ITEM ORDER IS FIXED BY CONSTRUCTION, AND THAT IS LOAD-BEARING. The plan
// digest (dnsplan.Snapshot.Digest) is computed over the record list in order,
// shown to the customer BEFORE they authorize and re-checked before any write; a
// map iteration here would digest differently on the next pass and tell a
// customer, mid-consent, that the plan changed. internal/relay sorts its own
// output for the same reason, so a caller merging the two must append.
type Plan struct {
	// Lane this plan was derived for. Two lanes on one domain are two
	// registrations with two different proofs.
	Lane lane.Lane

	// Anchor is the name the customer proved, and the bound on every record
	// below. Normalized: lowercased, no trailing root dot.
	Anchor string

	// Hosts are the hostnames this plan serves, in the order lane.Hosts derives
	// them. On lane 2 that is the single wildcard `*.<anchor>`.
	Hosts []string

	// Items are the records: ownership, routing, then certificate pointers.
	// Records 5 and 7 are relayed, merged in by the caller.
	Items []Item
}

// Publishable returns the records this service may write, in plan order.
//
// 🔴 IT IS AN ALLOW-LIST, NOT "EVERYTHING EXCEPT THE CUSTOMER'S". A Source added
// later is publishable by default under an exclusion and is not here; the
// unfamiliar case must fail toward not writing a record nobody decided to write.
//
// The result is a fresh slice the caller may append relayed records to before
// dnsplan.NewSnapshot re-checks containment on the whole set. Nothing here
// trusts this function to be the only check.
func (p Plan) Publishable() []dnsplan.Record {
	out := make([]dnsplan.Record, 0, len(p.Items))
	for _, item := range p.Items {
		switch item.Source {
		case SourceDerived, SourceRelayed:
			out = append(out, item.Record)
		}
	}
	return out
}

// Manual returns the items the customer must publish themselves.
//
// 🔴 THIS IS NOT THE `manual` OUTCOME IN docs/DESIGN.md §3, which hands the
// customer the WHOLE record set, Publishable() included. This is the strictly
// smaller half: what this service will not write EVEN WHEN it holds a live
// grant. A degraded response built from Manual() alone would tell somebody to
// add one TXT record and leave their app unrouted.
func (p Plan) Manual() []Item {
	out := make([]Item, 0, len(p.Items))
	for _, item := range p.Items {
		if item.Source == SourceCustomer {
			out = append(out, item)
		}
	}
	return out
}

// Config is the deployment's routing vocabulary: what a derived record POINTS
// AT, as opposed to what it is called.
//
// A struct rather than package constants, because a staging deployment points
// elsewhere and because `capabilities` publishes these, so a customer reads the
// exact targets BEFORE authorizing. None of it is secret: a customer sees every
// value in their zone the moment anything is written.
type Config struct {
	// OrgRoutingTarget is record 2's value: what the four platform siblings on
	// lane 1 point at.
	OrgRoutingTarget string

	// AppRoutingTarget is records 3 and 4's value: what lane 2's wildcard and
	// lane 3's single hostname point at.
	//
	// Separate from OrgRoutingTarget because the two are separate Cloudflare
	// zones with separate custom-hostname configurations. A host pointed at the
	// wrong one is not a custom hostname in the zone it reaches: it resolves and
	// then is not served, a failure whose DNS looks perfect.
	AppRoutingTarget string

	// DCVDelegationUUID is the middle label of record 6's value: the per-zone
	// identifier Cloudflare gives for delegated certificate validation, one value
	// covering every custom hostname under one of our SaaS zones. Despite its
	// name, the observed values are 16 hexadecimal characters rather than a
	// 36-character UUID, so it is validated as one DNS label. See DCVTarget.
	DCVDelegationUUID string

	// ReservedSuffixes are the names nobody may connect: MirrorStack's own. A
	// name under one has no customer at the other end — the ownership proof for
	// it would be published by us, the defect docs/DESIGN.md §1 exists to remove,
	// and the customer-grant write path would have become a platform-zone editor.
	// Validate refuses an EMPTY list rather than reading it as "reserve nothing":
	// a guard that silently protects nothing while reading like protection is
	// worse than no guard. reserved() folds both routing targets in as well,
	// since connecting the name a routing CNAME points at would publish a loop.
	ReservedSuffixes []string
}

const (
	// defaultOrgRoutingTarget and defaultAppRoutingTarget are MirrorStack's
	// production edge names, defaulted here so this repository and the private
	// half cannot silently disagree about what belongs in a customer's zone. An
	// unset variable is therefore not a safe no-op: a deployment that must NOT
	// point at production has to say so, the alternative being a derived record
	// with an empty value.
	defaultOrgRoutingTarget = "connect.mirrorstack.ai"
	defaultAppRoutingTarget = "connect.mirrorstack.app"

	orgRoutingTargetEnv  = "CF_SAAS_ORG_TARGET"
	appRoutingTargetEnv  = "CF_SAAS_TARGET"
	dcvDelegationUUIDEnv = "CF_ORG_DCV_DELEGATION_UUID"
	reservedSuffixesEnv  = "MS_RESERVED_DOMAIN_SUFFIXES"
)

// platformSuffixes are MirrorStack's own registrable domains, reserved
// unconditionally: no deployment, staging included, has any business accepting
// `mirrorstack.ai` as a customer's domain. The environment may add to the list;
// it cannot remove these.
var platformSuffixes = []string{"mirrorstack.ai", "mirrorstack.app"}

// ConfigFromEnv reads the deployment's routing vocabulary from the environment.
//
//	CF_SAAS_ORG_TARGET           record 2's value      (default above)
//	CF_SAAS_TARGET               records 3 and 4       (default above)
//	CF_ORG_DCV_DELEGATION_UUID   record 6's uuid half  (no default)
//	MS_RESERVED_DOMAIN_SUFFIXES  extra reserved names  (added to the hardcoded pair)
//
// The uuid has no default on purpose: empty is a truthful "this deployment has
// not been told", which Validate turns into a refusal rather than a record
// pointing at `.dcv.cloudflare.com` with a missing label. It should come from
// `GET /zones/{our_zone}/dcv_delegation/uuid` against MirrorStack's own zone,
// not from somebody's memory of the dashboard. Unlike shared/config.MustEnv this
// never exits, so Validate names the unset value as an error at the call site
// rather than as a process that died at boot.
func ConfigFromEnv() Config {
	return Config{
		OrgRoutingTarget:  envOr(orgRoutingTargetEnv, defaultOrgRoutingTarget),
		AppRoutingTarget:  envOr(appRoutingTargetEnv, defaultAppRoutingTarget),
		DCVDelegationUUID: strings.TrimSpace(os.Getenv(dcvDelegationUUIDEnv)),
		ReservedSuffixes: append(append([]string(nil), platformSuffixes...),
			splitSuffixes(os.Getenv(reservedSuffixesEnv))...),
	}
}

// Validate reports whether this deployment can derive anything at all. Every
// entry point below calls it first, so an unconfigured process refuses at the
// boundary: dnsplan.NormalizeRecords would catch an empty derived value only
// after a lane, an anchor and possibly a credential were resolved, and would
// name a record rather than the missing setting.
func (c Config) Validate() error {
	if err := validateTarget("org routing target", orgRoutingTargetEnv, c.OrgRoutingTarget); err != nil {
		return err
	}
	if err := validateTarget("app routing target", appRoutingTargetEnv, c.AppRoutingTarget); err != nil {
		return err
	}
	// The uuid becomes one label inside a DNS name, so the only shape that must
	// hold is "one LDH label" — lane.ValidateSlug, reused rather than copied,
	// since the looser of two copies is the one that matters. The length and
	// alphabet Cloudflare uses today are NOT pinned: an unverified 16-hex rule
	// would refuse a value Cloudflare itself handed us.
	if strings.TrimSpace(c.DCVDelegationUUID) == "" {
		return fmt.Errorf("%w: %s is not set, so no certificate pointer can be derived", ErrConfig, dcvDelegationUUIDEnv)
	}
	if _, err := lane.ValidateSlug(c.DCVDelegationUUID); err != nil {
		return fmt.Errorf("%w: %s must be one DNS label: %w", ErrConfig, dcvDelegationUUIDEnv, err)
	}
	if len(c.ReservedSuffixes) == 0 {
		return fmt.Errorf("%w: no reserved suffixes, so a MirrorStack name could be connected as a customer domain", ErrConfig)
	}
	for _, suffix := range c.ReservedSuffixes {
		if dnsplan.NormalizeName(suffix) == "" {
			return fmt.Errorf("%w: the reserved suffix list has an entry that normalizes to nothing", ErrConfig)
		}
	}
	return nil
}

// validateTarget checks one routing target. The reserved list is deliberately
// nil: a routing target IS a MirrorStack name and must not be refused for being
// one. That list refuses such names as somebody's domain to connect; this checks
// them as our own name to point at.
func validateTarget(what, env, target string) error {
	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("%w: the %s is empty (%s)", ErrConfig, what, env)
	}
	if _, err := lane.ValidateDomain(target, nil); err != nil {
		return fmt.Errorf("%w: the %s is not a DNS name (%s): %w", ErrConfig, what, env, err)
	}
	return nil
}

// reserved is the effective reserved list: the configured suffixes plus both
// routing targets, which matters for a deployment whose edge lives outside the
// hardcoded MirrorStack suffixes. Only ever called after Validate, which is what
// guarantees neither target is empty here; an empty entry would make
// lane.ValidateDomain refuse every domain.
func (c Config) reserved() []string {
	out := make([]string, 0, len(c.ReservedSuffixes)+2)
	out = append(out, c.ReservedSuffixes...)
	return append(out, c.OrgRoutingTarget, c.AppRoutingTarget)
}

// Registration derives the plan one registration intent returns: record 1, the
// lane's routing record or records, and record 6 where the lane has one.
//
// Records 5 and 7 are absent because they do not EXIST yet — AWS has not been
// asked for a certificate, Cloudflare has not been asked for a custom hostname.
// The caller merges them in from internal/relay later; a plan that pretended to
// know them would have invented bytes in it.
//
// identity is validated and then used in no derived byte, deliberately:
// internal/proof refuses the same malformed identities when it computes
// proofValue, so accepting one here that proof rejects would produce a plan
// whose ownership row can never be filled. proofValue itself comes from
// internal/proof because this package holds no key.
func (c Config) Registration(l lane.Lane, identity, anchor, proofValue string) (Plan, error) {
	if err := c.Validate(); err != nil {
		return Plan{}, err
	}
	parsed, err := lane.Parse(string(l))
	if err != nil {
		return Plan{}, fmt.Errorf("%w: %w", ErrDerive, err)
	}
	if _, err := lane.ValidateIdentity(identity); err != nil {
		return Plan{}, fmt.Errorf("%w: %w", ErrDerive, err)
	}
	anchor, err = lane.ValidateDomain(anchor, c.reserved())
	if err != nil {
		return Plan{}, fmt.Errorf("%w: %w", ErrDerive, err)
	}
	proofValue = strings.TrimSpace(proofValue)
	if proofValue == "" {
		// The value's SHAPE is not checked: that would assert internal/proof's
		// encoding without a key to verify anything. Empty is different — the one
		// value producing a record no customer can act on, and what a caller that
		// skipped the proof hands over.
		return Plan{}, fmt.Errorf("%w: no ownership proof value for the anchor", ErrDerive)
	}
	hosts := parsed.Hosts(anchor)
	if len(hosts) == 0 {
		// Unreachable today, and retained: it is the guard a fourth lane added to
		// Parse and forgotten in Hosts would trip. The alternative is a
		// registration that publishes only an ownership proof and reports success.
		return Plan{}, fmt.Errorf("%w: lane %q derives no hostname under %q", ErrDerive, parsed, echo(anchor))
	}

	ownership, err := ownershipItem(anchor, proofValue)
	if err != nil {
		return Plan{}, err
	}
	items := []Item{ownership}
	switch parsed {
	case lane.OrgPlatformDomain:
		// Four siblings, one routing CNAME each, and a certificate pointer for
		// every one INCLUDING cdn. The cdn asymmetry is about record 5, not 6: a
		// content host is terminated before the request reaches AWS, so it is owed
		// no AWS validation record — but it is still a Cloudflare custom hostname
		// needing the same delegated validation.
		for _, host := range hosts {
			items = append(items, routingItem(host, c.OrgRoutingTarget, fmt.Sprintf(
				"Points %s at MirrorStack. This is the only record here a browser follows, so deleting it takes that hostname down immediately.",
				host)))
		}
		for _, host := range hosts {
			item, err := dcvItem(host, c.DCVDelegationUUID)
			if err != nil {
				return Plan{}, err
			}
			items = append(items, item)
		}

	case lane.OrgAppDomain:
		// One wildcard and no certificate pointer: no host to derive one for yet,
		// and `_acme-challenge.*.example.net` is not a name anybody can publish.
		// Each app's pointer is minted per app, at deploy time, by BindApp.
		items = append(items, routingItem(hosts[0], c.AppRoutingTarget, fmt.Sprintf(
			"Routes every app you deploy at <app>.%s through MirrorStack. A wildcard answers only names your zone holds no record of its own for, so everything you already publish keeps resolving exactly as it does today; deleting it takes every app on this domain down at once.",
			anchor)))

	case lane.AppDomain:
		// The anchor itself is the host — the tightest of the three lanes, nothing
		// derived beneath it and nothing beside it reachable. When the anchor is a
		// registrable domain this is a CNAME at a zone apex, servable only by a
		// provider that flattens one; that refusal comes from the customer's
		// provider rather than being pre-judged here.
		items = append(items, routingItem(anchor, c.AppRoutingTarget, fmt.Sprintf(
			"Points %s at MirrorStack. This is the only record here a browser follows, so deleting it takes the site down immediately.",
			anchor)))
		item, err := dcvItem(anchor, c.DCVDelegationUUID)
		if err != nil {
			return Plan{}, err
		}
		items = append(items, item)
	}

	return newPlan(parsed, anchor, hosts, items)
}

// BindApp derives what ONE app owes under an org app domain, at deploy time.
//
// 🔴 A WILDCARD MATCHES EXACTLY ONE LABEL, AND THAT IS THE WHOLE REASON THIS
// FUNCTION EXISTS. `*.example.net` covers `blog.example.net` and NOT
// `_acme-challenge.blog.example.net`, so lane 2's single routing record routes
// every app the org will ever deploy while every app still owes a certificate
// record no wildcard can supply. A wildcard CUSTOM HOSTNAME would remove the
// need; it is Enterprise-only on the account this runs against.
//
// It derives record 6 and nothing else. No ownership proof: the parent's covers
// every name beneath the anchor, and a second per app would make deploying an
// app a manual DNS step, forever. No routing record: the wildcard already routes
// this app. Record 7 is relayed by internal/relay and merged in by the caller.
//
// parentAnchor comes from the org's sealed registration; slug is the app's — the
// one caller-chosen string anywhere in this design. It selects WHICH name under
// an already-proven parent, never WHAT is written there, and lane.ValidateSlug
// keeps it from spelling `_acme-challenge`, a dot, or `*`.
func (c Config) BindApp(parentAnchor, slug string) (Plan, error) {
	if err := c.Validate(); err != nil {
		return Plan{}, err
	}
	anchor, err := lane.ValidateDomain(parentAnchor, c.reserved())
	if err != nil {
		return Plan{}, fmt.Errorf("%w: %w", ErrDerive, err)
	}
	slug, err = lane.ValidateSlug(slug)
	if err != nil {
		return Plan{}, fmt.Errorf("%w: %w", ErrDerive, err)
	}
	host := slug + "." + anchor
	item, err := dcvItem(host, c.DCVDelegationUUID)
	if err != nil {
		return Plan{}, err
	}
	return newPlan(lane.OrgAppDomain, anchor, []string{host}, []Item{item})
}

const (
	// dcvPrefix is the owner a certificate authority looks up. The trailing dot is
	// inside the constant so no call site has to remember a separator — the
	// version of that bug which ships silently produces
	// `_acme-challengeapi.example.com`.
	dcvPrefix = "_acme-challenge."

	// dcvDelegationZone is where Cloudflare keeps the real, rotating tokens: in
	// its own zone, not in the customer's.
	dcvDelegationZone = "dcv.cloudflare.com"
)

// DCVTarget is record 6's value: where a certificate authority is sent to find
// the token for host.
//
//	_acme-challenge.<host>  CNAME  <host>.<uuid>.dcv.cloudflare.com
//
// The most consequential derivation in the package, for the reasons
// docs/DESIGN.md §6 gives: the record carries NO token and both halves are known
// up front, so it is publishable on the FIRST pass and never changes again —
// which is what lets lanes 1 and 3 hold a credential for 24 hours, not forever.
//
// 🔴 THE HOSTNAME PREFIX IS LOAD-BEARING, AND api-platform DISAGREES.
//
// Cloudflare documents the target as `<host>.<uuid>.dcv.cloudflare.com`, the
// hostname being the per-host namespace it writes its rotating TXT records into.
// Without the prefix every host delegated to one of our zones collides on a
// single name, and a CA following the pointer reads somebody else's token or
// nothing. api-platform's dcvDelegationTarget omits it. This file follows
// docs/DESIGN.md §6 — the merged public spec, which matches Cloudflare's docs —
// and the disagreement is recorded rather than resolved because the other half is
// a change in another repository.
//
// 🔴 UNVERIFIED AGAINST A LIVE DASHBOARD as of 2026-08-28. Nobody has read
// `GET /zones/{our_zone}/dcv_delegation/uuid` with our own token; the uuid in use
// is a hand-set environment variable. The one live probe on record — four custom
// hostnames stuck at `pending_validation` "with the delegation CNAME in place and
// resolving" — published the PREFIX-LESS target and concluded delegation was not
// in effect. It cannot distinguish that from a pointer aimed at a name Cloudflare
// never writes to, so "delegation does not work here" is open until re-measured
// with the form above. A reader of this repository is owed that uncertainty.
//
// Returns "" rather than a target that cannot be right, for proof.Name's reason:
// only the empty value fails loudly. The uuid's SHAPE is Config.Validate's.
func DCVTarget(host, uuid string) string {
	host = dnsplan.NormalizeName(host)
	uuid = dnsplan.NormalizeName(uuid)
	if host == "" || uuid == "" {
		return ""
	}
	target := host + "." + uuid + "." + dcvDelegationZone
	if len(target) > dnsplan.MaxDNSName {
		return ""
	}
	return target
}

// ownershipItem is record 1. See internal/proof for the value, and for why this
// service is deliberately unable to publish this row.
//
// It refuses an anchor too deep to carry the challenge name: the proof sits one
// 23-byte label above the anchor, so an anchor over 230 bytes has nowhere to put
// it. That bound is the customer's domain, not ours, and separate from dcvItem's
// pointer bound. Refusing with the cause named beats deriving an empty owner
// name, which a provider creates at the ZONE APEX.
func ownershipItem(anchor, value string) (Item, error) {
	if proof.Name(anchor) == "" {
		return Item{}, fmt.Errorf("%w: %q is too deep to carry an ownership proof at %s<anchor>",
			ErrDerive, echo(anchor), proof.Prefix)
	}
	return Item{
		Record: dnsplan.Record{
			Type:  "TXT",
			Name:  proof.Name(anchor),
			Value: value,
			// Meaningless for a TXT — the orange cloud applies to a hostname — but
			// stated so "grey on purpose" is distinguishable from "nobody decided".
			Proxied: false,
		},
		Purpose: PurposeOwnership,
		Source:  SourceCustomer,
		Host:    "",
		Explain: fmt.Sprintf(
			"Proves you control %s. MirrorStack cannot publish this one — a proof we write ourselves proves nothing — and deleting it stops every write from this service within one pass.",
			anchor),
	}, nil
}

// routingItem is records 2, 3 and 4: the CNAME that carries traffic for one name.
//
// 🔴 Proxied IS FALSE ON EVERY RECORD THIS PACKAGE DERIVES, AND IT IS NOT AN
// UNCONSIDERED DEFAULT. The proxy decision belongs to MirrorStack's private half
// and applies only inside MirrorStack's own zones. A record in a CUSTOMER's zone
// flipped to proxied would be flattened at THEIR edge: the name answers with
// addresses instead of following the delegation, the request never reaches our
// zone, and issuance — or a renewal months later — fails with every dashboard on
// both sides green. Cloudflare accepts `proxied: true` here without an error,
// which is what makes it silent rather than a rejected write.
func routingItem(host, target, explain string) Item {
	return Item{
		Record:  dnsplan.Record{Type: "CNAME", Name: host, Value: target, Proxied: false},
		Purpose: PurposeRouting,
		Source:  SourceDerived,
		// A routing record serves the name it IS.
		Host:    host,
		Explain: explain,
	}
}

// dcvItem is record 6 for one host.
//
// The two ways a pointer can fail to exist have different people behind them, so
// they are different refusals. A missing uuid is the operator's and cannot reach
// here through a validated Config. A target over the DNS wire limit is the
// request's — a deep anchor plus a long slug — and no shortening keeps the
// pointer pointing anywhere. Refusing the whole plan beats leaving a hostname
// routed to MirrorStack with a certificate that can never validate.
func dcvItem(host, uuid string) (Item, error) {
	target := DCVTarget(host, uuid)
	if target == "" {
		if strings.TrimSpace(uuid) == "" {
			return Item{}, fmt.Errorf("%w: %s is not set, so no certificate pointer can be derived",
				ErrConfig, dcvDelegationUUIDEnv)
		}
		return Item{}, fmt.Errorf("%w: the certificate pointer for %q would be over the %d-byte DNS limit",
			ErrDerive, echo(host), dnsplan.MaxDNSName)
	}
	return Item{
		Record: dnsplan.Record{
			Type: "CNAME",
			Name: dcvPrefix + host,
			// Proxied stays false here for a sharper reason: an owner starting with
			// an underscore is read directly by a certificate authority, and
			// proxying it replaces the delegation with addresses. See routingItem.
			Value:   target,
			Proxied: false,
		},
		Purpose: PurposeCertDCV,
		Source:  SourceDerived,
		Host:    host,
		Explain: fmt.Sprintf(
			"Delegates certificate validation for %s to Cloudflare, which mints and rotates the real tokens behind it. It carries no token of its own and never changes; deleting it breaks TLS at a renewal months from now, silently.",
			host),
	}, nil
}

// newPlan is the last gate before a plan leaves this package.
//
// 🔴 EVERY DERIVED RECORD IS CHECKED HERE EVEN THOUGH dnsplan.NewSnapshot WILL
// CHECK IT AGAIN. Catching a derivation bug at the point of derivation names the
// DEFECT — this lane, this label table, this concatenation — where catching it
// two packages later names only the symptom. dnsplan's copy is the boundary a
// hostile caller cannot get past; this copy tells whoever broke it what they
// broke.
func newPlan(l lane.Lane, anchor string, hosts []string, items []Item) (Plan, error) {
	for _, item := range items {
		if err := checkItem(anchor, item); err != nil {
			return Plan{}, err
		}
	}
	return Plan{Lane: l, Anchor: anchor, Hosts: hosts, Items: items}, nil
}

// checkItem re-derives, from the finished record, every property this package
// claims about what it produces.
func checkItem(anchor string, item Item) error {
	record := item.Record
	// The vocabulary is closed: CNAME and TXT. No A, AAAA, MX, NS or CAA, ever.
	// An A record points a customer's hostname at an address outliving any
	// deployment we control; an NS or a CAA moves authority for a name, or decides
	// which CA may issue for it, in a zone we were lent a token for.
	if record.Type != "CNAME" && record.Type != "TXT" {
		return fmt.Errorf("%w: derived a %q record, and the vocabulary is CNAME and TXT",
			ErrDerive, echo(record.Type))
	}
	if record.Name == "" || record.Value == "" {
		// Empty is the dangerous half-formed case: a provider handed an empty owner
		// name creates a record at the ZONE APEX.
		return fmt.Errorf("%w: derived an incomplete %s record for %q", ErrDerive, record.Type, echo(anchor))
	}
	if len(record.Name) > dnsplan.MaxDNSName {
		return fmt.Errorf("%w: derived a %d-byte name, over the %d-byte DNS limit",
			ErrDerive, len(record.Name), dnsplan.MaxDNSName)
	}
	if record.Name != dnsplan.NormalizeName(record.Name) {
		// Derived names are normalized by construction. One that is not means a
		// caller's spelling reached a record verbatim, and two spellings of one
		// name digest differently on the next pass.
		return fmt.Errorf("%w: derived a name that is not normalized: %q", ErrDerive, echo(record.Name))
	}
	if record.Proxied {
		return fmt.Errorf("%w: derived a proxied record for %q, and a customer-zone record is never proxied",
			ErrDerive, echo(record.Name))
	}
	if !dnsplan.Contains(anchor, record.Name) {
		slog.Error("derive: refusing a plan that names something outside its anchor",
			"anchor", anchor, "record", record.Name, "purpose", item.Purpose)
		return fmt.Errorf("%w: %q is not at or under %q", ErrDerive, echo(record.Name), echo(anchor))
	}
	if item.Purpose == "" || item.Source == "" || item.Explain == "" {
		// A row with no purpose, source or explanation is one a customer is asked
		// to accept with nothing to accept it on.
		return fmt.Errorf("%w: derived an unlabelled record for %q", ErrDerive, echo(record.Name))
	}
	return nil
}

// envOr reads one variable, falling back to a default when it is unset or blank.
func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// splitSuffixes parses the extra reserved suffixes out of one environment
// variable. Commas, semicolons and whitespace all separate: splitting on
// whitespace alone would keep the comma inside the first entry and produce a
// suffix that matches no name at all — protection that reads like protection and
// silently is not. That silence is the only reason this function repairs input;
// nothing else in this service does.
func splitSuffixes(raw string) []string {
	return strings.Fields(strings.NewReplacer(",", " ", ";", " ").Replace(raw))
}

// echo bounds what a refusal quotes back, for the reason lane.echo gives: an
// error string is somewhere a value is copied, logged, and copied again.
func echo(s string) string {
	const max = 64
	if len(s) > max {
		return s[:max] + "…(truncated)"
	}
	return s
}
