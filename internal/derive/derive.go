// Package derive turns an intent — a lane, an identity and a domain — into the
// exact set of DNS records this service will write into a customer's zone, and
// the one record it will not.
//
// 🔴 THIS IS THE PACKAGE THE REBUILD EXISTS FOR.
//
// The API being replaced took `Publish(records)`: every byte that reached a
// customer's zone came from a list MirrorStack's private half wrote. Anchor
// containment (internal/dnsplan) bounds a record's NAME to a suffix of the name
// the customer connected, and nothing anywhere bounds its VALUE. So reading this
// repository established WHERE we could write and nothing about WHAT — and a
// compromised, or merely mistaken, private half could publish
//
//	CNAME  account.example.com          →  attacker.example
//	TXT    _acme-challenge.example.com  →  a third party's ACME token
//
// with every check in this repository passing. The first puts a session host
// inside the customer's own domain in front of somebody else's origin. The
// second hands a stranger a publicly-trusted certificate for the customer's
// hostname, and the never-replace rule cannot stop it, because TXT records
// always ADD beside each other and a certificate authority accepts any matching
// TXT among several at one owner. Neither is a defect that better documentation
// fixes.
//
// Moving derivation here is the fix. Afterwards the private half names a domain
// and an intent and cannot name a record, and every value that can reach a
// customer's zone is one of exactly three things: computed by the code below,
// relayed verbatim from AWS or Cloudflare by internal/relay, or published by the
// customer themselves.
//
// Nothing here talks to a DNS provider, a resolver, a database or the network,
// and nothing here holds a key — the ownership proof's VALUE is computed in
// internal/proof and passed in, so this package can derive the plan and still be
// unable to mint the one record that authorizes it. It is a pure function of
// (lane, identity, anchor) and this deployment's routing configuration, which
// means the whole answer to "what will MirrorStack put in my zone" can be read,
// and tested, without a Cloudflare account.
//
// docs/DESIGN.md §6 is the record table this implements; docs/RECORDS.md is the
// customer-facing description of what each row does and what deleting it breaks.
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

// ErrDerive is the single refusal this package returns.
//
// Deliberately ONE error at the boundary, for the reason dnsplan and lane both
// give: every caller's check is then identical — errors.Is(err, ErrDerive) — and
// a refusal added here later cannot slip past a caller that switched on the set
// of sentinels it happened to know about. The specific cause travels in the
// wrapped text, where logs and tests read it.
var ErrDerive = errors.New("derive: cannot derive a plan")

// ErrConfig is the deployment-configuration refusal: this process has not been
// told what a derived record should point at.
//
// It WRAPS ErrDerive rather than sitting beside it, exactly as
// dnsplan.ErrAnchorEscape wraps dnsplan.ErrPlanInvalid. A caller checking the
// boundary keeps one answer, while an operator reading a log can tell the two
// audiences apart: ErrConfig is theirs to fix in the deployment, everything else
// is a malformed request from the private half.
var ErrConfig = fmt.Errorf("%w: the deployment's routing configuration is incomplete", ErrDerive)

// Purpose is why a record is in a plan.
//
// It is customer-facing rather than internal bookkeeping: it is what a console
// renders beside each row, what `describe` reports, and what somebody looking at
// their own zone sorts by while deciding which of these records they are willing
// to keep. The vocabulary is closed, and it is small on purpose — five kinds is
// a set a person can hold in their head while reading their own DNS.
type Purpose string

const (
	// PurposeOwnership is record 1: the TXT that proves the customer controls
	// the anchor. Exactly one per registration, at the anchor itself, and never
	// published by this service.
	PurposeOwnership Purpose = "ownership"

	// PurposeRouting is records 2, 3 and 4: the CNAMEs that carry traffic.
	//
	// 🔴 THE ONLY KIND A BROWSER EVER FOLLOWS. Every other record in a plan is
	// read by a certificate authority or by an edge. Deleting a routing record
	// takes that hostname down immediately and visibly; deleting any other row
	// here fails later, quietly, or not at all. A console that renders all five
	// kinds identically is telling a customer that one destructive action and
	// four harmless ones carry the same risk.
	PurposeRouting Purpose = "routing"

	// PurposeCertACM is record 5: the CNAME that validates an AWS certificate.
	// Lane 1 only, and its value is a token AWS chooses — relayed, never derived
	// here, and absent until AWS has answered.
	PurposeCertACM Purpose = "acm"

	// PurposeCertDCV is record 6: the pointer at Cloudflare's delegated DCV
	// location. Derived here, carries no token, and never changes again. See
	// DCVTarget.
	PurposeCertDCV Purpose = "dcv"

	// PurposeServing is record 7: Cloudflare's second, separate proof, read by
	// the edge before it will route a name. Relayed, never derived. Its absence
	// is a 526 while the certificate reads healthy, which is why it is its own
	// purpose rather than filed under a certificate.
	PurposeServing Purpose = "serving"
)

// Source is WHO writes a record. It is the safety property of this package
// rather than a label on it.
type Source string

const (
	// SourceDerived is computed here, from the lane, the anchor and this
	// deployment's configuration. Every byte of it is in this file.
	SourceDerived Source = "derived"

	// SourceRelayed is read from AWS or Cloudflare using MirrorStack's OWN
	// credentials and republished verbatim (internal/relay). This service
	// derives THAT the proof must exist and WHY; it cannot predict the bytes.
	// Saying so is more useful than a claim to derive everything, and a relayed
	// record gets no shortcut for having come from somewhere trusted — it passes
	// the same containment and the same never-delete rule.
	SourceRelayed Source = "relayed"

	// SourceCustomer is published by the customer, by hand, in their own zone.
	//
	// 🔴 A SourceCustomer RECORD IS NEVER PUBLISHED BY THIS SERVICE, AND THAT IS
	// THE FIX FOR THE UNPROVEN ANCHOR.
	//
	// There is exactly one today — the ownership proof — and it used to sit
	// inside the set we published, with the gate on proceeding being a public
	// lookup of that same record. The proof was satisfied by our own write, so
	// "the customer proved they own this anchor" was a sentence with no fact
	// behind it. Marking the source, rather than special-casing one name at each
	// publish site, is what makes the property survive a second record ever
	// needing it.
	SourceCustomer Source = "customer"
)

// Item is one record in a plan, with everything a person needs in order to
// decide whether they are willing to have it in their zone.
type Item struct {
	// Record is exactly what is written, or exactly what the customer is asked
	// to write. There is deliberately no second representation for the manual
	// path: the list somebody is told to add by hand and the list this service
	// reasons about are the same bytes, so they cannot drift apart.
	Record dnsplan.Record

	// Purpose and Source are the two questions anyone asks about an unfamiliar
	// row in their own zone: what is it for, and who put it there.
	Purpose Purpose
	Source  Source

	// Host is the hostname this record SERVES, which is not the record's own
	// name: `_acme-challenge.api.example.com` serves `api.example.com`. A
	// console groups by this so a customer sees one block per hostname rather
	// than an undifferentiated list.
	//
	// It is empty for the ownership proof, which is anchored above every host
	// and serves all of them at once — that is precisely what anchoring it at
	// the shared parent bought, and an arbitrary host here would misreport it as
	// belonging to one of the four.
	Host string

	// Explain is one sentence a customer's developer reads to understand why the
	// row is here and what breaks if they delete it.
	//
	// It is written for somebody scanning their own zone file at speed, so it
	// names the CONSEQUENCE rather than the mechanism, and it says WHEN the
	// consequence arrives. "Immediately" and "silently, months from now" are
	// different risks, and a row that does not distinguish them is not much help
	// to the person holding the delete button.
	Explain string
}

// Plan is everything one intent produces.
//
// 🔴 THE ITEM ORDER IS FIXED BY CONSTRUCTION, AND THAT IS LOAD-BEARING. The plan
// digest (dnsplan.Snapshot.Digest) is computed over the record list in order and
// is shown to the customer BEFORE they authorize, then re-checked before
// anything is written. A map iteration anywhere in this package would produce a
// different digest on the next pass and tell a customer, mid-consent, that the
// plan changed. internal/relay sorts its own output for the same reason; a
// caller merging the two must append rather than re-deriving an order of its own.
type Plan struct {
	// Lane is the lane this plan was derived for. Two lanes on one domain are
	// two different registrations with two different proofs.
	Lane lane.Lane

	// Anchor is the name the customer proved, and the bound on every record
	// below. Normalized: lowercased, no trailing root dot.
	Anchor string

	// Hosts are the hostnames this plan serves, in the order lane.Hosts derives
	// them. On lane 2 that is the single wildcard `*.<anchor>`, which is a host
	// in the sense that matters here: it is what the routing record is for.
	Hosts []string

	// Items are the records, ownership first, then routing, then certificate
	// pointers. Records 5 and 7 are not here — they are relayed, and the caller
	// merges them in from internal/relay once the upstreams have answered.
	Items []Item
}

// Publishable returns the records this service may write, in plan order.
//
// 🔴 IT IS AN ALLOW-LIST, NOT "EVERYTHING EXCEPT THE CUSTOMER'S".
//
// The two agree on today's vocabulary and disagree on tomorrow's: a Source
// constant added later is publishable by default under an exclusion and is not
// publishable by default here. The wrong default in this particular switch is a
// record written into somebody's zone that nobody decided to write, so the
// unfamiliar case has to fail toward not writing.
//
// The result is a fresh slice the caller may append relayed records to before
// handing it to dnsplan.NewSnapshot, which re-checks containment on the whole
// set. Nothing here trusts this function to be the only check.
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
// 🔴 THIS IS NOT THE `manual` OUTCOME IN docs/DESIGN.md §3, AND CONFUSING THE
// TWO WOULD SHIP A BROKEN DEGRADED PATH.
//
// That outcome — a bind or an advance that finds no usable credential — hands
// the customer the WHOLE record set to add by hand, everything in Publishable()
// included. This method is the strictly smaller half: the records this service
// will not write EVEN WHEN it holds a live grant. A degraded response built from
// Manual() alone would tell somebody to add one TXT record and leave their app
// unrouted, with a plausible-looking list to prove it was their fault.
func (p Plan) Manual() []Item {
	out := make([]Item, 0, len(p.Items))
	for _, item := range p.Items {
		if item.Source == SourceCustomer {
			out = append(out, item)
		}
	}
	return out
}

// Config is the deployment's routing vocabulary: the values that decide what a
// derived record POINTS AT, as opposed to what it is called.
//
// A struct rather than a set of package constants, because a staging deployment
// points somewhere else — and because `capabilities` publishes these, so a
// customer can read the exact targets BEFORE authorizing rather than discovering
// them in their own zone afterwards. None of it is secret. A customer sees every
// one of these values in their own zone the moment anything is written, so
// hiding them here would only mean a reader of this repository cannot check what
// the code will write, which is the entire property this repository exists to
// offer.
type Config struct {
	// OrgRoutingTarget is record 2's value: what the four platform siblings on
	// lane 1 point at.
	OrgRoutingTarget string

	// AppRoutingTarget is records 3 and 4's value: what lane 2's wildcard and
	// lane 3's single hostname point at.
	//
	// It is a separate name from OrgRoutingTarget because the two are separate
	// Cloudflare zones with separate custom-hostname configurations. A host
	// pointed at the wrong one is simply not a custom hostname in the zone it
	// reaches, so it resolves and then is not served — a failure whose DNS looks
	// perfect from the customer's side.
	AppRoutingTarget string

	// DCVDelegationUUID is the middle label of record 6's value: the per-zone
	// identifier Cloudflare gives for delegated certificate validation. One
	// value covers every custom hostname under one of our SaaS zones.
	//
	// Despite the name Cloudflare gives it, the observed values are 16
	// hexadecimal characters rather than a 36-character UUID, so it is validated
	// as one DNS label and never as a canonical UUID. See DCVTarget.
	DCVDelegationUUID string

	// ReservedSuffixes are the names nobody may connect: MirrorStack's own.
	//
	// 🔴 A NAME UNDER ONE OF THESE HAS NO CUSTOMER AT THE OTHER END. The
	// ownership proof for it would be published by us, which is exactly the
	// defect docs/DESIGN.md §1 exists to remove, and the customer-grant write
	// path would have become a platform-zone editor. Validate refuses an empty
	// list rather than treating it as "reserve nothing", because a guard that
	// silently protects nothing while reading like protection is worse than no
	// guard at all.
	//
	// The effective list also includes both routing targets, folded in by the
	// derivation itself: connecting the very name a routing CNAME points at
	// would publish a loop. See reserved.
	ReservedSuffixes []string
}

const (
	// defaultOrgRoutingTarget and defaultAppRoutingTarget are MirrorStack's
	// production edge names, and they are defaults here so that this repository
	// and the private half cannot silently disagree about what belongs in a
	// customer's zone — the split-brain the rebuild exists to remove.
	//
	// An unset variable is therefore not a safe no-op: a deployment that must
	// NOT point at production has to say so. That is the trade, and it is made
	// in this direction because a missing target that fell back to nothing would
	// derive a record with an empty value, which is a defect discovered later
	// and further away.
	defaultOrgRoutingTarget = "connect.mirrorstack.ai"
	defaultAppRoutingTarget = "connect.mirrorstack.app"

	orgRoutingTargetEnv  = "CF_SAAS_ORG_TARGET"
	appRoutingTargetEnv  = "CF_SAAS_TARGET"
	dcvDelegationUUIDEnv = "CF_ORG_DCV_DELEGATION_UUID"
	reservedSuffixesEnv  = "MS_RESERVED_DOMAIN_SUFFIXES"
)

// platformSuffixes are MirrorStack's own registrable domains, reserved
// unconditionally.
//
// They are hardcoded rather than configured because they are not a deployment
// detail: no deployment of this service, staging included, has any business
// accepting `mirrorstack.ai` as a customer's domain. A deployment may add to the
// list through the environment; it cannot remove these.
var platformSuffixes = []string{"mirrorstack.ai", "mirrorstack.app"}

// ConfigFromEnv reads the deployment's routing vocabulary from the environment.
//
//	CF_SAAS_ORG_TARGET           record 2's value      (default above)
//	CF_SAAS_TARGET               records 3 and 4       (default above)
//	CF_ORG_DCV_DELEGATION_UUID   record 6's uuid half  (no default)
//	MS_RESERVED_DOMAIN_SUFFIXES  extra reserved names  (added to the hardcoded pair)
//
// The uuid has no default on purpose: an empty value is a truthful "this
// deployment has not been told", and Validate turns it into a refusal at the
// first derivation rather than into a record pointing at `.dcv.cloudflare.com`
// with a missing label. It should come from
// `GET /zones/{our_zone}/dcv_delegation/uuid` against MirrorStack's own zone
// rather than from somebody's memory of the dashboard.
//
// This reads the environment and never exits, unlike shared/config.MustEnv: a
// missing routing target is worth reporting through Validate at the call site,
// where the refusal can name which of the four values is not set and reach the
// caller as an error rather than as a process that died at boot.
func ConfigFromEnv() Config {
	return Config{
		OrgRoutingTarget:  envOr(orgRoutingTargetEnv, defaultOrgRoutingTarget),
		AppRoutingTarget:  envOr(appRoutingTargetEnv, defaultAppRoutingTarget),
		DCVDelegationUUID: strings.TrimSpace(os.Getenv(dcvDelegationUUIDEnv)),
		ReservedSuffixes: append(append([]string(nil), platformSuffixes...),
			splitSuffixes(os.Getenv(reservedSuffixesEnv))...),
	}
}

// Validate reports whether this deployment can derive anything at all.
//
// Every entry point below calls it first, so an unconfigured process refuses at
// the boundary instead of producing a plan with a hole in it. That matters more
// here than in most config checks: a derived record with an empty value is
// caught eventually by dnsplan.NormalizeRecords, but only after a lane, an
// anchor and possibly a credential have been resolved, and the error it produces
// then names a record rather than the missing setting.
func (c Config) Validate() error {
	if err := validateTarget("org routing target", orgRoutingTargetEnv, c.OrgRoutingTarget); err != nil {
		return err
	}
	if err := validateTarget("app routing target", appRoutingTargetEnv, c.AppRoutingTarget); err != nil {
		return err
	}
	// The uuid becomes one label inside a DNS name, so the only shape that has
	// to hold is "one LDH label". lane.ValidateSlug is exactly that rule, reused
	// rather than copied — a second copy of a label rule is a second copy to
	// drift, and the looser copy is always the one that matters. What is
	// deliberately NOT checked is the length or the alphabet Cloudflare happens
	// to use today: pinning a 16-hex-character shape we have not verified would
	// refuse a value Cloudflare itself handed us.
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

// validateTarget checks one routing target.
//
// The reserved list passed to lane.ValidateDomain is deliberately nil: a routing
// target IS a MirrorStack name and must not be refused for being one. The
// inversion is the point — the reserved list refuses those names as somebody's
// domain to connect, while this checks them as our own name to point at.
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
// routing targets.
//
// Folding the targets in matters for a deployment whose edge lives outside the
// hardcoded MirrorStack suffixes — a staging one, say. Connecting the exact name
// a routing CNAME points at would publish a record that points at itself, and
// the customer's own edge would be the one serving the loop.
//
// Only ever called after Validate, which is what guarantees neither target is
// empty here. An empty entry would make lane.ValidateDomain refuse every domain,
// which is the correct answer to a malformed list and a terrible answer to a
// list this function built.
func (c Config) reserved() []string {
	out := make([]string, 0, len(c.ReservedSuffixes)+2)
	out = append(out, c.ReservedSuffixes...)
	return append(out, c.OrgRoutingTarget, c.AppRoutingTarget)
}

// Registration derives the plan one registration intent returns: record 1, the
// lane's routing record or records, and record 6 where the lane has one.
//
// Records 5 and 7 are absent, and their absence is not a partial answer — they
// do not EXIST yet at registration time. AWS has not been asked for a
// certificate and Cloudflare has not been asked for a custom hostname, so there
// is nothing to relay. The caller merges them in from internal/relay on a later
// pass, once the upstreams have answered. A plan that pretended to know them
// would be a plan with invented bytes in it.
//
// identity is validated and then not used in any derived byte, which is
// deliberate rather than an oversight: a registration IS (lane, identity,
// anchor), and internal/proof refuses exactly the same malformed identities when
// it computes proofValue. Accepting one here that proof rejects would produce a
// plan whose ownership row can never be filled — a plan that looks complete and
// cannot be completed.
//
// proofValue is the value internal/proof computed for this same triple. It is
// passed in rather than derived because this package holds no key: it can say
// which records exist and cannot mint the one that authorizes them, which is the
// same separation the customer relies on, seen from the inside.
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
		// The value's SHAPE is not checked, because checking it would be this
		// package asserting internal/proof's encoding without holding a key to
		// verify anything. Empty is different: it is the one value that produces
		// a record no customer can act on, and it is what a caller that skipped
		// the proof entirely hands over.
		return Plan{}, fmt.Errorf("%w: no ownership proof value for the anchor", ErrDerive)
	}
	hosts := parsed.Hosts(anchor)
	if len(hosts) == 0 {
		// Unreachable today, and retained: lane.Parse admits exactly three lanes
		// and all three derive hosts under a validated anchor. It is the guard a
		// fourth lane added to Parse and forgotten in Hosts would trip, and the
		// alternative to tripping it is a registration that publishes only an
		// ownership proof and reports success.
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
		// every one of them INCLUDING cdn. The cdn asymmetry is real but it is
		// about record 5, not record 6: a content host is terminated before the
		// request ever reaches AWS, so it owns no AWS certificate and is owed no
		// AWS validation record — while it is still a Cloudflare custom hostname
		// like the other three and needs the same delegated validation.
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
		// One wildcard, and no certificate pointer at all. There is no host to
		// derive one for yet — the apps this parent exists to serve have not
		// been deployed — and `_acme-challenge.*.example.net` is not a name
		// anybody can publish. Each app's pointer is minted per app, at deploy
		// time, by BindApp.
		items = append(items, routingItem(hosts[0], c.AppRoutingTarget, fmt.Sprintf(
			"Routes every app you deploy at <app>.%s through MirrorStack. A wildcard answers only names your zone holds no record of its own for, so everything you already publish keeps resolving exactly as it does today; deleting it takes every app on this domain down at once.",
			anchor)))

	case lane.AppDomain:
		// The anchor itself is the host, which is the tightest of the three
		// lanes: nothing is derived beneath it and nothing beside it in that
		// zone is reachable. When the anchor is a registrable domain the routing
		// record is a CNAME at a zone apex, which is only servable by a provider
		// that flattens one — that is a property of the customer's provider and
		// is why the refusal, if it comes, comes from their side rather than
		// being pre-judged here.
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
// FUNCTION EXISTS.
//
// `*.example.net` covers `blog.example.net` and does NOT cover
// `_acme-challenge.blog.example.net` — one label further left and the wildcard
// stops applying. So lane 2's single routing record genuinely routes every app
// the org will ever deploy, and every app still owes a certificate record that
// no wildcard can supply. A wildcard CUSTOM HOSTNAME would remove the need
// entirely; it is Enterprise-only on the account this runs against, so this is a
// real constraint rather than a shortcut nobody got round to removing.
//
// It derives record 6 and nothing else:
//
//   - No ownership proof. The parent's proof sits at the anchor and covers every
//     name beneath it, which is exactly what anchoring it at the shared parent
//     bought. Asking for a second proof per app would make deploying an app a
//     manual DNS step, forever.
//   - No routing record. The wildcard already routes this app, and a second
//     CNAME at `blog.example.net` would be a record published beside a name the
//     customer is already being served from.
//   - Record 7 is relayed by internal/relay and merged in by the caller, once
//     Cloudflare has minted it for this host.
//
// parentAnchor is the anchor out of the org's sealed registration, and slug is
// the app's — the one caller-chosen string anywhere in this design. It selects
// WHICH name under a parent already proven, never WHAT is written there, and
// lane.ValidateSlug is what keeps it from being able to spell `_acme-challenge`,
// a dot, or `*`.
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
	// dcvPrefix is the owner a certificate authority looks up when it validates
	// a name. The trailing dot is inside the constant so `dcvPrefix + host` is
	// the whole name and no call site has to remember a separator — the version
	// of that bug which ships is the one that silently produces
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
// This is the most consequential derivation in the package, because of what the
// form buys. The record carries NO token, and both halves of it — the hostname
// the customer just connected, and a per-zone identifier that is fixed
// configuration — are known before anything has been asked of anyone. So it is
// publishable on the FIRST pass, before a certificate has been requested or a
// custom hostname created, and it never changes again: Cloudflare mints and
// rotates the real tokens behind the pointer, in its own zone, for every future
// renewal. That is what lets lanes 1 and 3 hold a credential for 24 hours
// instead of forever. Cloudflare's DCV tokens live 7 days on Let's Encrypt and
// 14 on Google Trust Services, and a form that put the token in the customer's
// zone would need republishing on that clock, indefinitely, by a grant we
// deliberately do not keep.
//
// 🔴 THE HOSTNAME PREFIX IS LOAD-BEARING, AND api-platform DISAGREES WITH THIS
// FILE ABOUT IT.
//
// Cloudflare documents the target as `<host>.<uuid>.dcv.cloudflare.com`: the
// hostname is the per-host namespace Cloudflare writes its rotating TXT records
// into, and a wildcard hostname gets two of them at that one name. Without the
// prefix every host delegated to one of our zones would collide on a single
// name, and a certificate authority following the pointer would read a token for
// somebody else's hostname, or nothing at all.
//
// api-platform's `dcvDelegationTarget` builds `<uuid>.dcv.cloudflare.com`, with
// no prefix. THIS FILE FOLLOWS docs/DESIGN.md §6, which is the merged public
// specification and matches Cloudflare's own documentation. The disagreement is
// recorded rather than resolved here because the other half of it is a change in
// another repository.
//
// 🔴 AND THE FORM IS UNVERIFIED AGAINST A LIVE CLOUDFLARE DASHBOARD as of
// 2026-08-28. Nobody has yet read `GET /zones/{our_zone}/dcv_delegation/uuid`
// with our own token or copied the value out of the dashboard; the uuid in use
// is a hand-set environment variable. The one live probe on record — four custom
// hostnames that sat at `pending_validation` indefinitely "with the delegation
// CNAME in place and resolving" — published the PREFIX-LESS target, and
// concluded that delegation was not in effect on that zone. It cannot
// distinguish that from a pointer aimed at a name Cloudflare never writes to. So
// "delegation does not work here" is an open question until it is re-measured
// with the form above, and a reader of this repository is owed that uncertainty
// rather than a confident constant.
//
// It returns "" rather than a target that cannot be right, for the reason
// proof.Name does: a half-formed value is worse than an empty one, because only
// the empty one fails loudly. Callers below turn that into a refusal. The uuid's
// SHAPE is Config.Validate's business, not this function's — this is the form,
// that is the deployment.
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
// It refuses an anchor too deep to carry the challenge name — the proof sits one
// 23-byte label above the anchor, so an anchor over 230 bytes has nowhere to put
// it. That bound is the customer's domain rather than anything we chose, and it
// is separate from the pointer bound in dcvItem: an anchor can be shallow enough
// to prove and still too deep to hang a certificate pointer beneath. Refusing
// with the cause named beats deriving a record with an empty owner name, which a
// provider would create at the ZONE APEX.
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
			// Meaningless for a TXT — Cloudflare's orange cloud applies to a
			// hostname — but stated rather than left to a zero value, so "grey
			// on purpose" is distinguishable from "nobody decided".
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

// routingItem is records 2, 3 and 4: the CNAME that carries traffic for one
// name.
//
// 🔴 Proxied IS FALSE ON EVERY RECORD THIS PACKAGE DERIVES, AND IT IS NOT A
// DEFAULT NOBODY THOUGHT ABOUT.
//
// The proxy decision belongs to MirrorStack's private half and applies only
// inside MirrorStack's own zones. A record in a CUSTOMER's zone that we flipped
// to proxied would be flattened at THEIR edge: the name would answer with
// addresses instead of following the delegation, so the request never reaches
// our zone at all, and issuance — or a renewal months later — fails with every
// dashboard on both sides still green. Cloudflare accepts `proxied: true` on
// these names without an error, which is what makes it a silent failure rather
// than a rejected write. This service therefore ships the one-line rule and no
// path that can produce anything else.
func routingItem(host, target, explain string) Item {
	return Item{
		Record:  dnsplan.Record{Type: "CNAME", Name: host, Value: target, Proxied: false},
		Purpose: PurposeRouting,
		Source:  SourceDerived,
		// A routing record serves the name it IS, which is the one case where
		// Item.Host and the record's own name coincide.
		Host:    host,
		Explain: explain,
	}
}

// dcvItem is record 6 for one host.
//
// The two ways a pointer can fail to exist have different people behind them,
// so they are different refusals. A missing uuid is the operator's to fix and
// cannot reach here through a validated Config. A target over the DNS wire
// limit is the request's: a deep anchor plus a long slug can name a host whose
// pointer would not fit in a DNS name, and there is no shortening that keeps the
// pointer pointing anywhere. Refusing the whole plan is the right answer to it —
// publishing the rest would leave a hostname routed to MirrorStack with a
// certificate that can never validate, which is a worse outcome than not
// starting.
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
			// Proxied stays false here for a sharper reason than elsewhere: any
			// owner whose first label starts with an underscore is a name a
			// certificate authority reads directly, and proxying it replaces the
			// delegation with addresses. See routingItem.
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
// CHECK IT AGAIN.
//
// The duplication is the point. A derivation bug is exactly what containment
// exists to catch, and catching it at the point of derivation names the DEFECT —
// this lane, this label table, this concatenation — where catching it two
// packages later names only the symptom, after a lane, an anchor and possibly a
// credential have been resolved. dnsplan's copy is the boundary that a hostile
// or unknown caller cannot get past; this copy is the one that tells whoever
// broke it what they broke.
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
	// An A record would point a customer's hostname at an address that outlives
	// any deployment we control; an NS or a CAA would move authority for a name,
	// or decide which certificate authority may issue for it, in a zone we were
	// lent a token for.
	if record.Type != "CNAME" && record.Type != "TXT" {
		return fmt.Errorf("%w: derived a %q record, and the vocabulary is CNAME and TXT",
			ErrDerive, echo(record.Type))
	}
	if record.Name == "" || record.Value == "" {
		// Empty is the dangerous half-formed case, not a harmless one: a
		// provider handed an empty owner name creates a record at the ZONE APEX.
		return fmt.Errorf("%w: derived an incomplete %s record for %q", ErrDerive, record.Type, echo(anchor))
	}
	if len(record.Name) > dnsplan.MaxDNSName {
		return fmt.Errorf("%w: derived a %d-byte name, over the %d-byte DNS limit",
			ErrDerive, len(record.Name), dnsplan.MaxDNSName)
	}
	if record.Name != dnsplan.NormalizeName(record.Name) {
		// Derived names are normalized by construction. One that is not means a
		// caller's spelling reached a record verbatim, and a plan holding two
		// spellings of one name digests differently on the next pass.
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
		// A row with no purpose, no source or no explanation is a row a customer
		// is asked to accept with nothing to accept it on. It is cheaper to
		// refuse the plan than to render a blank cell in a consent screen.
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
// variable.
//
// Commas, semicolons and whitespace all separate, because an operator writing
// `a.example, b.example` is doing the obvious thing. Splitting on whitespace
// alone would keep the comma inside the first entry and produce a suffix that
// matches no name at all — protection that reads like protection and silently is
// not. That silence is the only reason this function is forgiving about
// anything; nothing else in this service repairs its input.
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
