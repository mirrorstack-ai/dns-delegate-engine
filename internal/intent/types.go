// Package intent is the RPC surface MirrorStack's private half calls: it names a
// DOMAIN and an INTENT, and it can no longer name a DNS record at all.
//
// 🔴 THIS IS THE SURFACE THAT REPLACES Publish(records), AND IT EXISTS TO CLOSE
// TWO DEFECTS. Both are described in full in docs/DESIGN.md §1; in short:
//
//  1. Anchor containment bounds a record's NAME and nothing bounds its VALUE.
//     A caller that supplies records can therefore point `account.example.com`
//     at somebody else's origin, or publish a third party's ACME token at
//     `_acme-challenge.example.com`, with every check in this repository
//     passing. Reading the old surface told you WHERE we could write and
//     nothing about WHAT. So there is no records field here, and there is no
//     value, target, proxy flag, certificate id, hostname id, ownership token,
//     expiry or stage either — every byte that reaches a customer's zone is
//     derived in internal/derive or relayed verbatim from AWS or Cloudflare in
//     internal/relay.
//
//  2. The anchor was not proven. The ownership TXT sat inside the set WE
//     published and the gate was a public lookup of that same record, so the
//     proof was satisfied by our own write. Here the ownership record is the
//     CUSTOMER's to publish (derive.SourceCustomer, never in what this service
//     writes) and it is re-checked on every pass that writes. Verify is what
//     makes "proven" mean something.
//
// 🔴 THE CREDENTIAL BOUNDARY, INHERITED VERBATIM FROM internal/grant.
//
// Cloudflare rotates the refresh token on every use, so a failure that arrives
// after a refresh leaves the caller's stored token already dead. Reporting that
// as an RPC error gives the caller nothing to persist, and the grant kills
// itself on the next pass holding a token the provider had already replaced —
// measured 2026-08-24. The rule:
//
//   - A malformed request, or a deployment that cannot offer delegated DNS at
//     all, is an RPC error. Nothing was consumed and nothing happened.
//   - Everything else is reported in the response. That includes every outcome
//     that describes the CUSTOMER's zone or the CUSTOMER's choices — no
//     credential held, the proof withdrawn, the provider unreachable — because
//     those are answers, not faults, and a caller has to render each one
//     differently. See Result.
//
// That second clause is slightly wider than grant's, which drew the line at
// "once a credential has been consumed or rotated". It has to be: this surface
// has outcomes (manual, stopped) that consume nothing and are still not errors.
// Everything grant reported in a response is still reported in a response here.
//
// Nothing in this package opens a database, because this service owns none
// (CLAUDE.md, docs/DESIGN.md §7). Every fact that survives between two calls
// travels as a sealed envelope the private half stores and hands back.
package intent

import (
	"errors"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/derive"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/observe"
)

// RPC-level errors: the refusals that consume nothing and describe the REQUEST
// or the DEPLOYMENT rather than the customer's zone.
//
// They are intent's own sentinels rather than grant's, because the two surfaces
// are on their way to being one and the survivor should not carry an import of
// the other. The semantics are identical, deliberately, so a caller migrating
// between them changes an identifier and not a behaviour.
var (
	// ErrUnavailable means this deployment cannot offer delegated DNS: no OAuth
	// client, or no keyset. It is a truthful state, not a fault — the console
	// renders no connect affordance at all, which beats a button that fails on
	// the provider's own consent screen.
	ErrUnavailable = errors.New("intent: delegated DNS unavailable")

	// ErrInvalidRequest covers a malformed or self-contradictory request: an id
	// that is not a canonical UUID, a domain that is not a DNS name or sits
	// under a MirrorStack suffix, an envelope this deployment cannot open, a
	// missing digest.
	ErrInvalidRequest = errors.New("intent: invalid request")

	// ErrNotProven is Authorize's refusal when the ownership proof does not
	// resolve at the anchor RIGHT NOW.
	//
	// It is deliberately NOT a kind of ErrInvalidRequest. The request is
	// perfectly well formed; what is missing is a TXT record in somebody else's
	// zone, and the two need different screens — one says "this is a bug",
	// the other says "publish this record and try again". A caller that could
	// only tell them apart by reading a message would eventually show the wrong
	// one.
	ErrNotProven = errors.New("intent: the ownership proof does not resolve at the anchor")

	// ErrConsentRequired is Authorize's refusal on the org_app_domain lane when
	// this service's own consent page was not served and acknowledged.
	//
	// A wildcard is the one grant whose scope a customer cannot enumerate for
	// themselves, so the description they act on has to come from here rather
	// than from a console this repository cannot vouch for (DESIGN §4).
	ErrConsentRequired = errors.New("intent: this lane requires an acknowledged consent page")
)

// ─── requests ───────────────────────────────────────────────────────────────
//
// 🔴 DESIGN §5 IS A HARD CONTRACT, AND reflect_test.go ENFORCES IT.
//
// A field on a request struct may only be a string, a bool, an int64 or a
// []string. No map, no json.RawMessage, no []dnsplan.Record, no nested struct,
// no `any`. The test walks every type in requestTypes below and fails on any
// type it does not recognise — so a map or a raw JSON field is rejected by
// DEFAULT rather than by somebody having thought of it — and it fails on a set
// of forbidden field NAMES as well, because `Value string` would pass a type
// check and reintroduce defect 1 above.
//
// It also parses this file and fails if a type whose name ends in `Request` is
// missing from requestTypes, so a new request struct cannot be added without
// being policed.
//
// Note what is NOT here. There is no `lane` field, even though §5 admits one:
// each intent is its own function, so the lane is a constant at the call site
// and a caller cannot get it wrong. There is no `reviewed` identity list either
// — that was a records field in disguise, and the digest does its job.

// AddOrgPlatformDomainRequest registers an org's console domain (lane 1). The
// four sibling hostnames are derived from a fixed table, so the caller cannot
// add a fifth or rename one.
type AddOrgPlatformDomainRequest struct {
	OrgID  string `json:"orgId"`
	Domain string `json:"domain"`
}

// AddOrgAppDomainRequest registers the parent under which an org's apps are
// auto-routed (lane 2). Individual apps are not named here and never need to
// be: the slug decides the hostname and one wildcard routes it.
type AddOrgAppDomainRequest struct {
	OrgID  string `json:"orgId"`
	Domain string `json:"domain"`
}

// AddAppDomainRequest registers one arbitrary domain against one app (lane 3).
//
// 🔴 IT TAKES AN APP, NOT AN ORG. The owner may be a person, and this lane has
// to work with no organization anywhere in the request. That is why the field
// is AppID and why nothing here falls back to an org id.
type AddAppDomainRequest struct {
	AppID    string `json:"appId"`
	Hostname string `json:"hostname"`
}

// BindAppRequest mints what ONE app owes under an org app domain, at deploy
// time. See Service.BindAppToOrgAppDomain for the two outcomes.
type BindAppRequest struct {
	// Registration is the org app domain's sealed registration.
	Registration string `json:"registration"`

	// Slug is the app's, and it is the one caller-chosen string anywhere in this
	// design. It selects WHICH name under a parent already proven, never WHAT is
	// written there, and lane.ValidateSlug keeps it from being able to spell
	// `_acme-challenge`, a dot or `*`.
	Slug string `json:"slug"`

	// SealedToken is the parent's held grant, if the caller has one. Absent is
	// not an error: it is the manual path, and it is a supported answer rather
	// than a fallback.
	SealedToken string `json:"sealedToken,omitempty"`
}

// VerifyRequest asks whether the ownership proof resolves in public DNS.
type VerifyRequest struct {
	Registration string `json:"registration"`
}

// AuthorizeRequest asks for the provider's consent URL.
//
// There is no state field, and that absence is the point: Authorize mints the
// state itself. See Service.Authorize.
type AuthorizeRequest struct {
	Registration string `json:"registration"`

	// CodeChallenge is the PKCE challenge whose verifier the caller keeps. It
	// reaches no record.
	CodeChallenge string `json:"codeChallenge"`

	// ConsentToken is the receipt of this service's own consent page, required
	// on the org_app_domain lane only. It is a MAC under this deployment's
	// keyset; a caller can echo one and can mint none.
	//
	// 🔴 THERE IS NO consentNonce FIELD, AND ITS ABSENCE IS THE CONTROL. The
	// reference the token is a MAC over is minted when the domain is registered
	// and sealed into the registration, so Authorize checks the token against a
	// value THIS service issued for THIS domain. When the caller supplied both
	// halves it was supplying a statement and its own signature over it, and one
	// acknowledgement authorized every later wildcard grant on the anchor. One
	// fewer caller-supplied field moves this surface toward DESIGN §5 rather
	// than away from it. What remains — an acknowledgement scoped to the
	// registration rather than to one attempt — is stated in consent.Token.
	ConsentToken string `json:"consentToken,omitempty"`
}

// CompleteRequest exchanges the authorization code and publishes.
//
// 🔴 IT CARRIES NO IDENTITY, NO LANE AND NO DOMAIN. All three come out of the
// sealed State. Two requests whose fields are checked against each other can be
// made to disagree, because a check is only as strong as the code path that
// reaches it and there are always more paths than checks. One sealed envelope
// cannot disagree with itself.
type CompleteRequest struct {
	// State is the envelope Authorize minted and the provider echoed back.
	State string `json:"state"`

	Code         string `json:"code"`
	CodeVerifier string `json:"codeVerifier"`

	// ExpectDigest is the hex SHA-256 of the plan the customer reviewed.
	//
	// 🔴 REQUIRED. Empty is REFUSED. The legacy PublishRequest made it optional,
	// and the README says so in as many words: "the check is skipped if the
	// caller omits the digest, so it defends against a bug in the private half,
	// not against the private half." An integrity check a caller can turn off by
	// omitting a field is a claim rather than a control, and the whole reason
	// this repository is public is that its claims are meant to be checkable.
	ExpectDigest string `json:"expectDigest"`
}

// AdvanceRequest runs one pass of the loop.
//
// There is no expectDigest here, and that is not an oversight: later passes
// publish records that did not exist when the customer authorized — AWS and
// Cloudflare produce them minutes to hours later — so there was nothing to
// approve. Those records are bounded by the anchor and by internal/relay's
// value check, which is what bounds a value containment cannot.
type AdvanceRequest struct {
	Registration string `json:"registration"`
	SealedToken  string `json:"sealedToken,omitempty"`
}

// DescribeRequest asks for every record, its purpose, and what public DNS says
// about it. It writes nothing and needs no credential.
type DescribeRequest struct {
	Registration string `json:"registration"`
}

// OrphansRequest asks what this service left behind in a zone.
type OrphansRequest struct {
	Registration string `json:"registration"`
	SealedToken  string `json:"sealedToken,omitempty"`
}

// ReleaseRequest ends a held grant at the provider.
type ReleaseRequest struct {
	Registration string `json:"registration"`
	SealedToken  string `json:"sealedToken"`

	// Reason is logged and nothing else. It reaches no provider call and no
	// record; it exists so an operator reading CloudWatch can tell a domain that
	// was deleted from one whose window simply closed.
	Reason string `json:"reason,omitempty"`
}

// requestTypes is every request struct on this surface.
//
// 🔴 IT IS THE REFLECTION TEST'S INPUT, AND A NEW REQUEST TYPE MISSING FROM IT
// FAILS THE BUILD. reflect_test.go parses this file for every `…Request` type
// declaration and asserts each one appears here, so the §5 contract cannot be
// escaped by declaring a struct and forgetting to list it — which is the only
// way it realistically would be escaped.
var requestTypes = []any{
	AddOrgPlatformDomainRequest{},
	AddOrgAppDomainRequest{},
	AddAppDomainRequest{},
	BindAppRequest{},
	VerifyRequest{},
	AuthorizeRequest{},
	CompleteRequest{},
	AdvanceRequest{},
	DescribeRequest{},
	OrphansRequest{},
	ReleaseRequest{},
}

// ─── responses ──────────────────────────────────────────────────────────────
//
// The §5 contract bounds what a caller may SEND. It does not bound what this
// service answers, and it must not: a response carries the records, their
// purposes, their sources and what was observed at each one, because that is
// the whole product. The asymmetry is the design — one side names an intent,
// the other side explains, in full, what that intent means in a zone.

// RecordView is one record as a person reads it.
//
// It is the same bytes on the manual path and the delegated path, because both
// come from the same derivation (DESIGN §3). The list a customer is told to add
// by hand cannot drift from the list this service writes, since there is only
// one of them.
type RecordView struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Value   string `json:"value"`
	Proxied bool   `json:"proxied"`

	// Purpose is why the record is here and Source is who writes it. Source is
	// the safety property rather than a label: "customer" means this service
	// never publishes the row, which is the fix for the unproven anchor.
	Purpose string `json:"purpose"`
	Source  string `json:"source"`

	// Host is the hostname this record SERVES, which is not the record's own
	// name: `_acme-challenge.api.example.com` serves `api.example.com`. Empty
	// for the ownership proof, which is anchored above every host and serves all
	// of them at once.
	Host string `json:"host,omitempty"`

	// Explain is one sentence naming the CONSEQUENCE of deleting this record and
	// WHEN that consequence arrives. "Immediately" and "silently, months from
	// now" are different risks.
	Explain string `json:"explain,omitempty"`

	// State and Found are set only by the read-only functions (Describe, Verify,
	// Orphans). An empty State means nothing was looked up, never "absent".
	State string   `json:"state,omitempty"`
	Found []string `json:"found,omitempty"`
}

func recordView(item derive.Item) RecordView {
	return RecordView{
		Type:    item.Record.Type,
		Name:    item.Record.Name,
		Value:   item.Record.Value,
		Proxied: item.Record.Proxied,
		Purpose: string(item.Purpose),
		Source:  string(item.Source),
		Host:    item.Host,
		Explain: item.Explain,
	}
}

// recordViews projects a whole plan, in plan order.
func recordViews(items []derive.Item) []RecordView {
	out := make([]RecordView, 0, len(items))
	for _, item := range items {
		out = append(out, recordView(item))
	}
	return out
}

// observedView overlays what public DNS said onto a derived record. The
// observation's Explain already carries the derived one joined to a diagnosis
// (see observe.Observation), so it replaces rather than appends.
func observedView(item derive.Item, obs observe.Observation) RecordView {
	view := recordView(item)
	view.State = string(obs.State)
	view.Found = obs.Found
	if obs.Explain != "" {
		view.Explain = obs.Explain
	}
	return view
}

// RegisteredResponse is what all three registration intents return. None of
// them touches a credential and none of them writes anything.
type RegisteredResponse struct {
	// Registration is the sealed envelope every later call takes. The private
	// half stores it; it cannot author, edit or reorder one.
	Registration string `json:"registration"`

	// KeyID is the key the envelope was sealed under. It is returned so an
	// operator can answer "is the retired key still needed?" with a
	// SELECT DISTINCT — this service holds no row to answer it from.
	KeyID string `json:"keyId"`

	Lane   string   `json:"lane"`
	Anchor string   `json:"anchor"`
	Hosts  []string `json:"hosts"`

	// Proof is record 1: the TXT the CUSTOMER publishes, at the anchor. It is
	// also present in Records; it is lifted out because nothing else can happen
	// until it exists, and a response that buries it in a list of seven invites
	// a console to bury it too.
	Proof RecordView `json:"proof"`

	// Records is every record this registration implies, ownership first. The
	// relayed rows (5 and 7) are not here yet — AWS and Cloudflare have not been
	// asked, and their bytes do not exist. Describe reports them once they do.
	Records []RecordView `json:"records"`

	// Digest is the hex SHA-256 of the records this service would WRITE — the
	// derived, publishable set, with the customer's own proof excluded because
	// we never write it. Complete refuses to publish a plan that does not
	// reproduce it.
	Digest string `json:"digest"`

	// GrantSeconds is how long a grant on this lane is held once authorized, and
	// 0 means STANDING. It is published here so the private half stores an
	// expiry it did not invent, and so a customer reads the lifetime before
	// authorizing rather than after.
	GrantSeconds int64 `json:"grantSeconds"`
}

// VerifyResponse reports whether the ownership proof resolves in public DNS.
type VerifyResponse struct {
	Verified bool   `json:"verified"`
	Name     string `json:"name"`

	// Unresolved means the LOOKUP did not complete, so Verified being false is
	// not a statement about the customer's zone at all.
	//
	// 🔴 IT IS THE DIFFERENCE BETWEEN "YOU HAVE NOT PUBLISHED IT" AND "WE COULD
	// NOT LOOK", AND SHOWING THE FIRST FOR THE SECOND SENDS A CUSTOMER TO EDIT A
	// RECORD THAT IS ALREADY CORRECT. Proof.State carries the same distinction
	// in internal/observe's vocabulary (unknown, never absent); this field is
	// here so a caller cannot miss it by reading only the boolean it branches
	// on. A resolver failure is a fact about the world rather than a fault in
	// the request, so it is reported here and not as an RPC error — which is
	// also what keeps the observation, the name and the expected value in front
	// of whoever has to act.
	Unresolved bool `json:"unresolved,omitempty"`

	// Expected is the value to publish TODAY — the MAC under the active key.
	//
	// Verification accepts one value per key in the keyset, so a proof published
	// before a rotation still verifies; this is the single value a console
	// renders and a support answer quotes. Echoing the whole accept set would
	// put every retired key's value in front of a customer.
	Expected string `json:"expected"`

	Proof RecordView `json:"proof"`
}

// AuthorizeResponse carries the consent URL and the state this service minted.
type AuthorizeResponse struct {
	AuthorizationURL string `json:"authorizationUrl"`

	// State is returned so the caller can match the provider's redirect to its
	// row. It is echoed back to Complete verbatim; the caller cannot author one,
	// because it is a sealed envelope carrying the lane, the identity, the
	// anchor and a nonce.
	State string `json:"state"`
}

// Result is what happened to the customer's zone on one pass. Every value has a
// different customer-facing meaning and a different caller action, which is why
// there are four rather than a boolean and a message.
const (
	// ResultPublished — the delegated write path ran. Persist the returned
	// credential and continue the loop.
	ResultPublished = "published"

	// ResultManual — no usable credential exists, so NOTHING was written and the
	// records to add by hand are in the response.
	//
	// 🔴 THIS IS NOT A FAILURE, AND THE CALLER DOES NOT CHOOSE IT. Whether a
	// usable credential exists is a fact this service establishes by opening the
	// sealed grant and refreshing it. A customer who never authorized — or who
	// revoked, which they are entitled to do at any moment — gets a working
	// answer instead of an error: here are the records, add them, and the app
	// comes up.
	ResultManual = "manual"

	// ResultStopped — the ownership proof no longer resolves, so nothing was
	// written and nothing will be until it is republished. This is the
	// customer's first stop control (DESIGN §8) and it takes effect within one
	// pass, with nothing needing to reach MirrorStack.
	ResultStopped = "stopped"

	// ResultDeferred — nothing conclusive happened: the provider could not be
	// reached, or a write failed part way. Try again on the next tick.
	//
	// It is separate from manual because the two look identical in a boolean and
	// mean opposite things to a customer. Manual says "we cannot write for you,
	// here is the list". Deferred says "we can, and we will; do not go and type
	// seven records into your DNS panel over a five-second Cloudflare blip."
	ResultDeferred = "deferred"
)

// PassResponse is the answer from every function that can write: Complete,
// Advance and BindAppToOrgAppDomain. One type, because DESIGN §3 and §4 say the
// three degrade identically and a shared response is the cheapest way to keep
// that true.
type PassResponse struct {
	// Result is one of the four constants above.
	Result string `json:"result"`

	// Published is the identity list actually written, in plan order, in
	// dnsplan's normalized TYPE|name|value form.
	Published []string `json:"published,omitempty"`

	// Records is the full record set for this pass, always — on every Result.
	// On the manual path it is the list to add by hand; on the published path it
	// is what was written and why. One list, so a console cannot render two.
	Records []RecordView `json:"records,omitempty"`

	// Digest is the hex SHA-256 of the reviewable (derived) record set, the same
	// value RegisteredResponse carries.
	Digest string `json:"digest,omitempty"`

	// SealedToken and KeyID are set whenever this service holds a credential the
	// caller must persist — INCLUDING when Failure is set. PERSIST THEM FIRST.
	//
	// 🔴 AN EMPTY SealedToken NEVER MEANS "DISCARD THE ONE YOU HOLD." It means
	// this service has no replacement to hand over, which is the normal case on
	// a pass that never opened the grant at all — a withdrawn proof, or a call
	// that carried no token. A caller that blindly overwrites its column with an
	// empty string erases a live grant that nothing can then release.
	SealedToken string `json:"sealedToken,omitempty"`
	KeyID       string `json:"keyId,omitempty"`

	// Rotated reports that the provider replaced the refresh token during this
	// pass, so the caller's stored copy is already dead.
	Rotated bool `json:"rotated"`

	// Revoked is the ONLY field that means "discard the credential you hold".
	// This service ended the grant at the provider — because it published and
	// then could not hold what it was given, or because it was left holding a
	// credential nothing would ever release. A dead grant that this service did
	// NOT end is signalled instead by Failure.Code (token_unreadable,
	// invalid_grant) with Retry false; the caller's action is the same, but only
	// one of the two is a revocation that actually happened.
	Revoked bool `json:"revoked"`

	// GrantSeconds is this lane's hold, 0 for standing. See
	// RegisteredResponse.GrantSeconds.
	GrantSeconds int64 `json:"grantSeconds"`

	// Failure describes an outcome that reached the provider, or the reason
	// there is no usable credential. Nil on a clean pass.
	Failure *Failure `json:"failure,omitempty"`

	// Warnings are MirrorStack-side problems that did not stop the pass — most
	// often an upstream (AWS, Cloudflare) that could not be read, so the records
	// it owes are simply not in this pass. They are not failures: the pass wrote
	// what it could and the next one re-reads. They are here rather than
	// swallowed because a relay that is broken for a week is otherwise
	// indistinguishable from an upstream that is merely slow.
	Warnings []string `json:"warnings,omitempty"`
}

// DescribeResponse is read-only and is the single source for what a console
// shows, so the screen and the writer cannot drift apart.
type DescribeResponse struct {
	Lane   string   `json:"lane"`
	Anchor string   `json:"anchor"`
	Hosts  []string `json:"hosts"`

	// Records carries every record with its observed State: present, absent,
	// conflicting, wrong_type, or unknown. Unknown is NOT absent — a lookup that
	// did not complete tells us nothing about the customer's zone.
	Records []RecordView `json:"records"`

	// Proof is the ownership row with its own verdict, which is computed against
	// every key in the keyset rather than against today's value. See
	// Service.Describe for why it cannot be judged with the rest.
	Proof RecordView `json:"proof"`

	Verified     bool     `json:"verified"`
	Digest       string   `json:"digest"`
	GrantSeconds int64    `json:"grantSeconds"`
	Warnings     []string `json:"warnings,omitempty"`
}

// OrphansResponse reports what this service left behind.
//
// 🔴 A REPORT, NEVER A MUTATION. There is no delete anywhere in this service —
// dnsprovider.Provider has no such method — and adding one is a design change
// rather than a refactor: no provider in scope offers a conditional mutation, so
// a compensating delete cannot prove it is undoing OUR write rather than
// clobbering an edit the customer made a second ago.
type OrphansResponse struct {
	Anchor string `json:"anchor"`

	// ReadThrough is "provider" when the customer's own zone was read with their
	// grant, and "public-dns" when it was not — no grant was supplied, it could
	// not be opened, the provider refused, or the refreshed grant could not be
	// held. The distinction matters to the person acting on the report: public
	// DNS is cached and shows what the world sees, while the provider shows what
	// is actually in the zone.
	ReadThrough string `json:"readThrough"`

	// Records are the names this service would have written, with what is at
	// them now. A record whose State is absent has already gone.
	Records []RecordView `json:"records"`

	// 🔴 THE HONEST LIMIT: THIS LIST IS DERIVED, NOT REMEMBERED. This service
	// keeps no published-record cursor (DESIGN §7), so it reports what the
	// CURRENT derivation would write and what is at those names now. A record
	// written months ago under a derivation that has since changed — a routing
	// target that moved, a certificate name AWS has stopped asking for — is not
	// in this list and cannot be. Nothing in a stateless design can enumerate
	// it, and claiming otherwise would be the more comfortable lie.
	Incomplete bool `json:"incomplete"`

	// SealedToken, KeyID and Rotated mean exactly what they mean on
	// PassResponse: reading the zone with the customer's grant REFRESHES it, so
	// the caller's stored copy is already dead and the replacement here must be
	// persisted. An empty SealedToken never means "discard the one you hold".
	SealedToken string `json:"sealedToken,omitempty"`
	KeyID       string `json:"keyId,omitempty"`
	Rotated     bool   `json:"rotated"`

	// Revoked is the ONLY field that means "discard the credential you hold",
	// and a report is a place it can genuinely happen: the refresh rotates the
	// grant, and if the replacement cannot be sealed there is nothing to hand
	// back — a live grant at the provider that nothing will ever release. So it
	// is ended here rather than stranded, the same choice write() makes on the
	// publishing path, and Failure.Code says reseal_failed. Nothing else in
	// Orphans revokes: reporting is not mutating.
	Revoked bool `json:"revoked"`

	Failure  *Failure `json:"failure,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// ReleaseResponse reports the end of a grant.
type ReleaseResponse struct {
	Revoked bool `json:"revoked"`

	// Unreadable means the envelope could not be opened, so nothing was sent to
	// the provider and nothing was guessed at. The caller should still release
	// its row — there is no way to USE the credential either — but a human may
	// need to revoke by hand, and the log line says so.
	Unreadable bool `json:"unreadable"`
}

// CapabilitiesResponse tells the caller, and through it the customer, what this
// deployment can do and what it would put in a zone — before anything is asked
// of anyone.
//
// It writes nothing and needs no registration. Publishing the routing targets
// here is what lets a customer check, in advance, that the CNAME value they are
// about to be asked for is the one this repository derives (DESIGN §4).
type CapabilitiesResponse struct {
	Available bool     `json:"available"`
	CanHold   bool     `json:"canHold"`
	Provider  string   `json:"provider"`
	Scopes    []string `json:"scopes,omitempty"`

	Lanes []LaneCapability `json:"lanes,omitempty"`

	OrgRoutingTarget  string `json:"orgRoutingTarget,omitempty"`
	AppRoutingTarget  string `json:"appRoutingTarget,omitempty"`
	DCVDelegationUUID string `json:"dcvDelegationUuid,omitempty"`

	// ConfigError names a deployment whose derivation configuration is
	// incomplete, in the same words the derivation would refuse with. Without it
	// a misconfigured deployment and an unconfigured one look identical from
	// outside, which is exactly the trap cfoauth.FromEnv documents.
	ConfigError string `json:"configError,omitempty"`

	// The loop's declared clock, so "how often could MirrorStack touch my zone"
	// is answerable from this repository rather than from a support reply
	// (DESIGN §8). internal/schedule is the source; these are its numbers.
	IntervalSeconds    int64 `json:"intervalSeconds"`
	JitterSeconds      int64 `json:"jitterSeconds"`
	MinIntervalSeconds int64 `json:"minIntervalSeconds"`
}

// LaneCapability is one lane, described in the terms a customer decides on.
type LaneCapability struct {
	Lane   string `json:"lane"`
	Hosts  string `json:"hosts"`
	Anchor string `json:"anchor"`

	// GrantSeconds is 0 for a standing grant. ConsentPage reports the lane where
	// this service serves its own consent screen because the grant's scope
	// cannot be enumerated by the customer.
	GrantSeconds int64 `json:"grantSeconds"`
	ConsentPage  bool  `json:"consentPage"`
}

// Failure describes an outcome that reached the provider, or the reason there is
// no usable credential. It is the shape internal/grant established and callers
// already branch on.
type Failure struct {
	// Code is the caller's contract. Retry is what distinguishes "try again
	// later" from "this grant is dead".
	Code    string `json:"code"`
	Message string `json:"message"`
	Retry   bool   `json:"retry"`
}

// Failure codes, inherited from internal/grant so a caller's switch survives the
// move to this surface.
const (
	// FailureProvider — the provider refused or could not be reached. The grant
	// is intact; a later pass may succeed.
	FailureProvider = "provider_failure"
	// FailurePlanPreparing — the plan is not publishable yet. Not a fault.
	FailurePlanPreparing = "plan_preparing"
	// FailureTokenUnreadable — the sealed grant cannot be opened under this
	// keyset and registration. The grant is dead; release the row.
	FailureTokenUnreadable = "token_unreadable"
	// FailureInvalidGrant — the provider rejected the refresh token. The grant is
	// dead; release it. Do NOT attempt to revoke: there is nothing to revoke.
	FailureInvalidGrant = "invalid_grant"
	// FailureResealFailed — the rotated token could not be sealed. It has been
	// revoked at the provider, so the grant is dead and safe.
	FailureResealFailed = "reseal_failed"
	// FailureNoGrant — no credential was supplied. This is the ordinary state of
	// a customer who never authorized, and it is why Result is manual rather
	// than an error.
	FailureNoGrant = "no_grant"
	// FailureProofWithdrawn — the ownership proof no longer resolves. Nothing was
	// written. Republishing the TXT resumes the loop; nothing else is needed.
	FailureProofWithdrawn = "proof_withdrawn"
)
