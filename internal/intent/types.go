// Package intent is the RPC surface MirrorStack's private half calls: it names a
// DOMAIN and an INTENT, and it can no longer name a DNS record at all.
//
// 🔴 IT REPLACES Publish(records) AND CLOSES THE TWO DEFECTS OF docs/DESIGN.md §1:
//
//  1. Anchor containment bounds a record's NAME and nothing bounds its VALUE, so
//     a caller supplying records could point `account.example.com` at somebody
//     else's origin, or publish a third party's ACME token at
//     `_acme-challenge.example.com`, with every check here passing. Hence no
//     records field, and no value, target, proxy flag, certificate id, hostname
//     id, ownership token, expiry or stage either: every byte that reaches a
//     customer's zone is derived in internal/derive or relayed verbatim from AWS
//     or Cloudflare in internal/relay.
//  2. The anchor was not proven — the ownership TXT sat inside the set WE
//     published and the gate was a public lookup of that same record. It is now
//     the CUSTOMER's to publish (derive.SourceCustomer, never in what this
//     service writes), re-checked on every pass that writes.
//
// 🔴 THE CREDENTIAL BOUNDARY, INHERITED VERBATIM FROM internal/grant.
//
// Cloudflare rotates the refresh token on every use, so a failure that arrives
// after a refresh leaves the caller's stored token already dead. Reporting that
// as an RPC error gives the caller nothing to persist, and the grant kills
// itself on the next pass holding a token the provider had already replaced —
// measured 2026-08-24. So a malformed request, or a deployment that cannot offer
// delegated DNS at all, is an RPC error: nothing was consumed and nothing
// happened. EVERYTHING else is reported in the response, including every outcome
// that describes the CUSTOMER's zone or choices — no credential held, the proof
// withdrawn, the provider unreachable. Those are answers, not faults, and a
// caller renders each differently (see Result). That is wider than grant's line
// at "consumed or rotated": manual and stopped consume nothing and are still not
// errors, and everything grant reported in a response is still reported here.
//
// Nothing here opens a database, because this service owns none (CLAUDE.md,
// DESIGN §7). Every fact that survives between two calls travels as a sealed
// envelope the private half stores and hands back.
package intent

import (
	"errors"
	"time"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/derive"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/observe"
)

// RPC-level errors: the refusals that consume nothing and describe the REQUEST
// or the DEPLOYMENT rather than the customer's zone. They are intent's own
// sentinels rather than grant's, because the two surfaces are on their way to
// being one and the survivor should not import the other; the semantics are
// identical, deliberately.
var (
	// ErrUnavailable means this deployment cannot offer delegated DNS: no OAuth
	// client, or no keyset. A truthful state, not a fault — the console renders
	// no connect affordance at all.
	ErrUnavailable = errors.New("intent: delegated DNS unavailable")

	// ErrInvalidRequest covers a malformed or self-contradictory request: a
	// non-canonical UUID, a domain that is not a DNS name or sits under a
	// MirrorStack suffix, an unopenable envelope, a missing digest.
	ErrInvalidRequest = errors.New("intent: invalid request")

	// ErrNotProven is Authorize's refusal when the ownership proof does not
	// resolve at the anchor RIGHT NOW. Deliberately NOT a kind of
	// ErrInvalidRequest: the request is well formed and what is missing is a TXT
	// record in somebody else's zone, so the two need different screens.
	ErrNotProven = errors.New("intent: the ownership proof does not resolve at the anchor")

	// ErrConsentRequired is Authorize's refusal on the org_app_domain lane when
	// this service's own consent page was not served and acknowledged: a
	// wildcard's scope is the one a customer cannot enumerate, so the
	// description comes from here (DESIGN §4).
	ErrConsentRequired = errors.New("intent: this lane requires an acknowledged consent page")
)

// ─── requests ───────────────────────────────────────────────────────────────
//
// 🔴 DESIGN §5 IS A HARD CONTRACT, AND reflect_test.go ENFORCES IT.
//
// A request field may only be a string, a bool, an int64 or a []string: no map,
// no json.RawMessage, no []dnsplan.Record, no nested struct, no `any`. The test
// walks every type in requestTypes below and fails on any it does not recognise,
// so a map or a raw JSON field is rejected by DEFAULT; it fails on forbidden
// field NAMES too, because `Value string` would pass a type check and
// reintroduce defect 1 above. No `lane` field, though §5 admits one: each intent
// is its own function. And no `reviewed` identity list, which the legacy
// PublishRequest carries — []string is an allowed type, so its absence is a
// choice: it was a records field in disguise.

// AddOrgPlatformDomainRequest registers an org's console domain (lane 1). The
// four sibling hostnames come from a fixed table: the caller cannot add a fifth
// or rename one.
type AddOrgPlatformDomainRequest struct {
	OrgID  string `json:"orgId"`
	Domain string `json:"domain"`
}

// AddOrgAppDomainRequest registers the parent under which an org's apps are
// auto-routed (lane 2). Apps are not named here: the slug decides the hostname
// and one wildcard routes it.
type AddOrgAppDomainRequest struct {
	OrgID  string `json:"orgId"`
	Domain string `json:"domain"`
}

// AddAppDomainRequest registers one arbitrary domain against one app (lane 3).
// It takes an APP, not an org: the owner may be a person, so this lane works
// with no organization in the request and nothing falls back to an org id.
type AddAppDomainRequest struct {
	AppID    string `json:"appId"`
	Hostname string `json:"hostname"`
}

// BindAppRequest mints what ONE app owes under an org app domain, at deploy
// time. See Service.BindAppToOrgAppDomain for the two outcomes.
type BindAppRequest struct {
	// Registration is the org app domain's sealed registration.
	Registration string `json:"registration"`

	// Slug is the app's, and the one caller-chosen string in this design: it
	// selects WHICH name under a parent already proven, never WHAT is written
	// there. lane.ValidateSlug keeps it from spelling `_acme-challenge`, a dot
	// or `*`.
	Slug string `json:"slug"`

	// SealedToken is the parent's held grant, if the caller has one. Absent is
	// the manual path — a supported answer, not a fallback.
	SealedToken string `json:"sealedToken,omitempty"`
}

// VerifyRequest asks whether the ownership proof resolves in public DNS.
type VerifyRequest struct {
	Registration string `json:"registration"`
}

// AuthorizeRequest asks for the provider's consent URL. There is no state field:
// Authorize mints the state itself (see Service.Authorize).
type AuthorizeRequest struct {
	Registration string `json:"registration"`

	// CodeChallenge is the PKCE challenge whose verifier the caller keeps. It
	// reaches no record.
	CodeChallenge string `json:"codeChallenge"`

	// ConsentToken is the receipt of this service's own consent page, required on
	// the org_app_domain lane only. It is a MAC under this deployment's keyset; a
	// caller can echo one and can mint none.
	//
	// 🔴 THERE IS NO consentNonce FIELD, AND ITS ABSENCE IS THE CONTROL. The
	// reference it is a MAC over is minted at registration and sealed in, so
	// Authorize checks the token against a value THIS service issued for THIS
	// domain. With both halves caller-supplied, one acknowledgement authorized
	// every later wildcard grant on the anchor. The residual limit — the
	// acknowledgement is scoped to the registration, not to one attempt — is
	// stated in consent.Token.
	ConsentToken string `json:"consentToken,omitempty"`
}

// CompleteRequest exchanges the authorization code and publishes. It carries no
// identity, no lane and no domain: all three come out of the sealed State, which
// cannot disagree with itself the way two cross-checked requests can.
type CompleteRequest struct {
	// State is the envelope Authorize minted and the provider echoed back.
	State string `json:"state"`

	Code         string `json:"code"`
	CodeVerifier string `json:"codeVerifier"`

	// ExpectDigest is the hex SHA-256 of the plan the customer reviewed.
	// Required; empty is REFUSED, because an integrity check a caller can turn
	// off by omitting a field is a claim rather than a control — which is all the
	// legacy PublishRequest, where it is optional, has. It defends against a bug
	// in the private half, not against the private half: DESIGN §4.
	ExpectDigest string `json:"expectDigest"`
}

// AdvanceRequest runs one pass of the loop. There is no expectDigest, and that
// is not an oversight: later passes publish records that did not exist when the
// customer authorized — AWS and Cloudflare produce them minutes to hours later —
// so there was nothing to approve. What bounds them instead is the anchor and
// internal/relay's value check (DESIGN §4).
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

	// Reason is free text, logged and nothing else: it reaches no provider call
	// and no record, and exists so an operator can tell a domain that was deleted
	// from one whose window simply closed (DESIGN §5).
	Reason string `json:"reason,omitempty"`
}

// requestTypes is every request struct on this surface, and the reflection
// test's input: reflect_test.go parses this file for every `…Request` declaration
// and asserts each appears here, so the §5 contract cannot be escaped by
// declaring a struct and forgetting to list it.
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
// §5 bounds what a caller may SEND, and deliberately not what this service
// answers: a response carries the records, their purposes, their sources and
// what was observed at each one, because that is the whole product.

// RecordView is one record as a person reads it — the same bytes on the manual
// path and the delegated path, from one derivation, so the list a customer is
// told to add by hand cannot drift from what this service writes (DESIGN §2).
type RecordView struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Value   string `json:"value"`
	Proxied bool   `json:"proxied"`

	// Purpose is why the record is here; Source is who writes it, and is a safety
	// property rather than a label: "customer" means this service never publishes
	// the row, which is the fix for the unproven anchor.
	Purpose string `json:"purpose"`
	Source  string `json:"source"`

	// Host is the hostname this record SERVES, not the record's own name:
	// `_acme-challenge.api.example.com` serves `api.example.com`. Empty for the
	// ownership proof, which is anchored above every host at once.
	Host string `json:"host,omitempty"`

	// Explain names the CONSEQUENCE of deleting this record and WHEN it arrives.
	// "Immediately" and "silently, months from now" are different risks.
	Explain string `json:"explain,omitempty"`

	// State and Found are set only by the read-only functions (Describe, Verify,
	// Orphans). An empty State means nothing was looked up, never "absent".
	State string   `json:"state,omitempty"`
	Found []string `json:"found,omitempty"`

	// Agreement says how many independent vantage points State rests on. Absent
	// means no lookup was issued for this row.
	Agreement *AgreementView `json:"agreement,omitempty"`
}

// AgreementView is one reading's vantage-point count, so "the proof is
// published" can be read for what it is worth rather than taken on trust.
type AgreementView struct {
	// Asked is how many vantage points were queried, Agreed how many served this
	// reading, and Threshold how many had to. `1 / 1 / 1` is a single recursive
	// resolver, believed on its own.
	Asked     int `json:"asked"`
	Agreed    int `json:"agreed"`
	Threshold int `json:"threshold"`
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

// Reviewable is the identity list a caller compares a customer's reviewed set
// against: exactly the records Digest is computed over, in the same
// TYPE|name|value form dnsplan uses.
//
// 🔴 IT IS NOT Records, AND THE DIFFERENCE IS WHY THIS EXISTS. Records is
// everything a console should SHOW — the ownership proof the customer publishes,
// and on Describe the relayed ACM and serving rows too. Digest binds only what
// this service will WRITE from its own derivation. On lane 1 converged that is
// 8 rows against as many as 16.
//
// Comparing a reviewed list against Records therefore mismatches in two ways
// that no customer action can fix: the ownership row is theirs and its value is
// recomputed here, and the relayed rows ARRIVE DURING THE CONSENT WINDOW, so the
// list grows while the digest deliberately does not. A caller that binds to the
// larger set manufactures a plan-changed refusal out of upstreams answering.
//
// Built from the same publishable() the digest is taken over, so the two cannot
// drift — see TestTheReviewableSetIsExactlyWhatTheDigestBinds.
func reviewableIdentities(records []dnsplan.Record) []string {
	_, identities, err := dnsplan.NormalizeRecords(records)
	if err != nil {
		// NewSnapshot already normalized these to build the digest, so a failure
		// here means the two disagree — report nothing rather than a partial list
		// a caller would compare against.
		return nil
	}
	return identities
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
	view.Agreement = agreementView(obs)
	if obs.Explain != "" {
		view.Explain = obs.Explain
	}
	return view
}

// agreementView projects a reading's vantage-point count. Nil when no lookup was
// issued, which is not the same as a lookup nobody agreed on.
func agreementView(obs observe.Observation) *AgreementView {
	if obs.Agreement.Asked == 0 {
		return nil
	}
	return &AgreementView{
		Asked:     obs.Agreement.Asked,
		Agreed:    obs.Agreement.Agreed,
		Threshold: obs.Agreement.Threshold,
	}
}

// RegisteredResponse is what all three registration intents return. None of them
// touches a credential and none of them writes anything.
type RegisteredResponse struct {
	// Registration is the sealed envelope every later call takes. The private
	// half stores it; it cannot author, edit or reorder one.
	Registration string `json:"registration"`

	// KeyID is the key the envelope was sealed under, returned so an operator can
	// answer "is the retired key still needed?" — this service holds no row to
	// answer it from.
	KeyID string `json:"keyId"`

	Lane   string   `json:"lane"`
	Anchor string   `json:"anchor"`
	Hosts  []string `json:"hosts"`

	// Proof is record 1: the TXT the CUSTOMER publishes, at the anchor. Also in
	// Records, lifted out because nothing else can happen until it exists.
	Proof RecordView `json:"proof"`

	// Records is every record this registration implies, ownership first. The
	// relayed rows (5 and 7) are absent because AWS and Cloudflare have not been
	// asked and their bytes do not exist; Describe reports them once they do.
	Records []RecordView `json:"records"`

	// Digest is the hex SHA-256 of the records this service would WRITE — the
	// derived, publishable set, the customer's own proof excluded because we
	// never write it. Complete refuses a plan that does not reproduce it.
	Digest string `json:"digest"`

	// Reviewable is exactly what Digest binds, as TYPE|name|value identities: the
	// set a caller compares a customer's reviewed list against. It is a SUBSET of
	// Records — see reviewableIdentities for why comparing against Records instead
	// manufactures a plan-changed refusal no customer action can fix.
	Reviewable []string `json:"reviewable,omitempty"`

	// GrantSeconds is how long a grant on this lane is held once authorized, 0
	// meaning STANDING. Published so the private half stores an expiry it did not
	// invent and a customer reads the lifetime before authorizing.
	GrantSeconds int64 `json:"grantSeconds"`
}

// VerifyResponse reports whether the ownership proof resolves in public DNS.
type VerifyResponse struct {
	Verified bool   `json:"verified"`
	Name     string `json:"name"`

	// Unresolved means the LOOKUP did not complete, so Verified being false is
	// not a statement about the customer's zone at all: "you have not published
	// it" against "we could not look", and showing the first for the second sends
	// a customer to edit a record that is already correct. Proof.State says the
	// same in internal/observe's vocabulary (unknown, never absent); this field
	// is here so a caller branching only on the boolean cannot miss it. See
	// Service.Verify for why it is not an RPC error.
	Unresolved bool `json:"unresolved,omitempty"`

	// Expected is the value to publish TODAY — the MAC under the active key.
	// Verification accepts one value per key in the keyset, so a proof published
	// before a rotation still verifies; echoing the whole accept set would put
	// retired keys' values in front of a customer.
	Expected string `json:"expected"`

	Proof RecordView `json:"proof"`
}

// AuthorizeResponse carries the consent URL and the state this service minted.
type AuthorizeResponse struct {
	AuthorizationURL string `json:"authorizationUrl"`

	// State is returned so the caller can match the provider's redirect to its
	// row, and is echoed back to Complete verbatim. The caller cannot author one:
	// it is a sealed envelope carrying the lane, identity, anchor and a nonce.
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
	// records to add by hand are in the response. Not a failure, and not the
	// caller's choice: whether a usable credential exists is a fact this service
	// establishes (see Service.BindAppToOrgAppDomain). A customer who never
	// authorized, or who revoked, gets a working answer instead of an error.
	ResultManual = "manual"

	// ResultStopped — the ownership proof no longer resolves, so nothing was
	// written and nothing will be until it is republished. The customer's first
	// stop control (DESIGN §8), effective within one pass and needing no call to
	// MirrorStack.
	ResultStopped = "stopped"

	// ResultDeferred — nothing conclusive happened: the provider could not be
	// reached, or a write failed part way. Try again on the next tick. Separate
	// from manual because the two look identical in a boolean and mean opposite
	// things: manual says "we cannot write for you, here is the list", deferred
	// says "we can, and we will — do not go and type them in by hand".
	ResultDeferred = "deferred"
)

// PassResponse is the answer from every function that can write: Complete,
// Advance and BindAppToOrgAppDomain. One type, because DESIGN §3 and §4 say the
// three degrade identically.
type PassResponse struct {
	// Result is one of the four constants above.
	Result string `json:"result"`

	// Published is the identity list actually written, in plan order, in
	// dnsplan's normalized TYPE|name|value form.
	Published []string `json:"published,omitempty"`

	// Records is the full record set for this pass, always — on every Result. On
	// the manual path it is the list to add by hand; on the published path it is
	// what was written and why. One list, so a console cannot render two.
	Records []RecordView `json:"records,omitempty"`

	// Digest is the hex SHA-256 of the reviewable (derived) record set, the same
	// value RegisteredResponse carries.
	Digest string `json:"digest,omitempty"`

	// SealedToken and KeyID are set whenever this service holds a credential the
	// caller must persist — INCLUDING when Failure is set. PERSIST THEM FIRST.
	//
	// 🔴 AN EMPTY SealedToken NEVER MEANS "DISCARD THE ONE YOU HOLD." It means
	// this service has no replacement to hand over, the normal case on a pass
	// that never opened the grant at all — a withdrawn proof, or a call that
	// carried no token. A caller that blindly overwrites its column with an empty
	// string erases a live grant that nothing can then release.
	SealedToken string `json:"sealedToken,omitempty"`
	KeyID       string `json:"keyId,omitempty"`

	// Rotated reports that the provider replaced the refresh token during this
	// pass, so the caller's stored copy is already dead.
	Rotated bool `json:"rotated"`

	// Revoked is the ONLY field that means "discard the credential you hold":
	// this service ended the grant at the provider, because it published and then
	// could not hold what it was given, or because it was left holding a
	// credential nothing would ever release. A dead grant this service did NOT
	// end is signalled instead by Failure.Code (token_unreadable, invalid_grant)
	// with Retry false — same caller action, but only one of the two is a
	// revocation that actually happened.
	Revoked bool `json:"revoked"`

	// GrantSeconds is this lane's hold, 0 for standing. See
	// RegisteredResponse.GrantSeconds.
	GrantSeconds int64 `json:"grantSeconds"`

	// Failure describes an outcome that reached the provider, or the reason there
	// is no usable credential. Nil on a clean pass.
	Failure *Failure `json:"failure,omitempty"`

	// Warnings are MirrorStack-side problems that did not stop the pass — most
	// often an upstream (AWS, Cloudflare) that could not be read, so the records
	// it owes are simply not in this pass; the next one re-reads. Reported rather
	// than swallowed: see Service.relayInto.
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

	// Proof is the ownership row with its own verdict, computed against every key
	// in the keyset rather than against today's value. See Service.Describe.
	Proof RecordView `json:"proof"`

	Verified bool   `json:"verified"`
	Digest   string `json:"digest"`

	// Reviewable is exactly what Digest binds, as TYPE|name|value identities: the
	// set a caller compares a customer's reviewed list against. It is a SUBSET of
	// Records — see reviewableIdentities for why comparing against Records instead
	// manufactures a plan-changed refusal no customer action can fix.
	Reviewable   []string `json:"reviewable,omitempty"`
	GrantSeconds int64    `json:"grantSeconds"`
	Warnings     []string `json:"warnings,omitempty"`
}

// OrphansResponse reports what this service left behind.
//
// A report, never a mutation: there is no delete anywhere in this service
// (dnsprovider.Provider has no such method), and adding one is a design change
// rather than a refactor — no provider in scope offers a conditional mutation,
// so a compensating delete cannot prove it is undoing OUR write rather than
// clobbering an edit the customer made a second ago.
type OrphansResponse struct {
	Anchor string `json:"anchor"`

	// ReadThrough is "provider" when the customer's own zone was read with their
	// grant, and "public-dns" when it was not — no grant supplied, none that could
	// be opened, the provider refused, or the refreshed grant could not be held.
	// Public DNS is cached and shows what the world sees; the provider shows what
	// is actually in the zone.
	ReadThrough string `json:"readThrough"`

	// Records are the names this service would have written, with what is at them
	// now. A record whose State is absent has already gone.
	Records []RecordView `json:"records"`

	// 🔴 THE HONEST LIMIT: THIS LIST IS DERIVED, NOT REMEMBERED. This service
	// keeps no published-record cursor (DESIGN §7), so it reports what the
	// CURRENT derivation would write and what is at those names now. A record
	// written months ago under a derivation that has since changed — a routing
	// target that moved, a certificate name AWS has stopped asking for — is not
	// in this list and cannot be. Nothing in a stateless design can enumerate it,
	// and claiming otherwise would be the more comfortable lie.
	Incomplete bool `json:"incomplete"`

	// SealedToken, KeyID and Rotated mean what they do on PassResponse: reading
	// the zone with the customer's grant REFRESHES it, so the stored copy is
	// already dead and the replacement here must be persisted.
	SealedToken string `json:"sealedToken,omitempty"`
	KeyID       string `json:"keyId,omitempty"`
	Rotated     bool   `json:"rotated"`

	// Revoked means this service ended the grant, which a report can genuinely
	// do: the refresh rotates the grant, and if the replacement cannot be sealed
	// there is nothing to hand back — a live grant nothing will ever release. It
	// is ended rather than stranded, as write() does, and Failure.Code says
	// reseal_failed. Nothing else in Orphans revokes.
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
// deployment can do and what it would put in a zone — before anything is asked of
// anyone. It writes nothing and needs no registration, and it publishes the
// routing targets so a customer can check the CNAME value they will be asked for
// against the one this repository derives (DESIGN §4).
type CapabilitiesResponse struct {
	Available bool     `json:"available"`
	CanHold   bool     `json:"canHold"`
	Provider  string   `json:"provider"`
	Scopes    []string `json:"scopes,omitempty"`

	Lanes []LaneCapability `json:"lanes,omitempty"`

	OrgRoutingTarget string `json:"orgRoutingTarget,omitempty"`
	AppRoutingTarget string `json:"appRoutingTarget,omitempty"`

	// DCVDelegationUUID is the CONFIGURED identifier — CF_ORG_DCV_DELEGATION_UUID
	// — and not necessarily the one in force. What each lane actually derives
	// record 6 from, and where it came from, is on the lane entries below.
	DCVDelegationUUID string `json:"dcvDelegationUuid,omitempty"`

	// ConfigError names a deployment whose derivation configuration is
	// incomplete, in the same words the derivation would refuse with. Without it
	// a misconfigured deployment and an unconfigured one look identical from
	// outside — the trap cfoauth.FromEnv documents.
	ConfigError string `json:"configError,omitempty"`

	// The loop's declared clock, so "how often could MirrorStack touch my zone" is
	// answerable from this API (DESIGN §8). internal/schedule is the source.
	IntervalSeconds    int64 `json:"intervalSeconds"`
	JitterSeconds      int64 `json:"jitterSeconds"`
	MinIntervalSeconds int64 `json:"minIntervalSeconds"`

	// Resolution is how this deployment reads the ownership proof, published
	// BEFORE anything is authorized because it is what a positive verification is
	// worth (docs/THREAT-MODEL.md, "We assume public DNS tells us the truth").
	Resolution ResolutionCapability `json:"resolution"`
}

// ResolutionCapability is the deployment's vantage-point rule, from
// observe.PolicyOf on the resolver the binary actually wired, beside a
// measurement of whether those vantage points can be reached from where it runs.
type ResolutionCapability struct {
	// Vantages is how many independent resolvers are asked and Threshold how many
	// must agree before a proof counts as published. `1` and `1` is a single
	// recursive resolver.
	Vantages  int `json:"vantages"`
	Threshold int `json:"threshold"`

	// Authoritative reports that one vantage point asks the zone's own
	// nameservers rather than a recursive resolver.
	Authoritative bool `json:"authoritative"`

	// DNSSEC is always false. Nothing in this repository validates a signature,
	// and the field exists so that is answerable from the API rather than only
	// from a source file.
	DNSSEC bool `json:"dnssec"`

	// Reachability is what the vantage points above actually answered. Absent
	// means unmeasured — no probe is wired — which is not the same as
	// unreachable.
	Reachability *ReachabilityView `json:"reachability,omitempty"`
}

// ReachabilityView answers the question a configuration file cannot: can this
// deployment reach the resolvers it was configured with? It comes from
// observe.Probe, which resolves a name that must always resolve at each vantage
// point on a TTL.
type ReachabilityView struct {
	// Reachable is how many vantage points answered, out of Vantages above, and
	// CheckedAt when they were last asked.
	Reachable int    `json:"reachable"`
	CheckedAt string `json:"checkedAt"`

	// Degraded means the reachable vantage points can no longer meet Threshold.
	//
	// 🔴 THAT IS A BROKEN DEPLOYMENT, NEVER A SMALLER QUORUM. Threshold above
	// still stands, so every proof reads `unknown` and every authorization is
	// refused until the egress is fixed — the health check fails for the same
	// reason.
	Degraded bool `json:"degraded"`

	// Points names each vantage point and whether it answered: what an operator
	// acts on.
	Points []VantageView `json:"points"`
}

// VantageView is one vantage point's reachability.
type VantageView struct {
	// Vantage is how it is addressed — a nameserver address, or the container's
	// own resolver.
	Vantage   string `json:"vantage"`
	Reachable bool   `json:"reachable"`

	// Explain is why it did not answer.
	Explain string `json:"explain,omitempty"`
}

// reachabilityView projects a probe reading. Nil when no sweep has run, which is
// not the same as a sweep in which nothing answered.
func reachabilityView(r observe.Reach) *ReachabilityView {
	if r.CheckedAt.IsZero() {
		return nil
	}
	out := &ReachabilityView{
		Reachable: r.Reachable(),
		CheckedAt: r.CheckedAt.UTC().Format(time.RFC3339),
		Degraded:  r.Degraded(),
		Points:    make([]VantageView, 0, len(r.Vantages)),
	}
	for _, v := range r.Vantages {
		out.Points = append(out.Points, VantageView{
			Vantage:   v.Vantage,
			Reachable: v.Reachable,
			Explain:   v.Explain,
		})
	}
	return out
}

// LaneCapability is one lane, described in the terms a customer decides on.
type LaneCapability struct {
	Lane   string `json:"lane"`
	Hosts  string `json:"hosts"`
	Anchor string `json:"anchor"`

	// GrantSeconds is 0 for a standing grant. ConsentPage marks the lane whose
	// scope a customer cannot enumerate, where this service serves its own
	// consent screen.
	GrantSeconds int64 `json:"grantSeconds"`
	ConsentPage  bool  `json:"consentPage"`

	// EdgeZone is the MirrorStack Cloudflare zone this deployment reads record 7,
	// the serving proof, from for this lane. Empty means the relay is not wired
	// for it, and that lane's `_cf-custom-hostname` will not appear in any plan.
	//
	// 🔴 PUBLISHED SO THE PER-LANE ZONE IS AUDITABLE FROM OUTSIDE. Lane 1 lives in
	// MirrorStack's org zone and lanes 2 and 3 in the app/SaaS zone, so one id
	// against all three, or the two swapped, is a misconfiguration whose only
	// other symptom is hosts that answer 526 with a healthy certificate. A zone id
	// is an identifier and not a credential; it appears in every Cloudflare
	// dashboard URL.
	EdgeZone string `json:"edgeZone,omitempty"`

	// DCVDelegationUUID is the identifier this lane's record 6 points at, and
	// DCVDelegationSource is where it came from: DCVFromCloudflare when this
	// deployment read it from the zone above, DCVFromConfig when it fell back to
	// the environment, empty when there is none and record 6 cannot be derived.
	//
	// 🔴 PUBLISHED SO A HAND-SET IDENTIFIER IS TELLABLE FROM A VERIFIED ONE. The
	// identifier is per zone and one environment variable covers all three lanes,
	// so a value that is right for the org zone is a guess about the app zone;
	// record 6 is published on the first pass and never republished, and a wrong
	// label is a certificate that never issues with the record looking correct.
	DCVDelegationUUID   string `json:"dcvDelegationUuid,omitempty"`
	DCVDelegationSource string `json:"dcvDelegationSource,omitempty"`
}

// Where a lane's DCV delegation identifier came from, reported by capabilities.
const (
	// DCVFromCloudflare: read from `GET /zones/{zone_id}/dcv_delegation/uuid`
	// under MirrorStack's own token, and the one that wins on a disagreement.
	DCVFromCloudflare = "cloudflare"

	// DCVFromConfig: CF_ORG_DCV_DELEGATION_UUID, hand-set — either because this
	// deployment holds no Cloudflare credential or because the read failed.
	DCVFromConfig = "configured"
)

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
	// FailureProvider — refused or unreachable. The grant is intact; a later pass
	// may succeed.
	FailureProvider = "provider_failure"
	// FailurePlanPreparing — the plan is not publishable yet. Not a fault.
	FailurePlanPreparing = "plan_preparing"
	// FailureTokenUnreadable — the sealed grant cannot be opened under this keyset
	// and registration. Dead; release the row.
	FailureTokenUnreadable = "token_unreadable"
	// FailureInvalidGrant — the provider rejected the refresh token. Dead; release
	// it, and do NOT attempt to revoke: there is nothing to revoke.
	FailureInvalidGrant = "invalid_grant"
	// FailureResealFailed — the rotated token could not be sealed, so it has been
	// revoked at the provider. Dead and safe.
	FailureResealFailed = "reseal_failed"
	// FailureNoGrant — no credential was supplied: the ordinary state of a
	// customer who never authorized, and why Result is manual rather than an error.
	FailureNoGrant = "no_grant"
	// FailureProofWithdrawn — the ownership proof no longer resolves and nothing
	// was written. Republishing the TXT resumes the loop; nothing else is needed.
	FailureProofWithdrawn = "proof_withdrawn"
)
