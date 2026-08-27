// Package grant is the RPC surface api-platform calls.
//
// 🔴 THE SERVICE IS STATELESS. IT OWNS NO TABLE AND OPENS NO DATABASE.
//
// api-platform derives the plan and owns every row; this service owns the two
// things a plan cannot be published without — the OAuth client that talks to the
// provider, and the key that seals a held refresh token. api-platform therefore
// stores ciphertext it holds no key for, and this service holds a credential it
// has no place to persist. Neither half can act alone, and the public half is
// small enough to read.
//
// That is a stronger arrangement than giving this service its own database
// grant, which was the earlier design: there is no schema to drift, no
// migration to sequence, and no second writer to the customer's rows.
package grant

import "github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"

// Kinds mirror dnsplan's.
const (
	KindPlatform = dnsplan.KindPlatform
	KindApp      = dnsplan.KindApp
)

// CapabilitiesResponse tells api-platform what this deployment can offer, so the
// console renders no connect affordance rather than a button that fails on the
// provider's own consent screen.
type CapabilitiesResponse struct {
	Available bool     `json:"available"`
	CanHold   bool     `json:"canHold"`
	Provider  string   `json:"provider"`
	Scopes    []string `json:"scopes,omitempty"`
}

// AuthorizeRequest carries only the per-attempt values api-platform generated.
// The client id, the redirect URL and the scope list are this service's, so a
// caller cannot widen the request it sends a customer to.
type AuthorizeRequest struct {
	State         string `json:"state"`
	CodeChallenge string `json:"codeChallenge"`
}

type AuthorizeResponse struct {
	AuthorizationURL string `json:"authorizationUrl"`
}

// PublishRequest is one delegated write.
//
// Exactly one credential source must be set: Code+CodeVerifier for a first
// exchange, or SealedToken for a grant already held.
type PublishRequest struct {
	Kind     string           `json:"kind"`
	OrgID    string           `json:"orgId"`
	TargetID string           `json:"targetId"`
	Anchor   string           `json:"anchor"`
	Records  []dnsplan.Record `json:"records"`

	// Reviewed is the identity list the operator saw, if this call is a
	// completion. It is an equality ASSERTION only — no element of it is ever
	// decoded into a provider write.
	Reviewed []string `json:"reviewed,omitempty"`

	// ExpectedDigest is the hex SHA-256 api-platform stored on the attempt
	// BEFORE the customer authorized.
	//
	// 🔴 THIS IS THE CROSS-BOUNDARY INTEGRITY CHECK. This service recomputes the
	// digest from Records and refuses the write if it differs. A buggy — or
	// hostile — api-platform therefore cannot publish a plan the customer never
	// reviewed, even though it is the side that derives the plan.
	ExpectedDigest string `json:"expectedDigest,omitempty"`

	Code         string `json:"code,omitempty"`
	CodeVerifier string `json:"codeVerifier,omitempty"`
	SealedToken  string `json:"sealedToken,omitempty"`

	// Hold asks for the refresh token to be sealed and returned instead of
	// revoked, because the rest of this registration's records do not exist yet.
	Hold bool `json:"hold"`
}

// PublishResponse reports what happened to the plan AND to the credential.
//
// 🔴 A PUBLISH FAILURE AFTER A ROTATION IS REPORTED HERE, NOT AS AN RPC ERROR.
//
// Cloudflare rotates the refresh token on every use, so a failure that arrives
// after the refresh leaves the caller's stored token already dead. Reporting
// that as an error would give api-platform nothing to persist, and the grant
// would kill itself on the next pass holding a token the provider had already
// replaced — measured 2026-08-24, a grant that published nothing and then
// released itself.
//
// The rule: once a credential has been consumed or rotated, this call returns
// ok=true and describes the outcome in Failure. Refusals that consume nothing
// (unavailable, malformed, containment, digest mismatch) are RPC errors.
type PublishResponse struct {
	// Published is the identity list actually written, in plan order.
	Published []string `json:"published,omitempty"`

	// SealedToken and KeyID are set whenever this service holds a credential the
	// caller must persist — including when Failure is set. PERSIST THEM FIRST.
	SealedToken string `json:"sealedToken,omitempty"`
	KeyID       string `json:"keyId,omitempty"`

	Held    bool `json:"held"`
	Revoked bool `json:"revoked"`
	Rotated bool `json:"rotated"`

	Failure *Failure `json:"failure,omitempty"`
}

// Failure describes an outcome that reached the provider.
type Failure struct {
	// Code is the caller's contract. Retry is what distinguishes "try again
	// later" from "this grant is dead".
	Code    string `json:"code"`
	Message string `json:"message"`
	Retry   bool   `json:"retry"`
}

// Failure codes.
const (
	// FailureProvider — the provider refused or could not be reached. The grant
	// is intact; a later pass may succeed.
	FailureProvider = "provider_failure"
	// FailurePlanPreparing — the plan is not publishable yet. Not a fault.
	FailurePlanPreparing = "plan_preparing"
	// FailureTokenUnreadable — the sealed token cannot be opened under this
	// keyset and row identity. The grant is dead; release it.
	FailureTokenUnreadable = "token_unreadable"
	// FailureInvalidGrant — the provider rejected the refresh token. The grant is
	// dead; release it. Do NOT attempt to revoke: there is nothing to revoke.
	FailureInvalidGrant = "invalid_grant"
	// FailureResealFailed — the rotated token could not be sealed. It has been
	// revoked at the provider, so the grant is dead and safe.
	FailureResealFailed = "reseal_failed"
)

// RevokeRequest ends a grant at the provider.
type RevokeRequest struct {
	OrgID       string `json:"orgId"`
	TargetID    string `json:"targetId"`
	Anchor      string `json:"anchor"`
	SealedToken string `json:"sealedToken"`
}

type RevokeResponse struct {
	Revoked bool `json:"revoked"`
	// Unreadable means the envelope could not be opened, so nothing was sent to
	// the provider. The caller should still release its row — there is no way to
	// use the credential either — but a human may need to revoke by hand.
	Unreadable bool `json:"unreadable"`
}
