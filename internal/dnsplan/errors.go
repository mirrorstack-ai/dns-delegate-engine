package dnsplan

import (
	"errors"
	"fmt"
)

var (
	// ErrPlanInvalid covers every "this does not describe a reviewable plan"
	// case: a malformed target id, an anchor that is not a DNS name, a record
	// naming something outside the anchor, or a stored snapshot whose digest
	// does not reproduce.
	//
	// Deliberately ONE error at the boundary: distinguishing the causes for a
	// caller would tell an attacker which half of a state they guessed. The
	// specific cause is logged, and wrapped errors below carry it for tests.
	ErrPlanInvalid = errors.New("dnsplan: plan invalid")

	// ErrAnchorEscape is the containment refusal — a plan named a record outside
	// the anchor. It WRAPS ErrPlanInvalid (not a sibling of it) so a caller
	// matching the boundary keeps one opaque answer while logs and tests can
	// name the real cause. A sibling sentinel would let an escape slip past a
	// caller that only checks ErrPlanInvalid.
	ErrAnchorEscape = fmt.Errorf("%w: record outside the plan anchor", ErrPlanInvalid)

	// ErrProxiedValidation is the refusal for a plan that would hide a
	// certificate-validation record behind Cloudflare's proxy. Like
	// ErrAnchorEscape it WRAPS ErrPlanInvalid, so a caller matching the boundary
	// keeps one opaque answer while logs and tests can name the real cause.
	//
	// See assertNoProxiedValidation for why a provider accepting the setting is
	// exactly the reason this has to be refused here.
	ErrProxiedValidation = fmt.Errorf("%w: validation record is proxied", ErrPlanInvalid)

	// ErrPlanPreparing means the plan is not publishable yet — most commonly a
	// row with no durable validation record. It is a wait, not a fault.
	ErrPlanPreparing = errors.New("dnsplan: plan preparing")

	// ErrPlanChanged means the authoritative plan is not the plan the operator
	// reviewed. The caller must re-render and ask for authorization again;
	// publishing the new records silently would turn a reviewed grant into an
	// unreviewed one.
	ErrPlanChanged = errors.New("dnsplan: plan changed")
)
