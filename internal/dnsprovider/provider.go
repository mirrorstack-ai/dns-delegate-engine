// Package dnsprovider is the seam between this service's safety rules and one
// DNS provider's API.
//
// 🔴 THE SAFETY INVARIANTS LIVE ABOVE THIS INTERFACE, NOT INSIDE AN ADAPTER.
//
// Cloudflare is the first provider; others will follow. Everything that bounds
// what a delegated credential can do to a customer's zone — never delete, read
// every affected name before writing any of them, update a routing record in
// place rather than adding a second one, never retry an ambiguous write, and do
// all of it inside one bounded window — is implemented once, in the reconciler,
// against this interface. An adapter cannot opt out of a rule it never sees.
//
// What a provider does own is genuinely provider-shaped: how a zone is located,
// the wire format, how "this already exists" and "this may or may not have
// applied" are spelled in its error vocabulary, and how it quotes a TXT value.
package dnsprovider

import (
	"context"
	"strings"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
)

// TrimTXTQuotes strips ONE MATCHED PAIR of surrounding double quotes — the DNS
// presentation wrapper, which a zone file writes and most provider APIs do not.
//
// 🔴 IT IS THE ONE COMPARISON FORM FOR A TXT VALUE, ON THE WRITE PATH AND THE
// READ PATH ALIKE. The write path asks "is this value already correct" and the
// read path asks "is this proof published"; two spellings of that question mean
// a value one accepts and the other rewrites or refuses.
//
// Matched, never `strings.Trim`: an unbalanced or doubled quote is DATA, and
// eating it makes two different values compare equal.
func TrimTXTQuotes(v string) string {
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		return v[1 : len(v)-1]
	}
	return v
}

// LiveRecord is one record as the provider currently holds it.
type LiveRecord struct {
	ID      string
	Type    string
	Name    string
	Value   string
	Proxied bool
}

// Desired is one record the reconciler wants to exist. It is derived from a
// dnsplan.Record that has already passed anchor containment; an adapter must
// never widen it.
type Desired struct {
	Type    string
	Name    string
	Value   string
	Proxied bool
}

// DesiredFrom projects a contained plan record onto a provider write.
func DesiredFrom(record dnsplan.Record) Desired {
	return Desired{Type: record.Type, Name: record.Name, Value: record.Value, Proxied: record.Proxied}
}

// Provider is one DNS provider's API, reduced to the four calls a forward-only
// reconciler needs.
//
// 🔴 THERE IS NO Delete METHOD, AND ADDING ONE IS A DESIGN CHANGE.
//
// Publication is forward-only. No DNS provider in scope offers a conditional
// mutation (a compare-and-set on a record version), so a compensating delete
// cannot prove it is undoing OUR write rather than clobbering an edit the
// customer made a second ago. A failed pass therefore leaves an approved prefix
// of the reviewed plan, and the next authorization re-reads and converges. That
// is the property the customer's own developers are being asked to check: this
// service has no code path that removes a record.
type Provider interface {
	// Name identifies the provider in logs and in stored grant rows.
	Name() string

	// FindZone resolves the zone that holds name, using the customer's token.
	// It must select the most specific zone the credential can see; picking a
	// parent zone would let a write land beside records the plan never named.
	FindZone(ctx context.Context, token, name string) (zoneID string, err error)

	// ListRecordsAt returns every record at exactly one owner name. The
	// reconciler calls this for each distinct name BEFORE it writes anything, so
	// the decision to create or update is made against a coherent read.
	ListRecordsAt(ctx context.Context, token, zoneID, name string) ([]LiveRecord, error)

	// CreateRecord adds a record. It must not delete or replace anything.
	CreateRecord(ctx context.Context, token, zoneID string, desired Desired) (id string, err error)

	// PatchRecord updates the record with this id in place. Updating in place is
	// what keeps a second, conflicting routing record from appearing at an owner
	// the customer is already serving from.
	PatchRecord(ctx context.Context, token, zoneID, id string, desired Desired) error

	// SameValue reports whether a live value already satisfies a desired one for
	// this record type. It exists because providers differ on presentation —
	// Cloudflare returns TXT content unquoted where the zone file quotes it —
	// and a false negative here writes a duplicate record into a customer's zone.
	SameValue(recordType, live, desired string) bool

	// IsDuplicate reports the provider's "this record already exists" answer. It
	// proves only that something raced the create, never that the existing row
	// is the desired one, so the reconciler still verifies by reading.
	IsDuplicate(err error) bool

	// IsAmbiguous reports whether an error leaves it unknown whether the
	// mutation committed — a timeout, a rate limit, a 5xx, or any transport or
	// decode failure. An ambiguous outcome is resolved by a bounded READ, never
	// by a second write.
	//
	// 🔴 FAIL TOWARD AMBIGUOUS. An adapter that returns false for an error it
	// does not recognise is claiming certainty it does not have, and the
	// reconciler would treat a possibly-applied write as definitively failed.
	IsAmbiguous(err error) bool
}
