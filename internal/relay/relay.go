// Package relay reads the two proofs this service does NOT derive.
//
// Records 5 and 7 of docs/DESIGN.md §6 are RELAYED, not derived. This service
// derives THAT a proof must exist and WHY; their bytes come from AWS and from
// Cloudflare, and no amount of reading this repository will let you predict
// them. Both halves of that belong in public — "the engine derives the record
// set" is true of which proofs exist and false of every byte, and someone
// deciding whether to hand this service a DNS credential is owed the difference.
//
//	5  _<token>.<host>             CNAME  <token>.acm-validations.aws   lane 1 only
//	7  _cf-custom-hostname.<host>  TXT    the serving proof             all lanes
//
// Record 6 (_acme-challenge.<host>) is deliberately NOT here. It is a pointer at
// Cloudflare's delegated DCV location, and both halves of it — the hostname the
// customer connected and a per-zone uuid — are known before anything is asked of
// anyone. That is why it is derived rather than relayed, and it is what lets a
// closed lane hold a credential for 24 hours instead of forever.
//
// 🔴 NOTHING IN THIS PACKAGE TOUCHES A CUSTOMER'S ZONE.
//
// It reads two upstreams with MirrorStack's own credentials and returns records.
// Whatever it returns still passes anchor containment in internal/dnsplan and is
// still published by internal/reconcile under the never-delete rule, exactly
// like a derived record. A relayed record gets no shortcut for having come from
// somewhere trusted.
package relay

import (
	"context"
	"errors"
	"strings"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
)

// ErrUnexpectedRecord means an upstream handed back something this service will
// not publish: a record type it cannot be, an empty name, or a value that does
// not name the validation zone it is supposed to.
//
// 🔴 A REFUSAL, NOT A WAIT. "Not issued yet" is an empty answer with a nil error
// (see CertificateAuthority), so anything that reaches this error is a claim the
// upstream's own contract says it cannot make. Publishing it anyway is how a
// wrong value ends up in a customer's zone with every dashboard green, and the
// value half is precisely what anchor containment cannot bound — containment
// bounds a record's NAME. So the value is bounded here, at the only place that
// knows what the value is supposed to be.
var ErrUnexpectedRecord = errors.New("relay: upstream returned a record this service will not publish")

// CertificateAuthority is AWS ACM, read for record 5 (lane 1 only).
//
// 🔴 STATELESS: we hold no certificate id. Every pass re-reads. The validation
// records are EMPTY until AWS has issued them, which is a WAIT, not a fault —
// return no records and no error for that case.
//
// That wait is not theoretical and it has shipped broken twice. RequestCertificate
// returns an ARN immediately and ACM populates the validation record seconds to
// minutes later, so a certificate is routinely present-but-recordless for the
// first minutes of its life. Absent means not yet; only a terminal certificate
// status ever justifies refusing.
type CertificateAuthority interface {
	ValidationRecords(ctx context.Context, hosts []string) ([]dnsplan.Record, error)
}

// EdgeHostnames is Cloudflare for SaaS, read for record 7 on every lane.
//
// 🔴 THIS READ USES MIRRORSTACK'S OWN ZONE CREDENTIAL, NEVER THE CUSTOMER'S
// GRANT. The custom hostname lives in OUR zone; the customer's token has no
// business being sent to it, and sending it there would widen what that grant is
// used for beyond what the consent screen described. The two credentials are
// separate variables in separate packages for that reason: the customer's token
// is a per-call argument in internal/dnsprovider, and nothing in this package
// accepts one.
//
// Record 7 is the SECOND, SEPARATE proof — read by the edge, not by a
// certificate authority. See ServingProof in edge.go for what its absence looks
// like from the outside, which is the part worth reading twice.
type EdgeHostnames interface {
	ServingProof(ctx context.Context, host string) (record dnsplan.Record, ready bool, err error)
}

// ValidationRecords reads record 5 through ca for the given hosts.
//
// 🔴 A NIL ADAPTER IS "NOT YET", NEVER AN ERROR.
//
// Both relays are optional. Lane 2 and lane 3 request no ACM certificate at all,
// a deployment may not be configured for one, and a lane whose upstream is not
// wired must still publish the records it CAN derive rather than failing the
// whole pass. Reporting "no certificate reader" as an error would turn a lane
// that was never going to have record 5 into a permanently failing one.
//
// Pass a nil INTERFACE, not a nil pointer to a concrete type: ACM and Edge are
// value types precisely so a zero value is a usable value and a caller is not
// tempted to park a typed nil in the interface, which is non-nil and panics.
func ValidationRecords(ctx context.Context, ca CertificateAuthority, hosts []string) ([]dnsplan.Record, error) {
	if ca == nil {
		return nil, nil
	}
	return ca.ValidationRecords(ctx, hosts)
}

// ServingProof reads record 7 through edge for one host. A nil edge reports
// not-ready, for the same reason a nil CertificateAuthority reports no records.
func ServingProof(ctx context.Context, edge EdgeHostnames, host string) (dnsplan.Record, bool, error) {
	if edge == nil {
		return dnsplan.Record{}, false, nil
	}
	return edge.ServingProof(ctx, host)
}

// ServingProofs reads record 7 for several hosts and returns only the ones
// Cloudflare has actually minted.
//
// A partial answer is the NORMAL answer, not a degraded one. Cloudflare mints
// this proof when a custom hostname is created, and a lane-1 registration
// creates four of them; on any given pass some exist and some do not. Collecting
// what is ready and moving on is what makes the loop converge, and it is why
// this returns records rather than a per-host readiness map: a record that is
// not ready is simply not in the plan yet.
//
// Host order is preserved. That is not cosmetic — the plan's SHA-256 digest is
// computed over the record list in order, and a digest that reorders between two
// passes tells a customer mid-connect that the plan changed.
func ServingProofs(ctx context.Context, edge EdgeHostnames, hosts []string) ([]dnsplan.Record, error) {
	if edge == nil {
		return nil, nil
	}
	out := make([]dnsplan.Record, 0, len(hosts))
	for _, host := range hosts {
		record, ready, err := edge.ServingProof(ctx, host)
		if err != nil {
			return nil, err
		}
		if ready {
			out = append(out, record)
		}
	}
	return out, nil
}

// relayedRecord normalizes one upstream record into a plan record.
//
// 🔴 PROXIED IS ALWAYS FALSE, AND IT IS AN ANSWER RATHER THAN A DEFAULT.
//
// Every relayed name begins with an underscore. Cloudflare accepts proxied:true
// on such a name with no error at all, then answers with addresses instead of
// following the record — so the certificate authority finds IP addresses where
// it needed a CNAME, and issuance, or a renewal months later, fails with every
// dashboard still green. There is no case in which a relayed record wants the
// orange cloud, so this does not take the flag as a parameter.
func relayedRecord(recordType, name, value string) dnsplan.Record {
	value = strings.TrimSpace(value)
	if strings.EqualFold(recordType, "CNAME") {
		// A resolver answer and a zone file spell one target with and without
		// the root dot, and AWS returns it with. A TXT value is deliberately NOT
		// trimmed: a trailing dot inside a TXT value is data, not presentation.
		value = strings.TrimSuffix(value, ".")
	}
	return dnsplan.Record{
		Type:    strings.ToUpper(recordType),
		Name:    dnsplan.NormalizeName(name),
		Value:   value,
		Proxied: false,
	}
}

// normalizeHosts folds the caller's host list to lower case without the root
// dot, drops blanks, and removes duplicates while keeping the caller's order.
//
// Order is preserved for the same reason ServingProofs preserves it: the plan
// digest is order-sensitive, and a set built by ranging a map would reorder
// between passes and invalidate an in-flight authorization at random.
func normalizeHosts(hosts []string) []string {
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = dnsplan.NormalizeName(host)
		if host == "" || len(host) > dnsplan.MaxDNSName {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

// underAnyHost reports whether name sits at or under one of the hosts this pass
// asked about.
//
// 🔴 THE SUFFIX ALONE IS NOT ENOUGH; THE RECORD MUST BE BOUND TO A HOST WE
// ASKED FOR. A certificate can legitimately carry names we did not ask about,
// and a stale sibling registration's validation record looks exactly like a
// valid one until you check whose host it names. api-platform shipped that bug:
// a completeness gate that matched on the target suffix alone accepted another
// row's record and persisted it forever.
func underAnyHost(hosts []string, name string) bool {
	for _, host := range hosts {
		if dnsplan.Contains(host, name) {
			return true
		}
	}
	return false
}
