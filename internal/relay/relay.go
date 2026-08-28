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
//
// 🔴 AND THE BOUNDS ON A RELAYED RECORD LIVE IN THIS FILE, NOT IN AN ADAPTER.
//
// ACM and Cloudflare for SaaS are the upstreams wired today; either can be
// swapped, and ACM's answer changes shape whenever AWS decides it does. So every
// rule about what a relayed record may BE — its type, an underscore name beneath
// a host this pass actually asked about, and a value the upstream does not get
// to choose freely — is applied by the free functions below, against the
// interfaces, the way internal/dnsprovider holds the write rules above its
// Provider. An adapter cannot opt out of a rule it never sees.
//
// What acm.go and edge.go keep is genuinely upstream-shaped: the wire format,
// the paging, and the difference between "not issued yet" and "failed".
package relay

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
)

// ErrUnexpectedRecord means an upstream handed back something this service will
// not publish: a record type it cannot be, an empty name, a name outside the
// hosts this pass asked about, a value that is not the shape the proof takes, or
// more records than a plan can hold.
//
// 🔴 A REFUSAL, NOT A WAIT. "Not issued yet" is an empty answer with a nil error
// (see CertificateAuthority), so anything that reaches this error is a claim the
// upstream's own contract says it cannot make. Publishing it anyway is how a
// wrong value ends up in a customer's zone with every dashboard green, and the
// value half is precisely what anchor containment cannot bound — containment
// bounds a record's NAME. So both halves are bounded in ValidationRecords and
// ServingProof below, ABOVE the interfaces, rather than inside whichever adapter
// happens to be wired.
var ErrUnexpectedRecord = errors.New("relay: upstream returned a record this service will not publish")

// ValidationTargetSuffix is the only zone an ACM DNS validation record may point
// at.
//
// 🔴 THIS BOUNDS THE HALF THAT CONTAINMENT CANNOT.
//
// dnsplan.Contains bounds a record's NAME to the subtree the customer proved
// they own. Nothing bounds its VALUE, and a relayed value is by definition one
// this repository cannot show you. So the value is checked against the only
// thing that is knowable about it in advance: an ACM DNS validation record
// always points into AWS's validation zone. A value that does not is refused
// loudly rather than dropped quietly, because a silently-dropped validation
// record looks identical to a certificate AWS has simply not filled in yet, and
// would sit "preparing" forever with nothing to read.
const ValidationTargetSuffix = ".acm-validations.aws"

// ownershipRecordPrefix is the owner name Cloudflare mints the serving proof at.
// It is here to be asserted against, not to be constructed from: the name is
// relayed verbatim, and this constant only checks that what came back is the
// record that was asked for.
const ownershipRecordPrefix = "_cf-custom-hostname."

// MaxRelayed is how many records this relay may add to one plan.
//
// It is a RESERVE, not the plan's whole budget, because the derived records are
// already in the plan by the time a relayed one is merged. The arithmetic, for a
// reader checking whether a large certificate estate can break their lane:
//
//	a plan holds                        dnsplan.MaxRecords = 128 records
//	the largest derived lane is lane 1:  1 ownership proof
//	                                     4 routing CNAMEs   (account api apps cdn)
//	                                     4 DCV pointers     (one per host)
//	                                     = 9 derived
//	relayed, worst case:                 3 ACM validations  (cdn owns no AWS cert)
//	                                     4 serving proofs   (one per host)
//	                                     = 7 relayed in practice
//
// So the real shapes are nowhere near the limit, and the reserve exists for the
// pathological upstream rather than the ordinary one. 64 leaves the derived side
// room to double twice over and still fit, and refuses an answer long before it
// could push a plan past dnsplan.MaxRecords — where the overflow would be spelled
// ErrPlanPreparing and read by the caller as a wait that never resolves.
//
// 🔴 IT IS COUNTED AFTER DEDUP. Counting before it counts certificates rather
// than records; see ValidationRecords.
const MaxRelayed = 64

// maxServingProofValue bounds the relayed TXT value at DNS's own limit — one TXT
// character-string carries at most 255 octets.
//
// 🔴 THIS CANNOT TELL A RIGHT PROOF FROM A WRONG ONE. The value is a token only
// Cloudflare can compute, so nothing in this repository can check that it means
// anything; a wrong-but-well-formed value is indistinguishable from a right one
// here and shows up later as a host that never starts serving. What the bound
// does is smaller and still worth having: it stops whatever answers the
// custom_hostnames endpoint from choosing an ARBITRARY payload to be published
// under a customer's own name. The value is unpredictable; its SHAPE is not.
const maxServingProofValue = 255

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
//
// An implementation is trusted to find the records and to spell the upstream's
// errors. It is NOT trusted about what may be published: ValidationRecords
// re-checks every record it is handed.
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
//
// As with CertificateAuthority, an implementation decides what it FOUND; the
// free ServingProof decides what may be published.
type EdgeHostnames interface {
	ServingProof(ctx context.Context, host string) (record dnsplan.Record, ready bool, err error)
}

// ValidationRecords reads record 5 through ca for the given hosts, and bounds
// every record it hands back.
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
//
// 🔴 THE ANSWER IS CHECKED, NOT TRUSTED. ca is an interface: internal/relay's
// ACM is one implementation, a test fake is another, and a second certificate
// authority would be a third. So each record proves itself again here — a CNAME,
// at an underscore name beneath a host this pass asked about, pointing into the
// AWS validation zone — before it can reach a plan. A bound that lived only in
// acm.go would be a bound the next implementation silently does not have, with
// every comment in this package still reading true.
func ValidationRecords(ctx context.Context, ca CertificateAuthority, hosts []string) ([]dnsplan.Record, error) {
	if ca == nil {
		return nil, nil
	}
	wanted := normalizeHosts(hosts)
	if len(wanted) == 0 {
		return nil, nil
	}
	records, err := ca.ValidationRecords(ctx, wanted)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(records))
	out := make([]dnsplan.Record, 0, len(records))
	for _, record := range records {
		checked, err := checkedValidationRecord(wanted, record)
		if err != nil {
			return nil, err
		}
		identity := checked.Type + "|" + checked.Name + "|" + checked.Value
		if _, ok := seen[identity]; ok {
			continue
		}
		seen[identity] = struct{}{}
		out = append(out, checked)
	}
	// 🔴 THE BOUND IS TAKEN AFTER DEDUP, AND AGAINST THE RELAY'S SHARE OF THE
	// PLAN — NOT AGAINST THE WHOLE PLAN'S BUDGET.
	//
	// Both halves of that were wrong once and each failed silently in its own
	// direction.
	//
	// Counting BEFORE dedup counts certificates, not records. ACM returns one
	// DomainValidationOption per SAN per certificate, and a host that has been
	// re-issued many times has many certificates naming it — so a lane-1
	// registration asking about three hosts can legitimately produce well over a
	// hundred rows that dedup to three. Refusing on the raw count turned an
	// ordinary certificate estate into ErrUnexpectedRecord, which the caller
	// downgrades to a warning: record 5 then never appears and the customer's AWS
	// certificate never validates, with nothing anywhere saying why.
	//
	// Counting against dnsplan.MaxRecords was the wrong number even when the
	// count was right. The derived records are already in the plan by the time a
	// relayed one is merged, so an answer exactly at the whole-plan bound
	// overflows it — and dnsplan spells that overflow ErrPlanPreparing, which the
	// caller reports as a retryable wait. That is verbatim the outcome this check
	// exists to prevent: a customer sitting in front of a "preparing" that
	// resolves on no pass, ever.
	//
	// MaxRelayed is therefore a reserve, sized so that the largest derived plan
	// plus a full relay still fits. See its declaration for the arithmetic.
	if len(out) > MaxRelayed {
		return nil, fmt.Errorf("%w: %d distinct validation records for %d hosts, past the %d this relay may add to a plan",
			ErrUnexpectedRecord, len(out), len(wanted), MaxRelayed)
	}
	// 🔴 SORTED, BECAUSE THE PLAN DIGEST IS ORDER-SENSITIVE. api-platform hashes
	// the record list in order before the customer authorizes, and this service
	// re-checks that hash before it writes. If two passes over one unchanged
	// upstream answer produced two orders, a customer sitting on the consent
	// screen would be told the plan changed, at random, with nothing having
	// changed. Ordering here rather than in an adapter is the same argument as
	// bounding here: it has to hold for the implementation nobody has written yet.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Value < out[j].Value
	})
	return out, nil
}

// ServingProof reads record 7 through edge for one host, and bounds the record
// it hands back. A nil edge reports not-ready, for the same reason a nil
// CertificateAuthority reports no records.
//
// 🔴 A NOT-READY ANSWER PUBLISHES NOTHING, WHATEVER IT CAME BACK CARRYING. The
// zero record is returned rather than the upstream's, so "ready" is the only
// door a relayed record comes through and a caller cannot accidentally read one
// out of a wait.
func ServingProof(ctx context.Context, edge EdgeHostnames, host string) (dnsplan.Record, bool, error) {
	if edge == nil {
		return dnsplan.Record{}, false, nil
	}
	host = dnsplan.NormalizeName(host)
	if host == "" || len(host) > dnsplan.MaxDNSName {
		return dnsplan.Record{}, false, fmt.Errorf("relay: %q is not a DNS name", host)
	}
	record, ready, err := edge.ServingProof(ctx, host)
	if err != nil || !ready {
		return dnsplan.Record{}, false, err
	}
	checked, err := checkedServingProof(host, record)
	if err != nil {
		return dnsplan.Record{}, false, err
	}
	return checked, true, nil
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
//
// It goes through the free ServingProof above rather than calling the interface
// itself, so the bounds apply on the path the service actually takes: this is
// the function internal/intent calls, and a check the plural form skipped would
// be a check that never ran in production.
func ServingProofs(ctx context.Context, edge EdgeHostnames, hosts []string) ([]dnsplan.Record, error) {
	if edge == nil {
		return nil, nil
	}
	out := make([]dnsplan.Record, 0, len(hosts))
	for _, host := range hosts {
		record, ready, err := ServingProof(ctx, edge, host)
		if err != nil {
			return nil, err
		}
		if ready {
			out = append(out, record)
		}
	}
	return out, nil
}

// checkedValidationRecord bounds one relayed record 5, whatever produced it.
//
// Every check is that the upstream returned what its own contract says it
// returns: AWS declares Name, Type and Value required, declares CNAME the only
// type this field takes, and always points the record into its own validation
// zone. Cheap, and the alternative is publishing a record nobody chose into a
// customer's zone.
func checkedValidationRecord(hosts []string, record dnsplan.Record) (dnsplan.Record, error) {
	out, err := checkedRelayedName("a certificate validation record", hosts, record)
	if err != nil {
		return dnsplan.Record{}, err
	}
	if out.Type != "CNAME" {
		return dnsplan.Record{}, fmt.Errorf("%w: the certificate validation record for %q is a %s, not a CNAME",
			ErrUnexpectedRecord, out.Name, out.Type)
	}
	// A CNAME target is a DNS name and carries a DNS name's limit. The suffix
	// check below would already refuse most over-long values; this one names the
	// real reason instead of reporting a 4KB string as the wrong zone.
	if len(out.Value) > dnsplan.MaxDNSName {
		return dnsplan.Record{}, fmt.Errorf("%w: the certificate validation record for %q has a %d-byte target, past the %d-byte DNS limit",
			ErrUnexpectedRecord, out.Name, len(out.Value), dnsplan.MaxDNSName)
	}
	if !strings.HasSuffix(out.Value, ValidationTargetSuffix) {
		return dnsplan.Record{}, fmt.Errorf("%w: the certificate validation record for %q points at %q, not %s",
			ErrUnexpectedRecord, out.Name, out.Value, ValidationTargetSuffix)
	}
	return out, nil
}

// checkedServingProof bounds one relayed record 7, whatever produced it.
func checkedServingProof(host string, record dnsplan.Record) (dnsplan.Record, error) {
	out, err := checkedRelayedName("a serving proof", []string{host}, record)
	if err != nil {
		return dnsplan.Record{}, err
	}
	if out.Type != "TXT" {
		return dnsplan.Record{}, fmt.Errorf("%w: the serving proof for %q is a %s, not a TXT",
			ErrUnexpectedRecord, host, out.Type)
	}
	if !strings.HasPrefix(out.Name, ownershipRecordPrefix) {
		return dnsplan.Record{}, fmt.Errorf("%w: the serving proof for %q is named %q, not %s%s",
			ErrUnexpectedRecord, host, out.Name, ownershipRecordPrefix, host)
	}
	// An empty value is a WAIT at the adapter (Cloudflare keeps the object
	// present with empty strings; see servingProofRecord in edge.go), so one
	// arriving here alongside ready=true is a contract violation rather than a
	// pass to skip.
	if out.Value == "" {
		return dnsplan.Record{}, fmt.Errorf("%w: the serving proof for %q has no value", ErrUnexpectedRecord, host)
	}
	if len(out.Value) > maxServingProofValue {
		return dnsplan.Record{}, fmt.Errorf("%w: the serving proof for %q is %d bytes, past the %d a TXT string carries",
			ErrUnexpectedRecord, host, len(out.Value), maxServingProofValue)
	}
	if i := strings.IndexFunc(out.Value, func(r rune) bool { return !txtValueSafe(r) }); i >= 0 {
		// The offending byte is NOT echoed. A control character in an error
		// string is how a log line is forged, and this is a value chosen by
		// whatever answered a call that carried a credential.
		return dnsplan.Record{}, fmt.Errorf("%w: the serving proof for %q carries a character at offset %d that a published TXT value cannot",
			ErrUnexpectedRecord, host, i)
	}
	return out, nil
}

// txtValueSafe reports whether r is a character a relayed TXT value may carry:
// printable ASCII, minus the double quote and the backslash.
//
// A TXT record holds arbitrary octets on the wire, so this is deliberately
// narrower than DNS itself. The value is published through a provider API that
// takes the DNS PRESENTATION form — internal/provider/cloudflare wraps it in
// quotes and does not escape what is inside — so a quote or a backslash in the
// value changes where that string ends. A control character costs twice: it
// lands in logs, where it is how a log line is forged.
//
// 🔴 WHAT THIS GIVES UP, SAID PLAINLY: if an upstream ever starts returning the
// value already in quoted presentation form, this refuses it and the host does
// not start serving until someone widens the rule. That is the direction to fail
// in. A refusal names the record and the offset and is one line to fix; a proof
// published with a value whose end nobody agrees on is a 526 with a healthy
// certificate, which is the failure this package spends the most words warning
// about.
func txtValueSafe(r rune) bool {
	return r >= 0x20 && r <= 0x7e && r != '"' && r != '\\'
}

// checkedRelayedName normalizes one relayed record and bounds its NAME.
//
// 🔴 A RELAYED RECORD SITS AT AN UNDERSCORE LABEL BENEATH A HOST THIS PASS ASKED
// ABOUT — NEVER AT THE HOST ITSELF.
//
// Both relayed names are underscore names by construction (`_<token>.<host>` and
// `_cf-custom-hostname.<host>`), and the difference is not decoration. A CNAME
// published AT a name the customer already serves from replaces that name's
// answer: it is the one shape of write in this service that could take a working
// site down, and it would be done with a credential the customer granted for the
// opposite purpose. An underscore label is not a name a browser ever resolves,
// so requiring one keeps every relayed write BESIDE the customer's records
// rather than on top of one. internal/reconcile refuses to overwrite a name in
// use as well; this is the half that does not depend on what the zone happens to
// hold at the moment of the write.
//
// The host bound is the other half. A certificate can legitimately carry names
// this pass did not ask about, and a stale sibling registration's record looks
// exactly like a valid one until you check whose host it names — api-platform
// shipped that bug: a completeness gate that matched on the target suffix alone
// accepted another row's record and persisted it forever. An adapter may SELECT
// those away before returning (see forAnotherHost); one that arrives here is a
// contract violation and is refused rather than dropped.
//
// The record is rebuilt through relayedRecord rather than trusted as it came,
// which also re-answers the proxied flag instead of accepting the upstream's.
func checkedRelayedName(what string, hosts []string, record dnsplan.Record) (dnsplan.Record, error) {
	out := relayedRecord(record.Type, record.Name, record.Value)
	if out.Name == "" || len(out.Name) > dnsplan.MaxDNSName {
		return dnsplan.Record{}, fmt.Errorf("%w: %s has no usable name", ErrUnexpectedRecord, what)
	}
	if !strings.HasPrefix(out.Name, "_") {
		return dnsplan.Record{}, fmt.Errorf("%w: %s is named %q, which is not an underscore name",
			ErrUnexpectedRecord, what, out.Name)
	}
	if !beneathAnyHost(hosts, out.Name) {
		return dnsplan.Record{}, fmt.Errorf("%w: %s names %q, which is not beneath a host this pass asked about",
			ErrUnexpectedRecord, what, out.Name)
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
		Type:    strings.ToUpper(strings.TrimSpace(recordType)),
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

// beneathAnyHost reports whether name sits strictly under one of the hosts this
// pass asked about.
//
// 🔴 THE SUFFIX ALONE IS NOT ENOUGH; THE RECORD MUST BE BOUND TO A HOST WE
// ASKED FOR. A certificate can legitimately carry names we did not ask about,
// and a stale sibling registration's validation record looks exactly like a
// valid one until you check whose host it names. api-platform shipped that bug:
// a completeness gate that matched on the target suffix alone accepted another
// row's record and persisted it forever.
//
// Strictly under, never equal: see checkedRelayedName for why a relayed record
// at a host's own name is the one that could take a site down rather than sit
// beside it.
func beneathAnyHost(hosts []string, name string) bool {
	for _, host := range hosts {
		if name != dnsplan.NormalizeName(host) && dnsplan.Contains(host, name) {
			return true
		}
	}
	return false
}

// forAnotherHost reports whether a relayed record plainly belongs to a host this
// pass did not ask about — the one and only reason an adapter may drop a record
// on the floor instead of handing it up.
//
// A certificate legitimately covers names beyond the ones asked for, and their
// validation records belong to another host's plan; skipping those is SELECTION,
// and it needs the upstream's knowledge of what a certificate is. A MALFORMED
// record is never "another host's" — it has no host at all — so it is handed up
// and refused by name. Dropping it in the adapter instead would make a contract
// violation indistinguishable from the ordinary wait, which is the one confusion
// this package exists to prevent.
func forAnotherHost(hosts []string, record dnsplan.Record) bool {
	return record.Name != "" && !beneathAnyHost(hosts, record.Name)
}
