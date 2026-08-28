// Package relay reads the two proofs this service does NOT derive.
//
// Records 5 and 7 of docs/DESIGN.md §6 are RELAYED: this service derives THAT a
// proof must exist and WHY, but their bytes come from AWS and from Cloudflare and
// nothing here predicts them. "The engine derives the record set" is true of which
// proofs exist and false of every byte — a difference someone deciding whether to
// hand this service a DNS credential is owed.
//
//	5  _<token>.<host>             CNAME  <token>.acm-validations.aws   lane 1 only
//	7  _cf-custom-hostname.<host>  TXT    the serving proof             all lanes
//
// Record 6 (_acme-challenge.<host>) is derived rather than relayed, so it is not
// here: it is a pointer whose halves are known before anything is asked of anyone,
// which is what lets a closed lane hold a credential for 24 hours instead of
// forever (docs/DESIGN.md §6).
//
// 🔴 NOTHING IN THIS PACKAGE TOUCHES A CUSTOMER'S ZONE. It reads two upstreams
// with MirrorStack's own credentials; what it returns still passes anchor
// containment in internal/dnsplan and is still published by internal/reconcile
// under the never-delete rule — no shortcut for having come from somewhere trusted.
//
// 🔴 AND THE BOUNDS ON A RELAYED RECORD LIVE IN THIS FILE, NOT IN AN ADAPTER.
// Either upstream can be swapped, and ACM's answer changes shape whenever AWS
// decides it does, so every rule about what a relayed record may BE — its type, an
// underscore name beneath a host this pass asked about, a value the upstream does
// not choose freely — is applied by the free functions below, against the
// interfaces, as internal/dnsprovider holds the write rules above its Provider:
// AN ADAPTER CANNOT OPT OUT OF A RULE IT NEVER SEES. acm.go and edge.go keep only
// the upstream-shaped part — wire format, paging, "not issued yet" vs "failed".
package relay

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
)

// ErrUnexpectedRecord means an upstream handed back something this service will
// not publish: a record type it cannot be, an empty name, a name outside the
// hosts this pass asked about, a value that is not the shape the proof takes, or
// more records than a plan can hold.
//
// 🔴 A REFUSAL, NOT A WAIT. "Not issued yet" is an empty answer with a nil error
// (see CertificateAuthority), so anything reaching this error is a claim the
// upstream's own contract says it cannot make, and publishing it anyway is how a
// wrong value ends up in a customer's zone with every dashboard green. Name and
// value are both bounded in ValidationRecords and ServingProof below, ABOVE the
// interfaces, not inside whichever adapter happens to be wired.
var ErrUnexpectedRecord = errors.New("relay: upstream returned a record this service will not publish")

// ValidationTargetSuffix is the only zone an ACM DNS validation record may point
// at.
//
// 🔴 THIS BOUNDS THE HALF THAT CONTAINMENT CANNOT. dnsplan.Contains bounds a
// record's NAME; nothing bounds its VALUE, and a relayed value is by definition
// one this repository cannot show you, so it is checked against the only thing
// knowable about it in advance. A value that fails is refused loudly rather than
// dropped quietly: a dropped one looks identical to a certificate AWS has simply
// not filled in yet.
const ValidationTargetSuffix = ".acm-validations.aws"

// ServingProofPrefix is the owner name Cloudflare mints the serving proof at. It
// is asserted against here, never constructed from: the name is relayed verbatim,
// and this only checks that what came back is the record that was asked for.
//
// Exported because internal/consent names this record on the page a customer
// agrees to, and a copy there could describe a name this package would refuse.
const ServingProofPrefix = "_cf-custom-hostname."

// MaxRelayed is how many records this relay may add to one plan.
//
// A RESERVE, not the plan's whole budget: the derived records are already in the
// plan by the time a relayed one is merged. The largest lane derives 9 records and
// relays at most 7 (docs/RECORDS.md), far below dnsplan.MaxRecords = 128, so this
// exists for the pathological upstream rather than the ordinary one. 64 leaves the
// derived side room to double twice over and still refuses an answer long before
// it could push a plan past MaxRecords, where the overflow would be spelled
// ErrPlanPreparing and read by the caller as a wait that never resolves.
//
// 🔴 IT IS COUNTED AFTER DEDUP. Counting before it counts certificates rather
// than records; see ValidationRecords.
const MaxRelayed = 64

// maxServingProofValue bounds the relayed TXT value at DNS's own limit — one TXT
// character-string carries at most 255 octets.
//
// 🔴 THIS CANNOT TELL A RIGHT PROOF FROM A WRONG ONE. The value is a token only
// Cloudflare can compute, so a wrong-but-well-formed one is indistinguishable
// from a right one here and shows up later as a host that never starts serving.
// What the bound does is stop whatever answers the custom_hostnames endpoint from
// choosing an ARBITRARY payload to be published under a customer's own name.
const maxServingProofValue = 255

// CertificateAuthority is AWS ACM, read for record 5 (lane 1 only).
//
// 🔴 STATELESS: we hold no certificate id, and every pass re-reads. The validation
// records are EMPTY until AWS has issued them, which is a WAIT, not a fault —
// return no records and no error for that case. That wait is not theoretical and
// it has shipped broken twice: RequestCertificate returns an ARN immediately and
// ACM populates the validation record seconds to minutes later, so a certificate
// is routinely present-but-recordless for the first minutes of its life. Absent
// means not yet; only a terminal certificate status ever justifies refusing.
//
// An implementation finds the records and spells the upstream's errors;
// ValidationRecords decides what may be published, re-checking every one.
type CertificateAuthority interface {
	ValidationRecords(ctx context.Context, hosts []string) ([]dnsplan.Record, error)
}

// EdgeHostnames is Cloudflare for SaaS, read for record 7 on every lane.
//
// 🔴 THIS READ USES MIRRORSTACK'S OWN ZONE CREDENTIAL, NEVER THE CUSTOMER'S
// GRANT. The custom hostname lives in OUR zone, and sending the customer's token
// there would widen what that grant is used for beyond what the consent screen
// described. The customer's token is a plain string, a per-call argument in
// internal/dnsprovider; this path takes a cfedge.Token, a defined type no string
// variable is assignable to.
//
// 🔴 THE LANE IS A PARAMETER BECAUSE THE ZONE IS PER LANE. MirrorStack's org
// zone and its app/SaaS zone are separate, so a reader with one zone id serves
// at most one lane; see EdgeZones. It travels through the interface rather than
// being fixed per instance so a caller cannot hold the wrong reader for a lane.
//
// Record 7 is the SECOND, SEPARATE proof, read by the edge rather than by a
// certificate authority; see ServingProof in edge.go for what its absence looks
// like from outside. The implementation decides what it FOUND, the free
// ServingProof what may be published.
type EdgeHostnames interface {
	ServingProof(ctx context.Context, l lane.Lane, host string) (record dnsplan.Record, ready bool, err error)
}

// EdgeZoneReporter is an EdgeHostnames that can name the zones it reads.
//
// Optional, and asserted for rather than required: it exists so
// IntentCapabilities publishes the zone ids ACTUALLY in use instead of a second
// read of the same environment variables, which is the copy that drifts. A fake
// in a test implements EdgeHostnames alone and reports no zones, truthfully.
type EdgeZoneReporter interface {
	EdgeZones() EdgeZones
}

// ValidationRecords reads record 5 through ca for the given hosts, and bounds
// every record it hands back.
//
// 🔴 A NIL ADAPTER IS "NOT YET", NEVER AN ERROR. Both relays are optional: lanes
// 2 and 3 request no ACM certificate at all, and a deployment may not be
// configured for one. Reporting "no certificate reader" as an error would turn a
// lane that was never going to have record 5 into a permanently failing one
// instead of one publishing what it can derive. Pass a nil INTERFACE, not a nil
// pointer to a concrete type: ACM and Edge are value types precisely so a zero
// value is usable and no caller parks a typed nil, which is non-nil and panics.
//
// Every record proves itself again here — a CNAME, at an underscore name beneath a
// host this pass asked about, pointing into the AWS validation zone.
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
	// The bound is taken AFTER dedup, and against the relay's share of the plan
	// rather than the whole plan's budget. Both halves were wrong once, silently.
	//
	// Counting BEFORE dedup counts certificates, not records: ACM returns one
	// DomainValidationOption per SAN per certificate, and a host re-issued many
	// times has many certificates naming it, so a lane-1 registration asking about
	// three hosts can legitimately produce well over a hundred rows that dedup to
	// three. Refusing on the raw count turned an ordinary certificate estate into
	// ErrUnexpectedRecord, which the caller downgrades to a warning: record 5 never
	// appears and the customer's AWS certificate never validates, with nothing
	// anywhere saying why.
	//
	// Counting against dnsplan.MaxRecords overflows the plan, because the derived
	// records are already in it — and dnsplan spells that overflow ErrPlanPreparing,
	// which the caller reports as a retryable wait: a customer left in front of a
	// "preparing" that resolves on no pass, ever.
	if len(out) > MaxRelayed {
		return nil, fmt.Errorf("%w: %d distinct validation records for %d hosts, past the %d this relay may add to a plan",
			ErrUnexpectedRecord, len(out), len(wanted), MaxRelayed)
	}
	// 🔴 SORTED, BECAUSE THE PLAN DIGEST IS ORDER-SENSITIVE. api-platform hashes
	// the record list in order before the customer authorizes, and this service
	// re-checks that hash before it writes, so two orders over one unchanged
	// upstream answer would tell a customer sitting on the consent screen that the
	// plan changed, at random. Ordered here, not in an adapter, for the reason the
	// bounds are.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Value < out[j].Value
	})
	return out, nil
}

// ServingProof reads record 7 through edge for one host on one lane, and bounds
// the record it hands back. A nil edge reports not-ready, for the same reason a
// nil CertificateAuthority reports no records — and it is how an unconfigured
// deployment answers, so a missing credential is a wait rather than a fault.
//
// 🔴 A NOT-READY ANSWER PUBLISHES NOTHING, WHATEVER IT CAME BACK CARRYING. The
// zero record is returned rather than the upstream's, so "ready" is the only door
// a relayed record comes through.
func ServingProof(ctx context.Context, edge EdgeHostnames, l lane.Lane, host string) (dnsplan.Record, bool, error) {
	if edge == nil {
		return dnsplan.Record{}, false, nil
	}
	host = dnsplan.NormalizeName(host)
	if host == "" || len(host) > dnsplan.MaxDNSName {
		return dnsplan.Record{}, false, fmt.Errorf("relay: %q is not a DNS name", host)
	}
	record, ready, err := edge.ServingProof(ctx, l, host)
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
// A partial answer is the NORMAL answer, not a degraded one: Cloudflare mints this
// proof when a custom hostname is created, a lane-1 registration creates four, and
// on any given pass some exist and some do not. Collecting what is ready is what
// makes the loop converge, and it is why this returns records rather than a
// per-host readiness map — a record that is not ready is simply not in the plan
// yet. Host order is preserved, for the digest's sake, and it goes through the free
// ServingProof rather than the interface so the bounds apply on the real path.
func ServingProofs(ctx context.Context, edge EdgeHostnames, l lane.Lane, hosts []string) ([]dnsplan.Record, error) {
	if edge == nil {
		return nil, nil
	}
	out := make([]dnsplan.Record, 0, len(hosts))
	for _, host := range hosts {
		record, ready, err := ServingProof(ctx, edge, l, host)
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
// Every check is that the upstream returned what its own contract says it
// returns: AWS declares Name, Type and Value required, declares CNAME the only
// type this field takes, and always points the record into its own validation
// zone.
func checkedValidationRecord(hosts []string, record dnsplan.Record) (dnsplan.Record, error) {
	out, err := checkedRelayedName("a certificate validation record", hosts, record)
	if err != nil {
		return dnsplan.Record{}, err
	}
	if out.Type != "CNAME" {
		return dnsplan.Record{}, fmt.Errorf("%w: the certificate validation record for %q is a %s, not a CNAME",
			ErrUnexpectedRecord, out.Name, out.Type)
	}
	// A CNAME target is a DNS name and carries a DNS name's limit. Checked before
	// the suffix so an over-long value is named for what it is rather than
	// reported as the wrong zone.
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
	if !strings.HasPrefix(out.Name, ServingProofPrefix) {
		return dnsplan.Record{}, fmt.Errorf("%w: the serving proof for %q is named %q, not %s%s",
			ErrUnexpectedRecord, host, out.Name, ServingProofPrefix, host)
	}
	// An empty value is a WAIT at the adapter (Cloudflare keeps the object
	// present with empty strings; see servingProofRecord in edge.go), so one
	// arriving here alongside ready=true is a contract violation.
	if out.Value == "" {
		return dnsplan.Record{}, fmt.Errorf("%w: the serving proof for %q has no value", ErrUnexpectedRecord, host)
	}
	if len(out.Value) > maxServingProofValue {
		return dnsplan.Record{}, fmt.Errorf("%w: the serving proof for %q is %d bytes, past the %d a TXT string carries",
			ErrUnexpectedRecord, host, len(out.Value), maxServingProofValue)
	}
	if i := strings.IndexFunc(out.Value, func(r rune) bool { return !txtValueSafe(r) }); i >= 0 {
		// The offending byte is NOT echoed: a control character in an error string
		// is how a log line is forged, and this value was chosen by whatever
		// answered a call that carried a credential.
		return dnsplan.Record{}, fmt.Errorf("%w: the serving proof for %q carries a character at offset %d that a published TXT value cannot",
			ErrUnexpectedRecord, host, i)
	}
	return out, nil
}

// txtValueSafe reports whether r is a character a relayed TXT value may carry:
// printable ASCII, minus the double quote and the backslash.
//
// Narrower than DNS, which carries arbitrary octets in a TXT record, because the
// value is published through a provider API that takes the DNS PRESENTATION form —
// internal/provider/cloudflare wraps it in quotes and does not escape what is
// inside — so a quote or a backslash changes where that string ends. A control
// character costs twice: it also lands in logs, where it is how a line is forged.
//
// 🔴 WHAT THIS GIVES UP, SAID PLAINLY: if an upstream ever starts returning the
// value already in quoted presentation form, this refuses it and the host does not
// start serving until someone widens the rule. That is the direction to fail in —
// the refusal names the record and the offset, while a proof published with a
// value whose end nobody agrees on is a 526 with a healthy certificate.
func txtValueSafe(r rune) bool {
	return r >= 0x20 && r <= 0x7e && r != '"' && r != '\\'
}

// checkedRelayedName normalizes one relayed record and bounds its NAME.
//
// 🔴 A RELAYED RECORD SITS AT AN UNDERSCORE LABEL BENEATH A HOST THIS PASS ASKED
// ABOUT — NEVER AT THE HOST ITSELF. Both relayed names are underscore names by
// construction (`_<token>.<host>`, `_cf-custom-hostname.<host>`), and no browser
// ever resolves an underscore label, so requiring one keeps every relayed write
// BESIDE the customer's records. A CNAME published AT a name the customer serves
// from replaces that name's answer: the one shape of write in this service that
// could take a working site down, made with a credential granted for the opposite
// purpose. internal/reconcile refuses to overwrite a name in use as well; this is
// the half that does not depend on what the zone holds at the moment of the write.
//
// The host bound is the other half. A certificate can legitimately carry names
// this pass did not ask about, and a stale sibling registration's record looks
// exactly like a valid one until you check whose host it names — api-platform
// shipped that bug: a completeness gate matching on the target suffix alone
// accepted another row's record and persisted it forever. An adapter may SELECT
// those away (see forAnotherHost); one arriving here is a contract violation and
// is refused rather than dropped.
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
// 🔴 PROXIED IS ALWAYS FALSE, AND IT IS AN ANSWER RATHER THAN A DEFAULT. Every
// relayed name begins with an underscore, and Cloudflare accepts proxied:true on
// such a name with no error at all, then answers with addresses instead of
// following the record — so the certificate authority finds IP addresses where it
// needed a CNAME, and issuance, or a renewal months later, fails with every
// dashboard still green. No relayed record wants the orange cloud.
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
// dot, drops blanks, and removes duplicates while keeping the caller's order —
// order for the digest's sake, as above: a set built by ranging a map would
// reorder between passes and invalidate an in-flight authorization at random.
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
// pass asked about. The suffix alone is not enough — the record must be bound to
// a host we asked for; see checkedRelayedName for the api-platform bug that shape
// produced, and for why a relayed record AT a host's own name, rather than
// strictly under it, is the one that could take a site down.
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
// instead of handing it up. A certificate legitimately covers names beyond the
// ones asked for, and their validation records belong to another host's plan;
// skipping those is SELECTION, and it needs the upstream's knowledge of what a
// certificate is. A MALFORMED record is never "another host's" — it has no host at
// all — so it is handed up and refused by name, keeping a contract violation
// distinguishable from the ordinary wait.
func forAnotherHost(hosts []string, record dnsplan.Record) bool {
	return record.Name != "" && !beneathAnyHost(hosts, record.Name)
}
