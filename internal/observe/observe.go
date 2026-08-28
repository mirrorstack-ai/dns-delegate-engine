// Package observe answers one question and refuses to answer any other: what
// does PUBLIC DNS say about the names in a plan, right now?
//
// It is what makes two of the seven lifecycle functions real.
//
//   - `describe` reports every record's purpose next to whether it is present,
//     absent, conflicting or the wrong type, so that "I added it and nothing
//     happened" has an answer that does not require a support reply.
//   - `verify` resolves the ownership proof. That is the gate this whole
//     rebuild turns on: the proof is the CUSTOMER's record to publish, it is
//     re-checked on EVERY pass, and this package is the only place that reads
//     it. Before, the proof was inside the set we published and the gate was a
//     lookup of our own write, which is a sentence with no fact behind it.
//
// 🔴 EVERYTHING THIS PACKAGE LEARNS COMES FROM A Resolver IT WAS HANDED.
//
// `Resolver` is an interface and every test here drives a fake one. That is a
// stated property of the repository rather than a testing convenience: a
// customer's own developers are being asked to settle "could MirrorStack break
// our website?" by reading this code, and a package whose behaviour can only be
// confirmed by pointing it at live infrastructure cannot be settled that way.
//
// Nothing here writes. There is no provider client in this package, no
// credential, and no path that reaches one — observation and mutation are kept
// in different packages precisely so that reading the imports is enough to know
// which one you are looking at.
package observe

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/derive"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
)

// ErrObserve is this package's single refusal: the plan handed in does not
// describe something that can be observed at all.
//
// It covers only defects in the REQUEST — a missing resolver, a plan larger
// than a plan may be, an item that is not a record. A record that is simply not
// published yet is not an error; it is an Observation with State absent, which
// is the ordinary early state of every registration and must never look like a
// fault to the loop that calls this.
//
// The containment refusal deliberately does NOT use this sentinel. It returns
// dnsplan.ErrAnchorEscape, the same error the write path returns, so that a
// caller asking "did something name a record outside the proven parent?" gets
// one answer wherever it happened.
var ErrObserve = errors.New("observe: cannot observe this plan")

// maxInFlight bounds how many names are resolved at once.
//
// Small on purpose. A zone is typically served by two to four authoritative
// nameservers, the largest lane's plan is a dozen names, and this runs on a
// five-minute loop across every registration this deployment holds. A wider
// fan-out would buy milliseconds per report and would arrive at a customer's
// DNS provider as a burst, which some of them rate-limit — turning a report
// into a page of `unknown` for reasons that were ours, not theirs.
const maxInFlight = 4

// defaultTimeout bounds one lookup when NetResolver.Timeout is left zero.
//
// An authoritative nameserver answers in tens of milliseconds; five seconds is
// room for a recursive resolver to retry a dropped packet, and short enough
// that a dozen names with one dead nameserver still produce a whole report
// inside a single invocation instead of being killed halfway through it.
const defaultTimeout = 5 * time.Second

// Resolver is public DNS.
//
// 🔴 AN INTERFACE SO THIS REPOSITORY'S TESTS NEED NO NETWORK, NO DATABASE AND
// NO CLOUDFLARE ACCOUNT.
//
// The contract is narrower than net.Resolver's, and the difference is the point
// of NetResolver's doc comment below:
//
//   - LookupCNAME returns the CNAME target published AT name — the right-hand
//     side of the record itself, not the far end of the chain it starts. When
//     the name resolves but holds no CNAME, it returns name back unchanged;
//     that is how an implementation says "something else answers here", and it
//     is the only evidence of a wrong type that public DNS reliably gives us.
//   - LookupTXT returns every TXT value at name. An owner may hold several, all
//     of them are returned, and their order carries no meaning.
//   - A name that does not resolve is reported as a *net.DNSError with
//     IsNotFound set. Any other error means the lookup did not complete, and
//     this package will never read it as absence.
type Resolver interface {
	LookupCNAME(ctx context.Context, name string) (string, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// NetResolver is the production Resolver, over the standard library.
//
// 🔴 IT CONSULTS NO CACHE OF OURS.
//
// The struct has exactly one field and it is a timeout: no map, no memo, no
// store, and a fresh net.Resolver per lookup so that the absence of one is
// visible rather than asserted. The reason is the reason verify() exists. A
// registration is advanced by the CUSTOMER's publication, so an answer we
// remembered would let a proof that has since been deleted keep this service
// writing into a zone whose owner has withdrawn it.
//
// What we cannot remove is the cache in front of us, and it is more honest to
// state the exposure than to imply there is none. We read what public DNS
// SERVES — the same thing any outside verifier sees — and a recursive resolver
// may keep serving a deleted record until its TTL expires. So the design's
// "every write stops within one tick" is bounded below by the TTL the customer
// chose for their own record: a five-minute tick behind a one-day TTL stops in
// a day. A customer who wants a faster stop should publish the proof with a
// short TTL, and that is a real lever they hold. It is a limit rather than a
// defect: a record nobody outside the zone can see yet is not yet a proof.
//
// PreferGo is set, and it is load-bearing rather than a style preference.
// Measured against Go 1.26's net/dnsclient_unix.go rather than inferred from
// the LookupCNAME doc comment, which describes the other path:
//
//   - Without it, LookupCNAME may be answered by cgo's getaddrinfo with
//     AI_CANONNAME. That resolves an ADDRESS: it follows the CNAME chain to the
//     end and fails outright when the chain terminates in a name that has no
//     A or AAAA record.
//   - Two of the records this service deals in terminate in exactly that.
//     `_acme-challenge.<host>` points at a Cloudflare DCV name that serves a
//     TXT, and `_<token>.<host>` points into `.acm-validations.aws`. On the cgo
//     path a correctly published validation record reads as MISSING — the worst
//     answer this package could give, because the customer did the right thing
//     and we would be telling them they had not.
//   - The pure Go resolver issues a real CNAME query alongside A and AAAA,
//     takes the FIRST CNAME in the answer section (the record at the queried
//     name, not the end of the chain), and returns it even when nothing
//     resolves beyond it.
//
// One consequence is worth writing down in a repository whose job is to be
// checkable: with PreferGo the CNAME lookup consults the container's
// /etc/hosts before DNS. Nothing in this service writes that file, and a
// deployment that did could make a name appear to resolve however it liked. The
// TXT lookup — which is the one the ownership proof goes through — never
// consults it and goes straight to the resolvers in /etc/resolv.conf.
type NetResolver struct {
	// Timeout bounds ONE lookup, not the whole report. Zero means
	// defaultTimeout. The caller's ctx still bounds everything above it, and
	// this is what keeps one unreachable nameserver from spending the whole
	// budget on the first of a dozen names.
	Timeout time.Duration
}

// LookupCNAME implements Resolver.
func (n NetResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, n.timeout())
	defer cancel()
	return n.resolver().LookupCNAME(ctx, rooted(name))
}

// LookupTXT implements Resolver.
func (n NetResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, n.timeout())
	defer cancel()
	return n.resolver().LookupTXT(ctx, rooted(name))
}

func (n NetResolver) timeout() time.Duration {
	if n.Timeout <= 0 {
		return defaultTimeout
	}
	return n.Timeout
}

// resolver is built per lookup rather than stored, so "this type holds no
// answers between calls" is something a reader can see instead of trust.
// net.Resolver is a small struct with no cache of its own.
func (n NetResolver) resolver() *net.Resolver {
	return &net.Resolver{PreferGo: true}
}

// rooted appends the root dot.
//
// 🔴 A NAME WE ASK ABOUT MUST BE ABSOLUTE. Measured in Go 1.26's nameList: a
// name WITHOUT a trailing dot is tried against the `search` list from
// /etc/resolv.conf as well as on its own, so a lookup of a customer's absent
// record could be answered by whatever `<name>.<our-search-domain>` happens to
// resolve to. A rooted name is queried once, exactly as written, and the whole
// class of question disappears.
func rooted(name string) string {
	if name == "" || strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

// State is what public DNS says about one record we expect to exist.
type State string

const (
	// StatePresent means the expected value is published at the expected name.
	StatePresent State = "present"

	// StateAbsent means the expected value is not there. For a TXT that
	// includes "other values are there, but not this one" — see Observation.
	StateAbsent State = "absent"

	// StateConflicting means something else answers there and it cannot simply
	// be added beside. Only a CNAME can be conflicting, because only a CNAME is
	// exclusive at its owner.
	StateConflicting State = "conflicting"

	// StateWrongType means the name resolves, but through a different record
	// type than the one that belongs there.
	StateWrongType State = "wrong_type"

	// StateUnknown means nothing may be concluded about this record. Two things
	// produce it: the lookup did not complete, or this report is structurally
	// unable to decide (the ownership proof — see Plan).
	//
	// 🔴 UNKNOWN IS NOT ABSENT, AND THE DISTINCTION IS THE POINT OF HAVING IT.
	// A SERVFAIL, a timeout or a cancelled context tells us nothing about the
	// customer's zone. Folding it into absent would make a transient resolver
	// blip indistinguishable from a customer withdrawing their proof, and the
	// caller's response to those differs: one is a retry, the other eventually
	// releases a live credential.
	StateUnknown State = "unknown"
)

// Observation is one record, and what public DNS said about it.
type Observation struct {
	// Name and Type are the record we looked for, normalized.
	Name string
	Type string

	// Want is the value that should be published there. It is empty for the
	// ownership proof, which is accepted against a SET of values rather than
	// one — see Proof.
	Want string

	State State

	// Found is what was actually published at Name, normalized the same way as
	// Want so the two can be read side by side. It is populated on every state
	// that has something to show, INCLUDING present: a report that says "yes"
	// without saying what it saw cannot be checked by the person reading it.
	Found []string

	// Purpose and Source are carried through from the derived item unchanged.
	// This package classifies what is published; it has no opinion about why a
	// record exists or who owes it, and inventing one here would be a second
	// place for that vocabulary to drift from derive's.
	Purpose derive.Purpose
	Source  derive.Source

	// Explain is the derived item's explanation and this observation's
	// diagnosis, joined. Both are kept because they answer different halves of
	// the customer's question — why is this record here, and why has adding it
	// not worked — and there is exactly one field in a report for a human to
	// read.
	Explain string
}

// Plan observes every item in a plan, concurrently and bounded.
//
// The result has one Observation per item, in item order, on every path that
// returns without an error: a report with holes in it is worse than no report,
// because the hole is silent.
//
// 🔴 IT DOES NOT DECIDE THE OWNERSHIP PROOF, AND MUST NOT BE MADE TO.
//
// derive puts the ownership record in the plan, carrying the value a customer
// is asked to publish TODAY. The keyset accepts one value per key, so a proof
// published months ago under a key that has since rotated is still perfectly
// valid and would not match the single value in the item. Judging it from here
// would produce a report that contradicts verify() on the one record everything
// else hangs from: `describe` says absent and offers a fix, while the domain is
// working and needs no fix at all. So the ownership item is reported unknown,
// with no lookup issued for it, and the caller overlays the Observation that
// Proof returns — which compares against the whole accept set and is the only
// thing entitled to an opinion here.
//
// It refuses the WHOLE plan for two defects rather than reporting around them,
// which is the same call dnsplan.NewSnapshot makes and for the same reason. A
// record outside the anchor, or a record of a type this service does not
// publish, is a derivation bug; the report goes in front of a customer as "the
// records this service manages in your zone", and a line in it that we have no
// business managing is a lie we would be asking them to act on.
func Plan(ctx context.Context, r Resolver, p derive.Plan) ([]Observation, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: no resolver", ErrObserve)
	}
	anchor := dnsplan.NormalizeName(p.Anchor)
	if anchor == "" || len(anchor) > dnsplan.MaxDNSName {
		return nil, fmt.Errorf("%w: anchor is not a DNS name", ErrObserve)
	}
	// The same bound the write path uses. A plan is one ownership group, not a
	// bulk zone-editing primitive, and an item count beyond that would turn a
	// corrupt plan into a fan-out of queries at a customer's nameservers.
	if len(p.Items) > dnsplan.MaxRecords {
		return nil, fmt.Errorf("%w: %d items", ErrObserve, len(p.Items))
	}

	observations := make([]Observation, len(p.Items))
	// Items are grouped by the name and type they ask about, and one lookup
	// serves the whole group. This is not a cache: it is one observation shared
	// by the items that are asking the same question in the same report. Two
	// TXT values at one owner judged against two separate answers can disagree
	// for no reason but timing, and a report that contradicts itself is exactly
	// the kind of thing that produces the support reply this package exists to
	// avoid.
	groups := make(map[lookupKey][]int, len(p.Items))
	order := make([]lookupKey, 0, len(p.Items))

	for i, item := range p.Items {
		recordType := strings.ToUpper(strings.TrimSpace(item.Record.Type))
		name := dnsplan.NormalizeName(item.Record.Name)
		want := strings.TrimSpace(item.Record.Value)
		if recordType == "CNAME" {
			want = dnsplan.NormalizeName(want)
		} else {
			want = normalizeTXT(want)
		}

		observations[i] = Observation{
			Name:    name,
			Type:    recordType,
			Want:    want,
			Purpose: item.Purpose,
			Source:  item.Source,
			Explain: item.Explain,
		}

		// CNAME and TXT are the only types this service ever publishes, and the
		// README says so as a promise rather than as a description. Observing
		// any other type would quietly widen what this repository claims to
		// touch.
		if recordType != "CNAME" && recordType != "TXT" {
			slog.Error("observe: refusing to observe a plan item that is not a CNAME or a TXT",
				"anchor", anchor, "name", name, "type", recordType)
			return nil, fmt.Errorf("%w: %q is not a record type this service publishes", ErrObserve, recordType)
		}
		if name == "" || len(name) > dnsplan.MaxDNSName {
			return nil, fmt.Errorf("%w: item %d does not name a DNS record", ErrObserve, i)
		}
		if !dnsplan.Contains(anchor, name) {
			slog.Error("observe: refusing to observe a plan item outside its anchor",
				"anchor", anchor, "name", name, "type", recordType)
			return nil, fmt.Errorf("%w: %q is not at or under %q", dnsplan.ErrAnchorEscape, name, anchor)
		}

		// The ownership proof, deferred to Proof. No lookup is issued: this
		// package cannot see the accept set from a plan, and a query whose
		// answer it is not entitled to judge is a query worth not making.
		if item.Purpose == derive.PurposeOwnership {
			observations[i].State = StateUnknown
			observations[i].Explain = explain(item.Explain,
				"this report does not decide the ownership proof. It is checked against every key in the keyset, including keys that have since rotated, and only verify() can see that set — a proof published under an older key is still valid and would be misreported here.")
			continue
		}

		// A value that is not known yet is a legitimate state, not a defect:
		// the relayed records exist in the plan before AWS or Cloudflare have
		// produced what goes in them. Nothing has been asked of the customer
		// for this record, so there is nothing to look for, and no query is
		// issued on its behalf. Reporting absent here would be wrong in the
		// direction that costs a support reply.
		if want == "" {
			observations[i].State = StateUnknown
			observations[i].Explain = explain(item.Explain,
				"the value for this record is not known yet, so nothing has been asked of you for it; it will appear here once the certificate authority or the edge has produced it")
			continue
		}

		key := lookupKey{recordType: recordType, name: name}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], i)
	}

	answers := resolveAll(ctx, r, order)
	for _, key := range order {
		answer := answers[key]
		for _, i := range groups[key] {
			state, found, diagnosis := classify(key, observations[i].Want, answer)
			observations[i].State = state
			// Copied, not shared. Two items in one group are handed the same
			// answer, and a caller that sorted or trimmed one report's Found
			// would otherwise be reordering another observation it never
			// touched. A nil stays nil, so "nothing was found" is still
			// distinguishable from "an empty answer".
			observations[i].Found = append([]string(nil), found...)
			observations[i].Explain = explain(observations[i].Explain, diagnosis)
		}
	}
	return observations, nil
}

// Proof resolves the ownership TXT and reports whether ANY of the accepted
// values is published.
//
// 🔴 THE CALLER CANNOT SAY WHAT TO LOOK FOR.
//
// `accepted` comes from internal/proof, recomputed from the sealed
// registration, and never from a request field. That is the whole reason
// verify() means something: a caller that could supply the value to match
// against could satisfy the proof with a string it made up, and "the customer
// proved they own this anchor" would go back to being a sentence with no fact
// behind it.
//
// There is more than one accepted value because the MAC key rotates. Every key
// in the keyset produces a value, all of them are accepted, and a rotation
// therefore does not invalidate a proof a customer published months ago and has
// no reason to revisit.
//
// The three returns are all meaningful, including together:
//
//   - ok reports the proof resolved and matched. Nothing else may be read as
//     that.
//   - obs is always populated, including on the error return, so a caller can
//     log and render what was seen rather than only that something failed.
//   - err is non-nil only when the lookup did not complete or the request was
//     malformed. A proof that is simply not published yet is (false, absent,
//     nil) — the ordinary state of every registration before the customer has
//     acted, and an error there would make the loop treat waiting as a fault.
func Proof(ctx context.Context, r Resolver, name string, accepted []string) (ok bool, obs Observation, err error) {
	obs = Observation{Type: "TXT", Name: dnsplan.NormalizeName(name), State: StateUnknown}
	if r == nil {
		return false, obs, fmt.Errorf("%w: no resolver", ErrObserve)
	}
	if obs.Name == "" || len(obs.Name) > dnsplan.MaxDNSName {
		return false, obs, fmt.Errorf("%w: the ownership proof name is not a DNS name", ErrObserve)
	}
	// 🔴 AN EMPTY ACCEPT SET IS A REFUSAL, NEVER A CLEAN NEGATIVE. It means the
	// keyset produced nothing, which is a deployment defect on our side. If it
	// returned (false, absent, nil) the caller could not tell it from a
	// customer who has not published yet, and would eventually release a live
	// credential over a fault of ours.
	usable := 0
	for _, value := range accepted {
		if value != "" {
			usable++
		}
	}
	if usable == 0 {
		return false, obs, fmt.Errorf("%w: no accepted ownership value was supplied", ErrObserve)
	}

	// Want stays empty deliberately. The accept set holds one value per key in
	// the keyset and carries no marker for which one is active, so picking one
	// to display would be picking arbitrarily — and echoing all of them back
	// would put every retired key's value into a customer-facing report. The
	// value to SHOW is proof.Prover.Expected, which the caller already holds.
	values, lookupErr := r.LookupTXT(ctx, obs.Name)
	if lookupErr != nil {
		if isNotFound(lookupErr) {
			obs.State = StateAbsent
			obs.Explain = "no TXT value resolves at this name yet. Until you publish this record nothing here treats the domain as proven, which is the entire job of the record."
			return false, obs, nil
		}
		obs.State = StateUnknown
		obs.Explain = fmt.Sprintf("the lookup did not complete: %v. This is NOT read as the proof having been withdrawn — a registration is stopped on an answer, never on a failure to get one.", lookupErr)
		return false, obs, lookupErr
	}

	obs.Found = normalizeTXTValues(values)
	if matchesAccepted(obs.Found, accepted) {
		obs.State = StatePresent
		obs.Explain = "the ownership proof is published."
		return true, obs, nil
	}
	obs.State = StateAbsent
	if len(obs.Found) == 0 {
		obs.Explain = "the name resolves but holds no TXT value."
		return false, obs, nil
	}
	obs.Explain = fmt.Sprintf("%d TXT value(s) resolve here and none of them is the expected proof. A value pasted with a character dropped looks exactly like this. TXT records add beside each other, so the ones already there can stay — the correct value only has to be added.", len(obs.Found))
	return false, obs, nil
}

type lookupKey struct {
	recordType string
	name       string
}

// answer is one completed lookup: the values public DNS returned, or the reason
// it could not be asked. The two are kept apart all the way to classify so that
// nothing along the path can quietly turn a failure into an empty result.
type answer struct {
	values []string
	err    error
}

// resolveAll runs one lookup per key, at most maxInFlight at a time.
func resolveAll(ctx context.Context, r Resolver, keys []lookupKey) map[lookupKey]answer {
	answers := make(map[lookupKey]answer, len(keys))
	if len(keys) == 0 {
		return answers
	}

	results := make([]answer, len(keys))
	slots := make(chan struct{}, maxInFlight)
	var wg sync.WaitGroup
	for i, key := range keys {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			// The context is already finished, so the remaining names get the
			// context's error rather than a lookup that cannot succeed. They
			// become unknown, which is honest, and never absent.
			results[i] = answer{err: ctx.Err()}
			continue
		}
		wg.Add(1)
		go func(i int, key lookupKey) {
			defer wg.Done()
			defer func() { <-slots }()
			// Re-checked inside the goroutine: this one may have waited for a
			// slot behind a name that used the whole budget.
			if err := ctx.Err(); err != nil {
				results[i] = answer{err: err}
				return
			}
			if key.recordType == "CNAME" {
				value, err := r.LookupCNAME(ctx, key.name)
				if err != nil {
					results[i] = answer{err: err}
					return
				}
				results[i] = answer{values: []string{dnsplan.NormalizeName(value)}}
				return
			}
			values, err := r.LookupTXT(ctx, key.name)
			if err != nil {
				results[i] = answer{err: err}
				return
			}
			results[i] = answer{values: normalizeTXTValues(values)}
		}(i, key)
	}
	wg.Wait()

	for i, key := range keys {
		answers[key] = results[i]
	}
	return answers
}

// classify turns one lookup into a state, what was found, and a sentence a
// customer can act on.
func classify(key lookupKey, want string, a answer) (State, []string, string) {
	if a.err != nil {
		if isNotFound(a.err) {
			if key.recordType == "CNAME" {
				return StateAbsent, nil, "nothing resolves at this name. If you believe you added it, check that your provider did not append the zone name a second time — a record entered as the full hostname into a panel that already appends the zone lands one level too deep and resolves nowhere."
			}
			return StateAbsent, nil, "no TXT value resolves at this name."
		}
		// 🔴 EVERY ERROR THAT IS NOT "NO SUCH NAME" IS UNKNOWN. This is the same
		// rule dnsprovider.IsAmbiguous states for writes, pointed the other way:
		// an unrecognised failure is not permission to claim certainty. Absence
		// has to be an ANSWER from DNS, never our failure to get one.
		return StateUnknown, nil, fmt.Sprintf("the lookup did not complete: %v. This is not evidence that the record is missing.", a.err)
	}

	if key.recordType == "CNAME" {
		return classifyCNAME(key.name, want, a.values)
	}
	return classifyTXT(want, a.values)
}

// classifyCNAME judges the one value a CNAME owner is allowed to hold.
func classifyCNAME(name, want string, values []string) (State, []string, string) {
	got := ""
	if len(values) > 0 {
		got = values[0]
	}
	switch {
	case got == "":
		// A resolver that returns no value and no error has told us nothing.
		// Treating that as absence would be inventing an answer.
		return StateUnknown, nil, "the lookup returned neither a value nor an error, so nothing can be concluded about this name."

	case got == name:
		// The resolver contract says a name that resolves without a CNAME
		// answers with itself. In practice that means address records are
		// published here, and the reason a customer usually hits it is worth
		// spelling out rather than leaving them to guess.
		return StateWrongType, nil, "this name resolves, but not through a CNAME — address records answer here. On Cloudflare that is exactly what a proxied (orange cloud) record looks like from outside: the CNAME is in your zone, but public DNS serves addresses instead and nothing downstream can follow it. Records in this plan must stay DNS-only (grey). An existing A or AAAA record at this name has the same effect and has to be removed before a CNAME can be added, because a CNAME cannot share its owner."

	case got == want:
		return StatePresent, []string{got}, "published as expected."

	default:
		// 🔴 A DIFFERENT TARGET IS CONFLICTING, NOT ABSENT, AND THE REPORT MUST
		// NAME IT. A CNAME owner holds exactly one value, so this record cannot
		// be added beside what is there — something has to be changed, and the
		// customer cannot decide what without being told what is in the way.
		return StateConflicting, []string{got}, fmt.Sprintf("a CNAME is published here, but it points at %q. A name can hold only one CNAME, so this cannot be added alongside — the existing record has to be changed or removed first.", got)
	}
}

// classifyTXT judges an owner that may legitimately hold many values.
//
// 🔴 NO TXT OBSERVATION IS EVER CONFLICTING, AND THAT IS NOT A SIMPLIFICATION.
//
// TXT records ADD beside each other: a second value at an owner never displaces
// the first, and every consumer of TXT is expected to scan the set for the one
// it cares about. So the presence of other values is information, not a
// problem, and reporting them as a conflict would send a customer off to delete
// records that were fine.
//
// It is also the other half of the defect this rebuild fixes. Anchor
// containment bounds a record's NAME, and for a CNAME that is nearly enough,
// because writing one at an owner the customer is serving from is visibly
// destructive and the reconciler updates in place. For a TXT it bounds almost
// nothing: a value added beside an existing one at an in-anchor name is invisible
// and can still do damage — a second `v=spf1` TXT at the apex is an SPF
// permerror under RFC 7208 §4.5, which is a customer's mail delivery, published
// from a name they proved they owned. Containment could never have caught that,
// which is why the fix had to be that the caller can no longer name a value at
// all.
func classifyTXT(want string, values []string) (State, []string, string) {
	for _, value := range values {
		if value == want {
			if len(values) > 1 {
				return StatePresent, values, fmt.Sprintf("published as expected, alongside %d other TXT value(s) at this name. That is fine and nothing needs removing: TXT records add beside each other.", len(values)-1)
			}
			return StatePresent, values, "published as expected."
		}
	}
	if len(values) == 0 {
		return StateAbsent, nil, "no TXT value resolves at this name."
	}
	// Absent WITH what is there. This is the report line that answers "I added
	// it and nothing happened" on its own: the value with the dropped character
	// is right there next to the one that was asked for.
	return StateAbsent, values, fmt.Sprintf("this value is not among the %d TXT value(s) published here. The published ones can stay — TXT records add beside each other — the expected value only has to be added.", len(values))
}

// isNotFound reports the one error that means the name genuinely does not
// resolve. NXDOMAIN and "the name exists but has no record of this type" both
// arrive as *net.DNSError with IsNotFound set.
//
// 🔴 IT RECOGNISES ONE ERROR AND NOTHING ELSE. There is no heuristic here, no
// string matching, and no list of failures that are "probably" absence, because
// every mistake this function could make points the same way: toward telling a
// caller a record is gone when it may not be, and a caller that believes that
// eventually releases a customer's credential.
func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// normalizeTXT strips the presentation a TXT value picks up in transit: the
// surrounding quotes a zone file uses and a provider's API usually does not,
// and whitespace from wherever it was pasted.
//
// Case is NOT folded. A TXT value is an octet string and a difference in case
// is a real difference to whoever is checking it — a value that looks published
// to us but not to Cloudflare would be the worst of both answers. The one place
// case IS folded is the ownership proof, deliberately, and only there; see
// foldProofValue.
func normalizeTXT(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	return strings.TrimSpace(value)
}

func normalizeTXTValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, normalizeTXT(value))
	}
	return out
}

// foldProofValue is the ownership proof's comparison form.
//
// 🔴 IT MUST AGREE WITH internal/proof's `fold`, WHICH IS THE CANONICAL ONE.
//
// It is duplicated rather than imported because Proof is handed an accept set
// and never an identity, which is what keeps this package unable to decide what
// counts as a valid proof. The duplication is guarded rather than promised:
// TestProofMatchingAgreesWithTheProofPackage drives both this and
// proof.Prover.Matches over one table and fails if they ever disagree.
//
// Case is folded here, unlike every other TXT value, because the proof is
// lowercase base32 and several DNS control panels upper-case what is pasted
// into them. Refusing a proof over presentation would be refusing a customer
// who did exactly what they were asked.
func foldProofValue(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	return strings.ToLower(strings.TrimSpace(value))
}

// matchesAccepted reports whether any observed value is an accepted one.
//
// `accepted` is used exactly as supplied: it comes straight from
// proof.Prover.Accepted, which returns the canonical spelling, and folding it
// here would let this package accept a value that proof.Prover.Matches would
// reject.
func matchesAccepted(observed, accepted []string) bool {
	match := false
	for _, candidate := range observed {
		candidate = foldProofValue(candidate)
		if candidate == "" {
			continue
		}
		for _, want := range accepted {
			if want == "" {
				continue
			}
			// hmac.Equal, and no early return: the candidate is whatever a zone
			// we do not control chose to publish, and the expected values are
			// derived from a key that never leaves this deployment. Neither the
			// comparison nor the loop's duration should report how close a guess
			// came. It costs nothing to be right about this.
			if hmac.Equal([]byte(candidate), []byte(want)) {
				match = true
			}
		}
	}
	return match
}

// explain joins the derived item's reason for existing to this observation's
// diagnosis. Both survive because they answer different halves of the same
// question — why is this record here, and why has adding it not worked.
func explain(itemExplain, diagnosis string) string {
	itemExplain = strings.TrimSpace(itemExplain)
	diagnosis = strings.TrimSpace(diagnosis)
	switch {
	case itemExplain == "":
		return diagnosis
	case diagnosis == "":
		return itemExplain
	default:
		return itemExplain + " — " + diagnosis
	}
}
