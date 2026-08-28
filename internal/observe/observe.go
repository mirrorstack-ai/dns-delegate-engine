// Package observe answers one question and refuses to answer any other: what
// does PUBLIC DNS say about the names in a plan, right now?
//
// It makes two of the seven lifecycle functions real. `describe` reports every
// record's purpose beside whether it is present, absent, conflicting or the
// wrong type, so "I added it and nothing happened" has an answer needing no
// support reply. `verify` resolves the ownership proof — the CUSTOMER's record,
// re-checked on EVERY pass, read nowhere but here; that closes the second defect
// in docs/DESIGN.md §1.
//
// 🔴 EVERYTHING THIS PACKAGE LEARNS COMES FROM A Resolver IT WAS HANDED.
//
// `Resolver` is an interface and every test here drives a fake one — a property
// of the repository, not a testing convenience. A customer's own developers are
// asked to settle "could MirrorStack break our website?" by reading this code,
// which a package confirmable only against live infrastructure cannot do.
//
// Nothing here writes: no provider client, no credential, no path that reaches
// one. Observation and mutation live in different packages so reading the
// imports tells you which you have.
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
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsprovider"
)

// ErrObserve is this package's single refusal: the plan cannot be observed at
// all. Only defects in the REQUEST — a missing resolver, an oversized plan, an
// item that is not a record. A record not published yet is State absent, the
// ordinary early state of every registration, and must never look like a fault.
//
// The containment refusal deliberately does NOT use this sentinel: it returns
// dnsplan.ErrAnchorEscape, the same error the write path returns, so "did
// something name a record outside the proven parent?" has one answer wherever
// it happened.
var ErrObserve = errors.New("observe: cannot observe this plan")

// maxInFlight bounds how many names are resolved at once. Small on purpose: a
// dozen names at most, against a zone's two to four authoritative nameservers,
// on a five-minute loop across every registration this deployment holds. A wider
// fan-out buys milliseconds and arrives as a burst some providers rate-limit —
// turning a report into a page of `unknown` for reasons that were ours.
const maxInFlight = 4

// defaultTimeout bounds one lookup when NetResolver.Timeout is zero. An
// authoritative nameserver answers in tens of milliseconds; five seconds leaves
// room to retry a dropped packet and still lets a dozen names with one dead
// nameserver produce a whole report inside one invocation.
const defaultTimeout = 5 * time.Second

// Resolver is public DNS. It is an interface so this repository's tests need no
// network, no database and no Cloudflare account.
//
// The contract is narrower than net.Resolver's; the difference is the point of
// NetResolver's doc comment below.
//
//   - LookupCNAME returns the target published AT name, not the far end of the
//     chain. A name that resolves holding no CNAME comes back unchanged: how an
//     implementation says "something else answers here", and the only evidence
//     of a wrong type public DNS reliably gives us.
//   - LookupTXT returns every TXT value at name, in no meaningful order.
//   - A name that does not resolve is a *net.DNSError with IsNotFound set. Any
//     other error means the lookup did not complete, and is never read here as
//     absence.
type Resolver interface {
	LookupCNAME(ctx context.Context, name string) (string, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// NetResolver is the production Resolver, over the standard library.
//
// 🔴 IT CONSULTS NO CACHE OF OURS.
//
// One field, and it is a timeout: no map, no memo, no store, and a fresh
// net.Resolver per lookup so the absence of one is visible rather than asserted.
// A registration is advanced by the CUSTOMER's publication, so a remembered
// answer would let a since-deleted proof keep this service writing into a zone
// whose owner has withdrawn it.
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
// PreferGo is load-bearing. Measured in Go 1.26's net/dnsclient_unix.go, not
// inferred from the LookupCNAME doc comment, which describes the other path.
// Without it cgo's getaddrinfo with AI_CANONNAME may answer, resolving an
// ADDRESS: it follows the chain to its end and fails outright when the chain
// terminates in a name with no A or AAAA. Two of our records do exactly that —
// `_acme-challenge.<host>` points at a Cloudflare DCV name serving a TXT, and
// `_<token>.<host>` into `.acm-validations.aws` — so on the cgo path a correctly
// published validation record reads as MISSING, the worst answer this package
// could give. The pure Go resolver issues a real CNAME query alongside A and
// AAAA and takes the FIRST CNAME in the answer section, which is what makes the
// Resolver contract above achievable at all.
//
// One consequence: with PreferGo the CNAME lookup consults the container's
// /etc/hosts before DNS. Nothing here writes that file, and a deployment that
// did could make a name appear to resolve however it liked. The TXT lookup —
// the ownership proof's — never consults it, going straight to
// /etc/resolv.conf.
type NetResolver struct {
	// Timeout bounds ONE lookup, not the whole report; zero means
	// defaultTimeout. The caller's ctx bounds everything above it.
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

func (n NetResolver) resolver() *net.Resolver {
	return &net.Resolver{PreferGo: true}
}

// rooted appends the root dot.
//
// 🔴 A NAME WE ASK ABOUT MUST BE ABSOLUTE. Measured in Go 1.26's nameList: a
// name WITHOUT a trailing dot is tried against /etc/resolv.conf's `search` list
// as well as on its own, so a lookup of a customer's absent record could be
// answered by whatever `<name>.<our-search-domain>` resolves to. A rooted name
// is queried once, exactly as written.
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

	// StateAbsent means the expected value is not there — for a TXT, including
	// "other values are there, but not this one".
	StateAbsent State = "absent"

	// StateConflicting means something else answers there and cannot be added
	// beside. Only a CNAME can be conflicting; only a CNAME is exclusive at its
	// owner.
	StateConflicting State = "conflicting"

	// StateWrongType means the name resolves, through a different record type
	// than the one that belongs there.
	StateWrongType State = "wrong_type"

	// StateUnknown means nothing may be concluded. Two things produce it: the
	// lookup did not complete, or this report is structurally unable to decide
	// (the ownership proof — see Plan).
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

	// Want is the value that should be published there. Empty for the ownership
	// proof, which is accepted against a SET of values — see Proof.
	Want string

	State State

	// Found is what was published at Name, normalized like Want so the two read
	// side by side. Populated on every state with something to show, INCLUDING
	// present: a report saying "yes" without saying what it saw is uncheckable.
	Found []string

	// Purpose and Source are carried through from the derived item unchanged.
	// This package classifies what is published and has no opinion about why a
	// record exists; inventing one would let that vocabulary drift from derive's.
	Purpose derive.Purpose
	Source  derive.Source

	// Explain is the derived item's explanation and this observation's
	// diagnosis, joined. See explain.
	Explain string
}

// Plan observes every item in a plan, concurrently and bounded. The result has
// one Observation per item, in item order, on every path that returns without
// an error: a report with holes is worse than no report, the hole being silent.
//
// 🔴 IT DOES NOT DECIDE THE OWNERSHIP PROOF, AND MUST NOT BE MADE TO.
//
// derive puts the ownership record in the plan carrying the value a customer is
// asked to publish TODAY, but the keyset accepts one value per key, so a proof
// published months ago under a since-rotated key is valid and would not match.
// Judging it here would contradict verify() on the record everything else hangs
// from: `describe` would say absent and offer a fix while the domain works. So
// the ownership item is reported unknown with no lookup issued, and the caller
// overlays Proof's Observation, which compares against the whole accept set.
//
// It refuses the WHOLE plan for two defects rather than reporting around them,
// the same call dnsplan.NewSnapshot makes. A record outside the anchor, or a
// type this service does not publish, is a derivation bug — and the report goes
// in front of a customer as "the records this service manages in your zone", so
// a line we have no business managing is a lie we would ask them to act on.
func Plan(ctx context.Context, r Resolver, p derive.Plan) ([]Observation, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: no resolver", ErrObserve)
	}
	anchor := dnsplan.NormalizeName(p.Anchor)
	if anchor == "" || len(anchor) > dnsplan.MaxDNSName {
		return nil, fmt.Errorf("%w: anchor is not a DNS name", ErrObserve)
	}
	// The same bound the write path uses. A plan is one ownership group, not a
	// bulk zone-editing primitive; more turns a corrupt plan into a fan-out of
	// queries at a customer's nameservers.
	if len(p.Items) > dnsplan.MaxRecords {
		return nil, fmt.Errorf("%w: %d items", ErrObserve, len(p.Items))
	}

	observations := make([]Observation, len(p.Items))
	// Grouped by the name and type they ask about; one lookup serves the group.
	// Not a cache — one observation shared by items asking the same question in
	// one report. Two TXT values at an owner judged against two separate answers
	// can disagree for no reason but timing, and a self-contradicting report is
	// what produces a support reply.
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

		// CNAME and TXT are the only types this service publishes, and the README
		// says so as a promise. Observing another would widen what this
		// repository claims to touch.
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

		// The ownership proof, deferred to Proof. No lookup: this package cannot
		// see the accept set from a plan, and a query whose answer it may not
		// judge is worth not making.
		if item.Purpose == derive.PurposeOwnership {
			observations[i].State = StateUnknown
			observations[i].Explain = explain(item.Explain,
				"this report does not decide the ownership proof. It is checked against every key in the keyset, including keys that have since rotated, and only verify() can see that set — a proof published under an older key is still valid and would be misreported here.")
			continue
		}

		// A value not known yet is legitimate, not a defect: the relayed records
		// exist in the plan before AWS or Cloudflare have produced what goes in
		// them. Nothing has been asked of the customer, so nothing is looked for
		// and no query is issued. Absent would be wrong in the direction that
		// costs a support reply.
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
			// Copied, not shared: two items in one group get the same answer, and
			// a caller sorting or trimming one report's Found would otherwise
			// reorder an observation it never touched. A nil stays nil, keeping
			// "nothing found" apart from "an empty answer".
			observations[i].Found = append([]string(nil), found...)
			observations[i].Explain = explain(observations[i].Explain, diagnosis)
		}
	}
	return observations, nil
}

// Proof resolves the ownership TXT and reports whether ANY of the accepted
// values is published.
//
// 🔴 THE CALLER CANNOT SAY WHAT TO LOOK FOR (docs/DESIGN.md §4). `accepted`
// comes from internal/proof, recomputed from the sealed registration, never from
// a request field: a caller that could supply the value to match against could
// satisfy the proof with a string it made up. There is more than one because the
// MAC key rotates — every key in the keyset produces one and all are accepted,
// so a rotation does not invalidate a proof published months ago.
//
// The three returns are all meaningful, including together:
//
//   - ok reports the proof resolved and matched. Nothing else may be read so.
//   - obs is always populated, including on the error return, so a caller can
//     render what was seen rather than only that something failed.
//   - err is non-nil only when the lookup did not complete or the request was
//     malformed. A proof not published yet is (false, absent, nil) — every
//     registration's ordinary early state, and an error there would make the
//     loop treat waiting as a fault.
func Proof(ctx context.Context, r Resolver, name string, accepted []string) (ok bool, obs Observation, err error) {
	obs = Observation{Type: "TXT", Name: dnsplan.NormalizeName(name), State: StateUnknown}
	if r == nil {
		return false, obs, fmt.Errorf("%w: no resolver", ErrObserve)
	}
	if obs.Name == "" || len(obs.Name) > dnsplan.MaxDNSName {
		return false, obs, fmt.Errorf("%w: the ownership proof name is not a DNS name", ErrObserve)
	}
	// 🔴 AN EMPTY ACCEPT SET IS A REFUSAL, NEVER A CLEAN NEGATIVE. It means the
	// keyset produced nothing, a deployment defect on our side. (false, absent,
	// nil) would be indistinguishable from a customer who has not published yet,
	// and would eventually release a live credential over a fault of ours.
	usable := 0
	for _, value := range accepted {
		if value != "" {
			usable++
		}
	}
	if usable == 0 {
		return false, obs, fmt.Errorf("%w: no accepted ownership value was supplied", ErrObserve)
	}

	// Want stays empty deliberately: the accept set holds one value per key with
	// no marker for which is active, so displaying one would be arbitrary and
	// displaying all would put every retired key's value into a customer-facing
	// report. The value to SHOW is proof.Prover.Expected, which the caller
	// holds.
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
// it could not be asked. The two stay apart all the way to classify, so nothing
// can turn a failure into an empty result.
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
			// The context is already finished, so the remaining names get its
			// error rather than a lookup that cannot succeed: unknown, never
			// absent.
			results[i] = answer{err: ctx.Err()}
			continue
		}
		wg.Add(1)
		go func(i int, key lookupKey) {
			defer wg.Done()
			defer func() { <-slots }()
			// Re-checked here: this one may have waited for a slot behind a
			// name that used the whole budget.
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
		// Every error that is not "no such name" is unknown — dnsprovider's
		// IsAmbiguous rule for writes, pointed the other way.
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
		return StateUnknown, nil, "the lookup returned neither a value nor an error, so nothing can be concluded about this name."

	// got == name is the resolver contract's "resolves, but holds no CNAME".
	case got == name:
		return StateWrongType, nil, "this name resolves, but not through a CNAME — address records answer here. On Cloudflare that is exactly what a proxied (orange cloud) record looks like from outside: the CNAME is in your zone, but public DNS serves addresses instead and nothing downstream can follow it. Records in this plan must stay DNS-only (grey). An existing A or AAAA record at this name has the same effect and has to be removed before a CNAME can be added, because a CNAME cannot share its owner."

	case got == want:
		return StatePresent, []string{got}, "published as expected."

	// A different target is conflicting, not absent, and the report names it:
	// the customer cannot decide what to change without knowing what is there.
	default:
		return StateConflicting, []string{got}, fmt.Sprintf("a CNAME is published here, but it points at %q. A name can hold only one CNAME, so this cannot be added alongside — the existing record has to be changed or removed first.", got)
	}
}

// classifyTXT judges an owner that may legitimately hold many values.
//
// 🔴 NO TXT OBSERVATION IS EVER CONFLICTING, AND THAT IS NOT A SIMPLIFICATION.
// TXT records ADD beside each other: a second value never displaces the first,
// and every consumer scans the set for the one it cares about. Other values are
// information; reporting them as a conflict would send a customer off to delete
// records that were fine.
//
// It is also the other half of the defect this rebuild fixes (docs/DESIGN.md
// §1). Containment bounds a record's NAME — nearly enough for a CNAME, since
// writing one at an owner the customer serves from is visibly destructive and
// the reconciler updates in place. For a TXT it bounds almost nothing: a value
// added beside an existing one at an in-anchor name is invisible and can still
// do damage — a second `v=spf1` TXT at the apex is an SPF permerror under
// RFC 7208 §4.5, i.e. a customer's mail delivery, published from a name they
// proved they owned. Containment could never catch that, so the fix had to be
// that the caller can no longer name a value at all.
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
	// Absent WITH what is there: the value with the dropped character sits next to
	// the one asked for, answering "I added it and nothing happened" on its own.
	return StateAbsent, values, fmt.Sprintf("this value is not among the %d TXT value(s) published here. The published ones can stay — TXT records add beside each other — the expected value only has to be added.", len(values))
}

// isNotFound reports the one error that means the name genuinely does not
// resolve. NXDOMAIN and "the name exists but has no record of this type" both
// arrive as *net.DNSError with IsNotFound set.
//
// 🔴 IT RECOGNISES ONE ERROR AND NOTHING ELSE. No heuristic, no string matching,
// no list of failures that are "probably" absence: every mistake it could make
// points one way, toward telling a caller a record is gone when it may not be —
// and a caller that believes that eventually releases a customer's credential.
func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// normalizeTXT strips the presentation a TXT value picks up in transit: the
// quotes a zone file uses and a provider's API usually does not, and whitespace
// from wherever it was pasted.
//
// The quotes go through dnsprovider.TrimTXTQuotes, which is the form the WRITE
// path compares with — "this value is already correct" and "this value is
// published" have to be one question.
//
// Case is NOT folded. A TXT value is an octet string, and a difference in case
// is a real difference to whoever is checking it — a value that looks published
// to us but not to Cloudflare would be the worst of both answers. The ownership
// proof is the one deliberate exception; see foldProofValue.
func normalizeTXT(value string) string {
	value = dnsprovider.TrimTXTQuotes(strings.TrimSpace(value))
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

// foldProofValue is the ownership proof's comparison form: normalizeTXT, then
// case folded, because the proof is lowercase base32 and several DNS control
// panels upper-case what is pasted into them. Refusing over presentation would
// refuse a customer who did as asked.
//
// 🔴 IT MUST AGREE WITH internal/proof's `fold`, WHICH IS THE CANONICAL ONE.
// Not imported because Proof is handed an accept set and never an identity —
// what keeps this package unable to decide what counts as a valid proof — so
// TestProofMatchingAgreesWithTheProofPackage drives this and proof.Prover.Matches
// over one table and fails if they ever disagree.
func foldProofValue(value string) string {
	return strings.ToLower(normalizeTXT(value))
}

// matchesAccepted reports whether any observed value is an accepted one.
// `accepted` is used exactly as supplied — proof.Prover.Accepted returns the
// canonical spelling, and folding it here would accept a value
// proof.Prover.Matches would reject.
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
			// hmac.Equal, and no early return: the candidate is whatever a zone we
			// do not control published, and the expected values come from a key
			// that never leaves this deployment. Neither the comparison nor the
			// loop's duration should report how close a guess came.
			if hmac.Equal([]byte(candidate), []byte(want)) {
				match = true
			}
		}
	}
	return match
}

// explain joins the derived item's reason for existing to this observation's
// diagnosis. Both survive: why is this record here, and why has adding it not
// worked.
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
