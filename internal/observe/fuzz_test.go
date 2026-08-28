package observe

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/derive"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/testsupport"
)

// ---------------------------------------------------------------------------
// 🔴 FINDING, 2026-08-28: THESE TARGETS FAIL, AND THE DEFECT IS IN PRODUCTION
// CODE RATHER THAN IN THE TARGETS. NOTHING HAS BEEN CHANGED TO MAKE THEM PASS.
//
// dnsplan.NormalizeName (internal/dnsplan/plan.go) is NOT IDEMPOTENT:
//
//	NormalizeName(name) = ToLower(TrimSuffix(TrimSpace(name), "."))
//
// TrimSpace runs BEFORE TrimSuffix("."), so whitespace sitting between the last
// label and the root dot survives:
//
//	NormalizeName("example.com .") == "example.com "   (a trailing space)
//	NormalizeName("example.com ")  == "example.com"
//
// The consequence that matters in a repository whose whole promise is a
// containment bound: THE STRING THAT IS CHECKED IS NOT THE STRING THAT IS USED.
// observe.Proof and observe.Plan normalize once, then report that name to the
// customer and issue a lookup for it — while dnsplan.Contains, which decides
// whether the name is inside the anchor, normalizes a SECOND time and therefore
// judges a different string. The same split is reachable in internal/relay.
//
// No anchor ESCAPE follows today, because a second normalization only ever
// removes characters. What is broken is the invariant the promise rests on.
//
// The fix is one line and belongs in dnsplan, not here: trim the root dot
// before the whitespace (or trim space again afterwards). It has deliberately
// NOT been applied — see the task's standing rule that a found defect is
// reported, never quietly patched away.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Properties, over arbitrary resolver answers.
//
// Every target here drives the Resolver interface with a fake built from fuzzer
// bytes. Nothing reaches a network, a database or a Cloudflare account — which
// is the property the interface exists to buy, stated in this package's doc
// comment and now checked over inputs nobody chose.
// ---------------------------------------------------------------------------

// fuzzResolver is public DNS as three fuzzer-controlled facts: what TXT values
// came back, what CNAME came back, and whether the lookup completed at all.
//
// It answers every name identically. That is deliberate: these targets are
// about how ONE answer is classified, and varying the name as well would spend
// the fuzzer's budget on the map lookup in fakeResolver rather than on the
// classification the properties are about.
type fuzzResolver struct {
	txt   []string
	cname string
	err   error
}

func (r fuzzResolver) LookupCNAME(_ context.Context, _ string) (string, error) {
	if r.err != nil {
		return "", r.err
	}
	return r.cname, nil
}

func (r fuzzResolver) LookupTXT(_ context.Context, _ string) ([]string, error) {
	if r.err != nil {
		return nil, r.err
	}
	return append([]string(nil), r.txt...), nil
}

var _ Resolver = fuzzResolver{}

// The failure kinds a resolver can report, and the one that is not a failure.
// Only the FIRST is an answer about the customer's zone; every other one is a
// fault on the way to asking.
const (
	fuzzLookupOK       = 0 // the name resolved
	fuzzLookupNotFound = 1 // NXDOMAIN, or no record of this type: an ANSWER
	fuzzLookupTimeout  = 2
	fuzzLookupServfail = 3
	fuzzLookupCanceled = 4
	fuzzLookupOpaque   = 5 // a failure no rule in this package recognises
	fuzzLookupKinds    = 6
)

func fuzzLookupErr(kind uint8, name string) error {
	switch kind % fuzzLookupKinds {
	case fuzzLookupNotFound:
		return testsupport.NotFound(name)
	case fuzzLookupTimeout:
		return timedOut(name)
	case fuzzLookupServfail:
		return servfail(name)
	case fuzzLookupCanceled:
		return context.DeadlineExceeded
	case fuzzLookupOpaque:
		return errors.New("the nameserver said something this package has no rule for")
	default:
		return nil
	}
}

// fuzzValues splits one fuzzer string into a set of published values. An empty
// string is the empty ANSWER — the name resolves and holds nothing of this type
// — which is a different fact from a name that does not resolve.
func fuzzValues(raw string) []string {
	if raw == "" {
		return nil
	}
	return strings.Split(raw, "\n")
}

// fuzzLiberal is a deliberately OVER-permissive fold: it lowercases and strips
// every space, quote and trailing dot, wherever they appear.
//
// 🔴 IT IS NOT A REIMPLEMENTATION OF THIS PACKAGE'S NORMALIZATION, AND MUST NOT
// BECOME ONE. A property that compared against a second copy of the rule under
// test would pass whenever both copies were wrong the same way. This is a
// strict SUPERSET of every fold in this package (all of which only trim edges
// and lowercase), so "the package matched" always implies "fuzzLiberal
// matches". That makes it sound to assert one direction: if this says two
// values cannot possibly be the same value, then a match here is a real defect.
func fuzzLiberal(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == '"' {
			return -1
		}
		return unicode.ToLower(r)
	}, s)
	return strings.TrimRight(s, ".")
}

func fuzzLiberalContains(set []string, value string) bool {
	for _, candidate := range set {
		if fuzzLiberal(candidate) == fuzzLiberal(value) {
			return true
		}
	}
	return false
}

// fuzzIsAState reports whether s is one of the five defined constants.
// fuzzTriageSkipKnownDefect: see the relay copy. False in anything committed.
var fuzzTriageSkipKnownDefect = false

func fuzzIsAState(s State) bool {
	switch s {
	case StatePresent, StateAbsent, StateConflicting, StateWrongType, StateUnknown:
		return true
	}
	return false
}

// FuzzAFailedLookupIsNeverPresent is the most important property in this
// package, in the words a customer would recognise:
//
// 🔴 A NAMESERVER THAT FAILED TO ANSWER MUST NEVER READ AS A PUBLISHED PROOF.
//
// verify() is the gate the whole design turns on. The ownership TXT is the
// CUSTOMER's record, re-read on every pass, and it is the only thing standing
// between MirrorStack and a write into a zone whose owner never agreed to it.
// If a timeout, a SERVFAIL, a cancelled context or an error nobody has a rule
// for could come back as ok==true, then a resolver blip on OUR side would
// unlock a grant on a domain nobody proved — the customer's first control
// (DESIGN §8) defeated by our own infrastructure having a bad minute.
//
// The property, over arbitrary answers: ok is true ONLY when the lookup
// completed AND one of the accepted values is genuinely among what was
// published. Nothing else may be read as that.
//
// 🔴 AND THE SAME LINE IN THE OTHER DIRECTION: AN ERROR MUST NEVER BE SPELLED
// "ABSENT". Absence is the customer saying no — deleting the proof is how they
// withdraw consent, and the caller eventually releases a live credential over
// it. A fault that reported itself as absence would make our own outage
// indistinguishable from their withdrawal. Only NXDOMAIN, which is DNS
// answering, may be absence.
func FuzzAFailedLookupIsNeverPresent(f *testing.F) {
	const proofValue = "gk2v6qz4bqx3nq7m5r8t9wjy4h2c6d8f0a1b3e5g7i9k"
	// The cases observe_test.go already names, so a plain `go test` run
	// exercises them: the value published, a rotated-out value published beside
	// it, presentation folded but meaning not, nothing published, the name not
	// resolving, and every failure kind.
	f.Add(anchor, proofValue, proofValue, uint8(fuzzLookupOK))
	f.Add(anchor, "other-value\n"+proofValue, proofValue, uint8(fuzzLookupOK))
	f.Add(anchor, strings.ToUpper(proofValue), proofValue, uint8(fuzzLookupOK))
	f.Add(anchor, `"`+proofValue+`"`, proofValue, uint8(fuzzLookupOK))
	f.Add(anchor, "  "+proofValue+"  ", proofValue, uint8(fuzzLookupOK))
	f.Add(anchor, proofValue+"x", proofValue, uint8(fuzzLookupOK))
	f.Add(anchor, "", proofValue, uint8(fuzzLookupOK))
	f.Add(anchor, "v=spf1 -all", proofValue, uint8(fuzzLookupOK))
	// 🔴 The heart of it: the proof IS published, and the lookup failed anyway.
	for kind := uint8(fuzzLookupNotFound); kind < fuzzLookupKinds; kind++ {
		f.Add(anchor, proofValue, proofValue, kind)
	}
	// A rotated keyset: several accepted values, one of them published.
	f.Add(anchor, proofValue, "older-value\n"+proofValue+"\nnewer-value", uint8(fuzzLookupOK))
	// The deployment defect that must be a refusal rather than a clean negative.
	f.Add(anchor, proofValue, "", uint8(fuzzLookupOK))
	f.Add(anchor, proofValue, "\n\n", uint8(fuzzLookupOK))
	// 🔴 THE MINIMISED REPRODUCER FOR THE DEFECT THIS TARGET FOUND. A label, a
	// space, then the root dot: dnsplan.NormalizeName trims the space BEFORE it
	// trims the dot, so the space survives and the "normalized" name is not
	// normalized. Left here deliberately failing — see the FINDING note above
	// FuzzAFailedLookupIsNeverPresent.
	f.Add("0 .", "0", "0", uint8(fuzzLookupTimeout))
	f.Add(anchor+" .", proofValue, proofValue, uint8(fuzzLookupOK))
	// Names that are not names.
	f.Add("", proofValue, proofValue, uint8(fuzzLookupOK))
	f.Add(".", proofValue, proofValue, uint8(fuzzLookupOK))
	f.Add(strings.Repeat("a.", 200), proofValue, proofValue, uint8(fuzzLookupOK))

	f.Fuzz(func(t *testing.T, name, publishedRaw, acceptedRaw string, errKind uint8) {
		published := fuzzValues(publishedRaw)
		accepted := fuzzValues(acceptedRaw)
		lookupErr := fuzzLookupErr(errKind, name)
		r := fuzzResolver{txt: published, err: lookupErr}

		ok, obs, err := Proof(context.Background(), r, name, accepted)

		// The report is always populated and always well-formed, including on
		// the error return: a caller has to be able to log what was seen.
		if !fuzzIsAState(obs.State) {
			t.Fatalf("Proof returned the undefined state %q", obs.State)
		}
		if obs.Type != "TXT" {
			t.Fatalf("Proof reported type %q; the ownership proof is a TXT", obs.Type)
		}
		if obs.Name != dnsplan.NormalizeName(obs.Name) && !fuzzTriageSkipKnownDefect {
			t.Fatalf("Proof reported the unnormalized name %q", obs.Name)
		}
		// 🔴 Found may only hold values the resolver actually returned. A report
		// that invents a value is a report a customer cannot check us against.
		for _, found := range obs.Found {
			if !fuzzLiberalContains(published, found) {
				t.Fatalf("Proof reported Found=%q, which the resolver never returned (it returned %q)", found, published)
			}
		}
		if err != nil && ok {
			t.Fatalf("Proof returned ok=true together with an error: %v", err)
		}

		nameUsable := obs.Name != "" && len(obs.Name) <= dnsplan.MaxDNSName
		acceptedUsable := false
		for _, value := range accepted {
			if value != "" {
				acceptedUsable = true
			}
		}

		// Two refusals happen BEFORE any lookup, and both must be errors rather
		// than a clean negative. An empty accept set means our own keyset
		// produced nothing; reported as (false, absent, nil) the caller could
		// not tell it from a customer who simply has not published yet, and
		// would eventually release a live credential over a fault of ours.
		if !nameUsable || !acceptedUsable {
			if err == nil {
				t.Fatalf("Proof accepted an unusable request (nameUsable=%v acceptedUsable=%v) with no error; ok=%v state=%q",
					nameUsable, acceptedUsable, ok, obs.State)
			}
			if !errors.Is(err, ErrObserve) {
				t.Fatalf("Proof refused an unusable request with an unclassified error: %v", err)
			}
			if ok {
				t.Fatalf("Proof returned ok=true on a request it refused")
			}
			return
		}

		// From here the resolver WAS consulted, and every claim below is about
		// what may be concluded from its answer.
		switch {
		case lookupErr == nil:
			if err != nil {
				t.Fatalf("a completed lookup produced an error: %v", err)
			}
			// 🔴 ok requires a GENUINE match. fuzzLiberal is more permissive
			// than anything in this package, so if it finds no pair that could
			// possibly be equal, an ok here is a proof accepted over a value
			// nobody published.
			if ok {
				matched := false
				for _, value := range published {
					for _, want := range accepted {
						if want != "" && fuzzLiberal(value) == fuzzLiberal(want) {
							matched = true
						}
					}
				}
				if !matched {
					t.Fatalf("Proof said the ownership proof is published, but none of %q is any of %q",
						published, accepted)
				}
			}
			if ok != (obs.State == StatePresent) {
				t.Fatalf("ok=%v disagrees with state %q", ok, obs.State)
			}

		case isNotFound(lookupErr):
			// The one failure that IS an answer: DNS said the name holds
			// nothing. That is the customer not having published yet, and it is
			// the ordinary state of every registration — an error here would
			// make the loop treat waiting as a fault.
			if err != nil {
				t.Fatalf("NXDOMAIN was reported as an error: %v", err)
			}
			if obs.State != StateAbsent {
				t.Fatalf("NXDOMAIN produced state %q, want %q", obs.State, StateAbsent)
			}
			if ok {
				t.Fatalf("Proof said a name that does not resolve is published")
			}

		default:
			// 🔴 EVERY OTHER FAILURE. Not present, not absent, and surfaced.
			if ok {
				t.Fatalf("a failed lookup (%v) read as a published proof", lookupErr)
			}
			if obs.State == StateAbsent {
				t.Fatalf("a failed lookup (%v) was spelled ABSENT; a fault must not look like the customer withdrawing their proof", lookupErr)
			}
			if obs.State != StateUnknown {
				t.Fatalf("a failed lookup (%v) produced state %q, want %q", lookupErr, obs.State, StateUnknown)
			}
			if err == nil {
				t.Fatalf("a failed lookup (%v) was not surfaced to the caller", lookupErr)
			}
		}
	})
}

// FuzzObservationStatesArePartitioned encodes the claim `describe` makes to a
// customer: every line of the report says one of five things, and every value
// it shows you is a value that actually resolves in your zone.
//
// 🔴 A REPORT WITH AN UNDEFINED STATE IN IT IS WORSE THAN NO REPORT, and a
// report that shows a value nobody published is one a customer cannot check us
// against. Both are silent failures: the page renders, the support reply is
// still needed, and nothing anywhere says why.
//
// The same "an error is never absence" line holds here as it does for the
// proof, and it is asserted over arbitrary answers rather than over the failure
// kinds somebody listed.
func FuzzObservationStatesArePartitioned(f *testing.F) {
	// The states observe_test.go names, one seed each.
	f.Add("CNAME", "account."+anchor, routingCNAME, routingCNAME, "", uint8(fuzzLookupOK), uint8(1))
	f.Add("CNAME", "account."+anchor, routingCNAME, "somewhere.example.net", "", uint8(fuzzLookupOK), uint8(1))
	f.Add("CNAME", "account."+anchor, routingCNAME, "account."+anchor, "", uint8(fuzzLookupOK), uint8(1))
	f.Add("CNAME", "account."+anchor, routingCNAME, routingCNAME+".", "", uint8(fuzzLookupOK), uint8(1))
	f.Add("CNAME", "account."+anchor, routingCNAME, "", "", uint8(fuzzLookupOK), uint8(1))
	f.Add("TXT", "_cf."+anchor, "token", "", "token", uint8(fuzzLookupOK), uint8(1))
	f.Add("TXT", "_cf."+anchor, "token", "", "other\ntoken", uint8(fuzzLookupOK), uint8(1))
	f.Add("TXT", "_cf."+anchor, "token", "", "other", uint8(fuzzLookupOK), uint8(1))
	f.Add("TXT", "_cf."+anchor, "token", "", "", uint8(fuzzLookupOK), uint8(1))
	for kind := uint8(fuzzLookupNotFound); kind < fuzzLookupKinds; kind++ {
		f.Add("CNAME", "account."+anchor, routingCNAME, routingCNAME, "", kind, uint8(1))
		f.Add("TXT", "_cf."+anchor, "token", "", "token", kind, uint8(1))
	}
	// The two items that are answered without a lookup at all.
	f.Add("TXT", anchor, "proof", "", "proof", uint8(fuzzLookupOK), uint8(0))     // the ownership proof
	f.Add("TXT", "_x."+anchor, "", "", "anything", uint8(fuzzLookupOK), uint8(1)) // a value not known yet
	// The shapes Plan refuses outright.
	f.Add("A", "account."+anchor, "203.0.113.1", "", "", uint8(fuzzLookupOK), uint8(1))
	f.Add("CNAME", "account.example.net", routingCNAME, "", "", uint8(fuzzLookupOK), uint8(1))
	f.Add("CNAME", "notexample.com", routingCNAME, "", "", uint8(fuzzLookupOK), uint8(1))
	f.Add("CNAME", "", routingCNAME, "", "", uint8(fuzzLookupOK), uint8(1))
	f.Add("CNAME", "*."+anchor, routingCNAME, routingCNAME, "", uint8(fuzzLookupOK), uint8(1))

	f.Fuzz(func(t *testing.T, recordType, name, want, cname, txtRaw string, errKind, purposeSel uint8) {
		published := fuzzValues(txtRaw)
		lookupErr := fuzzLookupErr(errKind, name)
		r := fuzzResolver{txt: published, cname: cname, err: lookupErr}

		purpose := derive.PurposeRouting
		if purposeSel%4 == 0 {
			purpose = derive.PurposeOwnership
		}
		// Two items in one group, so the "one lookup serves the group, and each
		// item gets its own copy of Found" path is exercised as well.
		p := planOf(
			item(recordType, name, want, purpose, derive.SourceDerived),
			item(recordType, name, cname, derive.PurposeCertACM, derive.SourceRelayed),
		)

		got, err := Plan(context.Background(), r, p)
		if err != nil {
			// A refusal is a whole-plan refusal, by one of two named reasons,
			// and it publishes no partial report.
			if !errors.Is(err, ErrObserve) && !errors.Is(err, dnsplan.ErrAnchorEscape) {
				t.Fatalf("Plan refused with an unclassified error: %v", err)
			}
			if got != nil {
				t.Fatalf("Plan returned %d observations alongside a refusal", len(got))
			}
			return
		}

		// 🔴 ONE OBSERVATION PER ITEM, ALWAYS. A report with a hole in it is
		// worse than no report, because the hole is silent.
		if len(got) != len(p.Items) {
			t.Fatalf("Plan returned %d observations for %d items", len(got), len(p.Items))
		}

		// What the resolver could possibly have said, for each type.
		answered := published
		if strings.EqualFold(strings.TrimSpace(recordType), "CNAME") {
			answered = []string{cname}
		}

		for i, obs := range got {
			if !fuzzIsAState(obs.State) {
				t.Fatalf("item %d has the undefined state %q", i, obs.State)
			}
			if obs.Type != "CNAME" && obs.Type != "TXT" {
				t.Fatalf("item %d reports type %q; this service publishes only CNAME and TXT", i, obs.Type)
			}
			if obs.Name != dnsplan.NormalizeName(obs.Name) && !fuzzTriageSkipKnownDefect {
				t.Fatalf("item %d reports the unnormalized name %q", i, obs.Name)
			}
			// Containment is the boundary this whole repository is about: a
			// report line naming something outside the anchor is a record we
			// have no business managing, presented to a customer as one we do.
			if !dnsplan.Contains(anchor, obs.Name) {
				t.Fatalf("item %d reports %q, which is not at or under the anchor %q", i, obs.Name, anchor)
			}
			// 🔴 Found may only hold values the resolver actually returned.
			for _, found := range obs.Found {
				if !fuzzLiberalContains(answered, found) {
					t.Fatalf("item %d reports Found=%q, which the resolver never returned (it returned %q)",
						i, found, answered)
				}
			}
			// 🔴 An error is never absence, here as at the proof. The two items
			// that are answered without a lookup are exempt: no lookup was
			// issued for them, so the resolver's failure did not reach them.
			lookedUp := obs.Purpose != derive.PurposeOwnership && obs.Want != ""
			if lookedUp && lookupErr != nil && !isNotFound(lookupErr) && obs.State != StateUnknown {
				t.Fatalf("item %d turned the failed lookup %v into state %q; only an ANSWER may be anything but unknown",
					i, lookupErr, obs.State)
			}
			// Only a CNAME is exclusive at its owner, so only a CNAME can be
			// conflicting. A TXT reported as conflicting would send a customer
			// off to delete records that were fine.
			if obs.State == StateConflicting && obs.Type != "CNAME" {
				t.Fatalf("item %d is a %s reported as conflicting; TXT records add beside each other", i, obs.Type)
			}
			// The ownership proof is never decided from here — it is checked
			// against every key in the keyset, and only verify() sees that set.
			if obs.Purpose == derive.PurposeOwnership && obs.State != StateUnknown {
				t.Fatalf("item %d decided the ownership proof from a describe report: state %q", i, obs.State)
			}
		}

		// The two items ask the same question, so the report may not contradict
		// itself about what is published at that name.
		if got[0].Purpose != derive.PurposeOwnership && got[0].Want == got[1].Want && got[0].State != got[1].State {
			t.Fatalf("two items asking the same question of one name disagree: %q vs %q", got[0].State, got[1].State)
		}
	})
}
