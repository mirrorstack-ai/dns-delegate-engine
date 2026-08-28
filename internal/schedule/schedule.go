// Package schedule declares the clock the advance loop runs on.
//
// 🔴 THIS PACKAGE IS A DECLARATION. IT IS NOT A CONTROL.
//
// The numbers below are published so that "how often could MirrorStack touch my
// zone, and under what conditions" has an answer somebody outside the company
// can read: the ordinary gap between two passes over one registration, the
// spread that keeps a fleet from advancing in the same second, the floor, what a
// failed pass waits and how far that grows, how many passes a stuck registration
// gets, and whether a pass that finds nothing missing writes anything (it does
// not). They are constants in a public file rather than settings in a private
// scheduler because a promise denominated in ticks is worth exactly what the
// tick is worth, and a tick that can only be learned by asking us is worth
// nothing to the person relying on it.
//
// What this package does NOT do is make any of it happen:
//
//	declared here   the intended gap, the spread, the floor, the backoff curve
//	                and its ceiling, the pass ceiling, and the quiet steady
//	                state — as constants, and as three functions that compute
//	                them.
//	done elsewhere  which registrations exist, which one is asked about next,
//	                when it is asked, and whether it is asked at all.
//
// That split is structural, not a preference. Deciding something is due needs
// the list of registrations; the list is rows; this service owns no rows and
// never will (CLAUDE.md, "No database, ever", and DESIGN.md §7). So the private
// half in api-platform holds the list AND the clock. Advance, Complete and
// BindAppToOrgAppDomain publish as fast as they are invoked, and nothing in this
// repository slows them down.
//
// 🔴 SO THE FLOOR IS DECLARED HERE AND ENFORCED NOWHERE, and the reason is worth
// stating rather than leaving a reader to assume it is unfinished work. Refusing
// an early pass means knowing when the last one ran, and there is nowhere honest
// to keep that timestamp. DESIGN §5 lists every field the caller may send and
// none of them is a time; neither sealed envelope carries one. Sealing one would
// not fix it either: the private half holds every envelope this service ever
// issued and can hand back an older one, and rolling a last-pass time backwards
// asks for MORE frequency, not less. That is the same argument §8 gives for why
// a stateless service cannot count deletions, and it lands the same way here.
//
// Which is why the numbers are still worth publishing:
//
//	a declared cadence is a claim a customer can falsify. An undeclared one
//	cannot be checked at all.
//
// How far that goes is worth being precise about, because only the checkable
// half is any use. Every write we make under an anchor lands in the customer's
// own zone with a timestamp, in a log we do not control and cannot edit. Quiet
// is the claim it tests hardest: a converged registration should leave that log
// silent, so a chatty steady state would be visible the first day. A repair
// recurring faster than minInterval would be visible the same way. What a change
// log does NOT show is a pass that wrote nothing — most of them, by design — so
// the poll rate itself is only checkable where the provider logs API access as
// well as changes. Where it is checkable, these are the numbers to check
// against. Where it is not, the two controls in §8 — delete the ownership proof,
// revoke at the provider — end it regardless of what we were doing, and neither
// needs our cooperation. Those are the real bounds; this file is the claim they
// are used to judge.
//
// One neighbouring guarantee does NOT depend on any of this, and confusing the
// two would undersell it. §8's "every write stops within one tick" is kept by
// the pass, not by the clock: intent.Service.pass re-reads the ownership proof
// and, when it resolves as ABSENT, returns before a credential is opened. So the
// cadence cannot open a window between a customer deleting the proof and us
// stopping — a slower loop makes fewer writes, not later ones, and the tick in
// that sentence bounds how long the customer waits to see the record NOT come
// back, not how long we keep writing. (A proof that cannot be resolved at all —
// SERVFAIL, a timeout — is a third state, and what a pass does with it is
// decided there, not here.) That promise is enforced in code. The cadence below
// is not, and the difference is the point of this comment.
//
// Due, Spread and Delay stay because they are that declaration in executable
// form. A reader who wants the wait after the fourth consecutive failure calls
// Delay(4) rather than parsing a sentence, and Due answers the boundary cases —
// never advanced, a clock running ahead, an interval set below the floor — that
// prose leaves ambiguous. Any loop built to run this cadence, ours or a second
// implementation of the private half, should go through them rather than
// re-derive the arithmetic, so the schedule that runs and the schedule that is
// published cannot drift apart. Today they have no caller outside the tests, and
// this comment says so until they do.
//
// Nothing in this file reads a clock of its own, opens a connection, or starts a
// goroutine. Every function is pure and takes the times it needs as arguments,
// which is also why the tests need no network, no database and no account.
package schedule

import (
	"hash/fnv"
	"time"
)

// maxDuration is the largest time.Duration. Used only as an overflow guard in
// Delay; see the comment there for why an overflowing backoff is worse than a
// long one.
const maxDuration = time.Duration(1<<63 - 1)

// Cadence is the declared clock for the advance loop.
//
// Every field is public and every value is published, because each one is a
// fact a customer is entitled to know BEFORE authorizing: together they answer
// "how often could MirrorStack touch my zone, and under what conditions". A
// cadence held privately would leave every time-denominated guarantee in §8
// unfalsifiable — true, perhaps, but not checkable, which in this repository is
// the same as not claimed.
type Cadence struct {
	// Interval is the ordinary gap between two passes over one registration,
	// and so the resolution of anything in §8 measured in time: a proof the
	// customer deletes is noticed one interval after they delete it, if the
	// loop is running at the cadence declared here. A loop running slower
	// notices later — the private half may advance a domain less often than
	// this, or never, which is §7's "a sealed envelope can be withheld" seen
	// from the schedule side and is a limitation in the customer's favour.
	//
	// The direction that would NOT be in their favour is not governed here:
	// §8's "every write stops within one tick" is kept by the proof re-check
	// inside a pass, not by this number. See the package comment.
	Interval time.Duration

	// Jitter is the width of the per-registration offset that keeps a fleet
	// from advancing in the same second; Spread derives it deterministically.
	//
	// Interval + Jitter, not Interval, is the honest reading of "within one
	// tick" — a spread that is never disclosed is a promise quietly widened.
	Jitter time.Duration

	// MinInterval is the floor: the fastest this cadence says a registration
	// may be advanced, whatever a caller asks for.
	//
	// 🔴 IT IS DECLARED, NOT ENFORCED, and it is the field most likely to be
	// misread as a guarantee. Due applies it to every caller that asks — and
	// applies it to a Cadence whose Interval was set below it — but nothing in
	// this service makes a caller ask, because refusing an early pass needs a
	// last-pass timestamp this service has no honest place to keep. The package
	// comment gives that argument in full; it is the same one §8 gives for why
	// we cannot count deletions.
	//
	// What the number is for: it is the rate a customer can hold us to. A
	// repair recurring faster than this in their own change log is us breaking
	// a published claim, in a record they can point at.
	MinInterval time.Duration

	// Backoff is what a failed pass waits before the next one. Worth reading as
	// a customer-facing number rather than an operational one: a failure is
	// frequently the customer's own provider saying "slow down", and backing
	// off is how we stop being the reason their rate limit is exhausted.
	Backoff Backoff

	// MaxPasses is how many consecutive passes may leave a registration still
	// unfinished before the loop should stop advancing it and it becomes
	// something a person looks at. A pass that finds everything present ends
	// the run and resets the count.
	//
	// 🔴 IT IS NOT ONE OF THE CUSTOMER'S STOP BUTTONS. It bounds futile work,
	// not authority: a converged registration keeps being re-checked at this
	// same cadence, which is precisely what §8 admits to when it says "we hold
	// write access to names under your anchor, and we continuously enforce a
	// desired state there until you stop us". Deleting the proof and revoking
	// the grant remain the only two things that end that, and both of them are
	// the customer's alone. Reading this field as a third one would be reading
	// a guarantee that is not here.
	MaxPasses int

	// Quiet declares that a pass which finds nothing missing writes nothing: no
	// touch, no re-PUT of an identical value, no TTL refresh, no reordering.
	//
	// It is a field rather than an unwritten assumption because it is the most
	// important half of "what may this loop do to my zone", and because getting
	// it wrong is invisible from our side and loud from the customer's: several
	// providers stamp a record's modified time on an identical write, so a
	// chatty steady state would make "when did this last actually change?"
	// unanswerable in the customer's own dashboard, and would bury the one
	// write that mattered under a few hundred no-ops a day.
	Quiet bool
}

// Backoff is the wait a failed pass earns, growing with consecutive failures.
type Backoff struct {
	// First is the wait after a single failure.
	First time.Duration

	// Factor multiplies the wait for each additional consecutive failure. A
	// factor below 2 does not grow at all, and Delay treats such a declaration
	// as a flat wait rather than looping forever multiplying by one.
	Factor int

	// Max is the ceiling. A ceiling is not politeness: without one an
	// exponential reaches days, and a registration that would have healed on
	// its own instead sits dark because nobody asked again.
	Max time.Duration
}

// The declared clock, as constants, so that changing one is a diff someone
// outside the company can read. Each carries the argument for its size — what
// it costs the customer if it is too small, and what it costs them if it is too
// large — because a number without its argument is a number the next person
// will change for the wrong reason.
const (
	// interval — 5 minutes.
	//
	// TOO SMALL and a pass mostly re-reads an answer that cannot have changed:
	// the ownership proof is resolved in PUBLIC DNS, that answer is cached, and
	// 300 seconds is the most common TTL there is. Polling at 30 seconds reads
	// one resolver cache entry ten times while spending the customer's provider
	// rate limit on records that were already correct.
	//
	// TOO LARGE and §8's "within one tick" becomes a wait that is felt twice:
	// it is how long after deleting the ownership proof we may still be
	// writing, and how long a connect flow sits on "waiting for your record"
	// with nothing visibly happening.
	//
	// Five minutes is where those meet — one interval is about one cache
	// lifetime, so a pass has a real chance of seeing something new, and a
	// converged domain costs a few hundred reads a day rather than a few
	// thousand.
	interval = 5 * time.Minute

	// jitter — 60 seconds, a fifth of the interval.
	//
	// Registrations that completed in the same minute — a migration, a fleet
	// restart, a deploy that re-armed every loop at once — would otherwise
	// advance in the same second forever after, and the pile lands in exactly
	// one place: the customer's provider API, under the customer's token,
	// against the customer's rate limit. A 429 there is indistinguishable from
	// their own tooling being throttled, so our herd would present as their
	// outage.
	//
	// A fifth rather than a whole interval because jitter widens the tick the
	// customer is promised: with these numbers that tick is six minutes, and a
	// full-interval spread would have made it ten for no additional protection.
	jitter = 60 * time.Second

	// minInterval — 60 seconds, and it is a FLOOR rather than a target.
	//
	// It exists because "how often" has to mean something across a boundary
	// this repository cannot see. A scheduler over there that loops, retries
	// hot, or is deployed twice will not be stopped by this number — nothing
	// here can stop it, see the package comment — but it will be MEASURED
	// against it. Sixty seconds is the line between a fast pass and a bug we
	// have published our own definition of, which is what makes "your zone was
	// touched nine times a minute" a breach of something written down rather
	// than an argument about what is reasonable.
	//
	// It sits well below interval on purpose, so that a legitimate "check now"
	// — a person clicking retry in a console immediately after publishing the
	// proof — is inside what we published, without a code change here. A floor
	// set at the interval would have made the one case that is a human waiting
	// look like the abuse.
	minInterval = 60 * time.Second

	// backoffFirst — 60 seconds, set EQUAL TO minInterval deliberately: the
	// first retry after a failure is the fastest thing the floor permits and no
	// faster. Failures are usually transient (a provider 5xx, a throttle, a
	// half-propagated zone), and waiting a full interval to discover that makes
	// a connect flow feel broken when it is merely slow.
	backoffFirst = minInterval

	// backoffFactor — doubling: 1m, 2m, 4m, 8m, 16m, 32m, then the ceiling.
	backoffFactor = 2

	// backoffMax — 1 hour.
	//
	// TOO SMALL and a provider outage becomes a steady drum on the customer's
	// zone for its entire duration. TOO LARGE and a domain that would have
	// healed by itself stays dark until somebody notices it.
	//
	// An hour is a twelfth of the ordinary pressure — 24 attempts a day rather
	// than 288 — while still giving a multi-hour outage several chances to
	// recover with nobody touching anything. It is also comfortably inside the
	// 24-hour lifetime of a closed lane's grant, so a registration never spends
	// its whole credential sitting inside a single wait.
	backoffMax = time.Hour

	// maxPasses — 288, which is exactly 24 hours of five-minute passes.
	//
	// This bounds the stuck registration: proof published, grant live, and
	// something outside both — a certificate wedged in validation, a name
	// pointed at another provider mid-flight — means the desired state is never
	// reached. Without a ceiling we would try forever, which is a cost to the
	// customer (reads against their zone, and their rate limit) with no path to
	// an outcome.
	//
	// 288 is tied to the 24-hour grant on lanes 1 and 3 on purpose: the passes
	// we are willing to make run out at about the moment the credential we hold
	// to make them does. On lane 2, whose grant is standing, the credential
	// never expires, so this ceiling is the only declared end to a futile run —
	// which is why there is a number here at all rather than whatever the caller
	// thought was reasonable, unwritten.
	//
	// It counts PASSES, not hours. A registration that is failing and backing
	// off spans far longer in wall-clock time, deliberately: passes are what
	// touch a customer's zone, and hours are not.
	maxPasses = 288

	// quiet — true, and there is no code path in this package that sets it
	// false. See Cadence.Quiet for what it costs to get this wrong.
	quiet = true
)

// Declared is the cadence this build publishes.
//
// It is a constant in this file rather than an environment variable, a flag or a
// parameter, and that is the entire point: a value read from configuration is
// not something a reader of this repository can verify. Configuration would let
// someone see the shape of the clock and none of its numbers, which is the
// situation §8 exists to end. Changing any of these is a customer-visible change
// to how often we may touch a zone, so it should be a reviewable diff in a
// public repository.
//
// A diff is only half of it: knowing WHICH revision is deployed needs the
// running service to say so. That is health()'s job, and the claim above is
// worth exactly as much as health()'s answer identifies a commit — so if this
// build's health response carries no revision, the numbers below are checkable
// in the source and not in the deployment, and a customer comparing the two is
// taking our word for which is which.
//
// It returns the whole struct rather than exporting the fields one by one so a
// caller cannot take half a cadence. An interval without its floor is not a
// promise.
func Declared() Cadence {
	return Cadence{
		Interval:    interval,
		Jitter:      jitter,
		MinInterval: minInterval,
		Backoff: Backoff{
			First:  backoffFirst,
			Factor: backoffFactor,
			Max:    backoffMax,
		},
		MaxPasses: maxPasses,
		Quiet:     quiet,
	}
}

// Due reports whether a registration whose last pass was at last may be advanced
// at now. The boundary is inclusive: at exactly last+gap the pass may run, so a
// scheduler that fires on the dot is not pushed out by a whole extra tick.
//
// 🔴 THE REQUIRED GAP IS THE LARGER OF Interval AND MinInterval.
//
// A Cadence whose interval was set below the floor — by a bug, by a test, by
// some future per-lane variation — cannot beat the floor here, because the
// comparison is made at the decision rather than trusted to whoever assembled
// the struct. That is the whole of what this function guarantees, and it is
// worth being exact about the size of it: the floor binds every caller that
// ASKS. Nothing in this service makes one ask, and the package comment says why
// that cannot be fixed from this side.
//
// Three edges fall out of the arithmetic, and all three fail in the safe
// direction:
//
//   - A registration that has never had a pass carries the zero time and is due
//     at once, which is what a freshly completed registration should be. No
//     special case, so no special case to get wrong.
//   - A last in the FUTURE — clock skew, or a row stamped by a machine running
//     ahead — is not due. Skew may delay a pass; it can never accelerate one.
//   - A zero-value Cadence has a non-positive gap and is never due. The empty
//     declaration must answer "no" rather than "always": the opposite default
//     would make a forgotten field the most permissive schedule in the file.
func (c Cadence) Due(last, now time.Time) bool {
	gap := c.Interval
	if c.MinInterval > gap {
		gap = c.MinInterval
	}
	if gap <= 0 {
		return false
	}
	return !now.Before(last.Add(gap))
}

// Spread is the fixed offset added to one registration's next pass, so that a
// fleet which all completed in the same minute does not advance in the same
// second forever after. key is any stable per-registration string the caller
// already holds — the anchor and the lane are the obvious one. It must not
// change between passes; a key that changes re-rolls the phase and un-spreads
// the fleet it was there to spread.
//
// It is DERIVED rather than drawn from a random source, for two reasons. A
// registration then keeps the same phase across restarts, redeploys and any
// number of processes — precisely the events most likely to re-align a fleet,
// and exactly the ones a per-pass random offset does nothing about. And a value
// a reader can recompute from this file is a value they can check; "we call
// rand" is not something anyone can verify from outside.
//
// 🔴 SPREAD ONLY EVER DELAYS. The result is in [0, Jitter), it is ADDED to a
// pass time, and Due deliberately does not consult it. A jitter that could pull
// a pass earlier would mean the declared floor and the declared spread
// contradicting each other — the file would be publishing two numbers a customer
// cannot both hold us to. Jitter widens the tick they are promised and never
// narrows it.
//
// FNV is not a security primitive and nothing here needs it to be one. The
// modulo bias across a 64-bit hash is orders of magnitude below anything
// observable in a schedule; this is spreading, not sampling. An adversary who
// can choose a key can choose their own phase, and gains nothing by it: the
// floor and the ceiling bound every registration identically whatever its phase.
func (c Cadence) Spread(key string) time.Duration {
	if c.Jitter <= 0 {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(key)) // hash.Hash.Write never returns an error
	return time.Duration(h.Sum64() % uint64(c.Jitter))
}

// Delay is the wait after attempt consecutive failures. Zero or fewer failures
// is not a backoff — the ordinary Interval governs — and returning First there
// would make the first successful pass wait as though it had failed.
func (b Backoff) Delay(attempt int) time.Duration {
	if attempt <= 0 || b.First <= 0 {
		return 0
	}
	delay := b.First
	factor := time.Duration(b.Factor)
	// 🔴 attempt IS THE PRIVATE HALF'S COUNT, SO IT IS UNTRUSTED, like
	// every other value that crosses that boundary. So the loop stops the moment
	// another step would reach the ceiling: a runaway or corrupt counter costs a
	// handful of iterations rather than 2^n of them, and — the part that
	// actually matters — the multiplication can never wrap int64 into a NEGATIVE
	// duration. A negative delay would re-arm a failing registration instantly
	// instead of slowing it down, turning the one mechanism that protects a
	// customer's zone during an outage into the thing hammering it.
	for i := 1; i < attempt && factor > 1; i++ {
		if b.Max > 0 && delay >= b.Max/factor {
			return b.Max
		}
		if delay > maxDuration/factor {
			return maxDuration
		}
		delay *= factor
	}
	if b.Max > 0 && delay > b.Max {
		return b.Max
	}
	return delay
}
