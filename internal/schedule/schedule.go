// Package schedule declares the clock the advance loop runs on.
//
// 🔴 THIS PACKAGE SETTLES HOW OFTEN. IT CANNOT SETTLE WHICH.
//
// docs/DESIGN.md §8 makes a promise measured in time: delete the ownership proof
// and every write from this service stops "within one tick", because the proof
// is re-checked on every pass. A promise denominated in ticks is worth exactly
// what the tick is worth, and a tick that lives in a private scheduler's
// configuration is worth nothing to the person relying on it — they would be
// reading a support reply rather than a repository. So the numbers are here, in
// the open, as constants, and two of them are functions a pass has to go
// through rather than sentences a pass can ignore.
//
// Now the part that does not resolve, stated plainly rather than dressed up:
//
//	a stateless service cannot enumerate what is due.
//
// Enumeration needs the list of registrations; the list is rows; and this
// service owns no rows and never will — see CLAUDE.md, "No database, ever", and
// DESIGN.md §7. So the half of "what runs, and when" that walks the list and
// picks the next domain to advance stays in api-platform, where it is not
// public. The division is exact, and a reader should hold both halves of it:
//
//	settled here       the gap between two passes over one registration, the
//	                   spread that stops a fleet advancing in the same second,
//	                   the floor nothing may go below, what a failed pass waits,
//	                   how many passes a stuck registration gets, and whether a
//	                   pass that finds nothing missing writes anything (it does
//	                   not).
//	settled elsewhere  which registrations exist, which one is asked about next,
//	                   and whether anything is asked at all.
//
// What that division buys is a BOUND, not a schedule. The private half may
// advance a domain less often than the cadence below, or never — §7's "a sealed
// envelope can be withheld" is the same limitation seen from the credential
// side, and it is a limitation in the customer's favour. What it cannot do is
// make this service touch a zone more often than MinInterval, because Due
// refuses.
//
// 🔴 A PASS THAT DOES NOT CONSULT Due IS A DEFECT. Same standing rule as
// dnsplan.Contains, and for the same reason: a bound one caller may skip is a
// bound that will be skipped by the caller that mattered.
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
	// Interval is the ordinary gap between two passes over one registration.
	// It is also the resolution of every promise in §8 that is measured in
	// time: a proof the customer deletes is noticed one interval later, at
	// worst, because noticing is what a pass does.
	Interval time.Duration

	// Jitter is the width of the per-registration offset that keeps a fleet
	// from advancing in the same second; Spread derives it deterministically.
	//
	// Interval + Jitter, not Interval, is the honest reading of "within one
	// tick" — a spread that is never disclosed is a promise quietly widened.
	Jitter time.Duration

	// MinInterval is the floor: no caller, ours or otherwise, can cause a
	// registration to be advanced more often than this.
	//
	// 🔴 THIS IS THE ONE VALUE HERE THAT IS A CONTROL RATHER THAN A
	// DECLARATION. Interval, Jitter and MaxPasses describe what the loop
	// intends; a caller that ignores them advances at some other rate and no
	// code in this repository would know. MinInterval is different because Due
	// enforces it at the door, against whatever the caller asks for.
	MinInterval time.Duration

	// Backoff is what a failed pass waits before the next one. Worth reading as
	// a customer-facing number rather than an operational one: a failure is
	// frequently the customer's own provider saying "slow down", and backing
	// off is how we stop being the reason their rate limit is exhausted.
	Backoff Backoff

	// MaxPasses bounds one run of consecutive passes that leave a registration
	// still unfinished. After that it stops being advanced and becomes
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
	// It exists because "how often" has to survive a bug on the other side of a
	// boundary this repository cannot see. If a scheduler over there loops,
	// retries hot, or is deployed twice, the worst it can do to a customer zone
	// is sixty reads an hour instead of sixty a second.
	//
	// It sits well below interval on purpose, so that a legitimate "check now"
	// — a person clicking retry in a console immediately after publishing the
	// proof — still works without a code change here. A floor set at the
	// interval would have punished the one case that is a human waiting.
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
	// to make them does. On lane 2, whose grant is standing, this ceiling is the
	// only thing that ends a futile run at all, which is why it is declared
	// rather than left to whatever the caller felt was reasonable.
	//
	// It counts PASSES, not hours. A registration that is failing and backing
	// off spans far longer in wall-clock time, deliberately: passes are what
	// touch a customer's zone, and hours are not.
	maxPasses = 288

	// quiet — true, and there is no code path in this package that sets it
	// false. See Cadence.Quiet for what it costs to get this wrong.
	quiet = true
)

// Declared is the cadence this build runs.
//
// It is a constant in this file rather than an environment variable, a flag or a
// parameter, and that is the entire point: a value read from configuration is
// not something a reader of this repository can verify. Configuration would let
// someone see the shape of the clock and none of its numbers, which is the
// situation §8 exists to end. Changing any of these is a customer-visible change
// to how often we may touch a zone, so it should be a reviewable diff in a
// public repository — and health() publishes the deployed commit, so which diff
// is running is checkable too.
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
// That max() is the floor doing its job. A Cadence whose interval was set below
// the floor — by a bug, by a test, by some future per-lane variation — still
// cannot beat the floor, because the comparison is made here rather than trusted
// to whoever built the struct. A floor that is only a comment on a constant is
// not a floor.
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
// pass time, and Due deliberately does not consult it. Jitter that could pull a
// pass earlier would be a way around MinInterval, which is the one number in
// this file that nothing may weaken.
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
	// 🔴 attempt ARRIVES FROM THE PRIVATE HALF'S ROW AND IS UNTRUSTED, like
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
