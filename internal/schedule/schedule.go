// Package schedule declares the clock the advance loop runs on.
//
// 🔴 IT IS A DECLARATION, NOT A CONTROL. Declared here: the gap between two
// passes over one registration, the spread that stops a fleet advancing in the
// same second, the floor, the backoff curve and its ceiling, the pass ceiling,
// and that a pass finding nothing missing writes nothing. Done elsewhere: which
// registrations exist, which one is asked about next, and whether it is asked at
// all. That split is structural: deciding a registration is due needs the list of
// them, the list is rows, and this service owns no rows (CLAUDE.md, "No database,
// ever"; DESIGN §7). api-platform holds both the list and the clock, and Advance,
// Complete and BindAppToOrgAppDomain publish as fast as they are invoked.
//
// 🔴 THE FLOOR IS THEREFORE DECLARED HERE AND ENFORCED NOWHERE — a limit, not
// unfinished work. Refusing an early pass means knowing when the last one ran:
// DESIGN §5 lists every field a caller may send and none is a time, neither
// sealed envelope carries one, and sealing one would not help, because the private
// half can hand back an older envelope and rolling a last-pass time backwards asks
// for MORE frequency rather than less. DESIGN §8 makes the case for declaring it
// anyway, and names the part that stays unfalsifiable: a pass that writes nothing
// leaves no trace in the customer's zone, so the poll rate is checkable only where
// their provider logs API access as well as changes.
//
// 🔴 DO NOT READ THIS AS §8's STOP CONTROL. "Every write stops within one tick"
// is kept by the pass, not by the clock: intent.Service.pass re-reads the
// ownership proof and returns before a credential is opened when it resolves
// ABSENT. A slower loop makes fewer writes, not later ones.
//
// Due, Spread and Delay are that declaration in executable form, and any loop
// running this cadence should go through them so the schedule that runs and the
// schedule that is published cannot drift. They have no caller outside the tests
// today. Every function here is pure and takes the times it needs as arguments.
package schedule

import (
	"hash/fnv"
	"time"
)

// maxDuration is the largest time.Duration, used only as an overflow guard in
// Delay — see there for why an overflowing backoff is worse than a long one.
const maxDuration = time.Duration(1<<63 - 1)

// Cadence is the declared clock for the advance loop. Every field is public and
// every value published, because each is a fact a customer is entitled to know
// BEFORE authorizing: together they answer "how often could MirrorStack touch my
// zone, and under what conditions".
type Cadence struct {
	// Interval is the ordinary gap between two passes over one registration, and so
	// the resolution of anything in §8 measured in time: a deleted proof is noticed
	// one interval later, if the loop runs at the cadence declared here. A slower
	// loop notices later — the private half may advance a domain less often than
	// this, or never — which is a limitation in the customer's favour. The
	// direction that would not be is not governed here (package comment).
	Interval time.Duration

	// Jitter is the width of the per-registration offset that keeps a fleet from
	// advancing in the same second; Spread derives it deterministically. Interval
	// + Jitter, not Interval, is the honest reading of "within one tick" — a spread
	// that is never disclosed is a promise quietly widened.
	Jitter time.Duration

	// MinInterval is the floor: the fastest this cadence says a registration may be
	// advanced, whatever a caller asks for, and so the rate a customer can hold us
	// to — a repair recurring faster than this in their own change log is us
	// breaking a published claim, in a record they can point at.
	//
	// It is DECLARED, NOT ENFORCED, and the field most likely to be misread as a
	// guarantee: Due applies it to every caller that asks, and to a Cadence whose
	// Interval was set below it, but nothing in this service makes a caller ask.
	MinInterval time.Duration

	// Backoff is what a failed pass waits before the next one. A customer-facing
	// number rather than an operational one: a failure is frequently the customer's
	// own provider saying "slow down".
	Backoff Backoff

	// MaxPasses is how many consecutive passes may leave a registration still
	// unfinished before the loop should stop advancing it and it becomes something
	// a person looks at. A pass that finds everything present ends the run and
	// resets the count.
	//
	// It is NOT one of the customer's stop buttons: it bounds futile work, not
	// authority. A converged registration keeps being re-checked at this same
	// cadence — §8's "we continuously enforce a desired state until you stop us" —
	// and deleting the proof or revoking the grant remain the only two things that
	// end that, both the customer's alone.
	MaxPasses int

	// Quiet declares that a pass which finds nothing missing writes nothing: no
	// touch, no re-PUT of an identical value, no TTL refresh, no reordering.
	//
	// A field rather than an unwritten assumption because getting it wrong is
	// invisible from our side and loud from the customer's: several providers stamp
	// a record's modified time on an identical write, so a chatty steady state
	// would bury the one write that mattered under a few hundred no-ops a day and
	// make "when did this last actually change?" unanswerable in their dashboard.
	Quiet bool
}

// Backoff is the wait a failed pass earns, growing with consecutive failures.
type Backoff struct {
	// First is the wait after a single failure.
	First time.Duration

	// Factor multiplies the wait for each additional consecutive failure. A factor
	// below 2 does not grow at all, and Delay treats it as a flat wait rather than
	// looping forever multiplying by one.
	Factor int

	// Max is the ceiling. Without one an exponential reaches days, and a
	// registration that would have healed on its own sits dark because nobody
	// asked again.
	Max time.Duration
}

// The declared clock, as constants, so that changing one is a diff someone
// outside the company can read. Each carries the argument for its size — what it
// costs the customer if it is too small, and if it is too large — because a
// number without its argument is one the next person changes for the wrong
// reason.
const (
	// interval — 5 minutes, one DNS cache lifetime. The ownership proof is resolved
	// in PUBLIC DNS where 300s is the most common TTL, so polling faster mostly
	// re-reads one resolver cache entry while spending the customer's rate limit;
	// polling slower makes §8's "within one tick" a wait felt twice, once after
	// deleting the proof and once on "waiting for your record".
	interval = 5 * time.Minute

	// jitter — 60 seconds of spread, so a fleet advancing on one boundary does
	// not arrive at one provider's API as a burst.
	jitter = 60 * time.Second

	// minInterval — 60 seconds. The number that makes "your zone was touched nine
	// times a minute" a breach of something written down rather than an argument
	// about what is reasonable. Well below interval on purpose: a person clicking
	// retry just after publishing their proof is a legitimate "check now".
	minInterval = 60 * time.Second

	// backoffFirst — equal to minInterval deliberately: the first retry is the
	// fastest the floor permits and no faster. Failures are usually transient (a
	// 5xx, a throttle, a half-propagated zone), and a full interval spent finding
	// that out makes a connect feel broken rather than slow.
	backoffFirst = minInterval

	// backoffFactor — doubling: 1m, 2m, 4m, 8m, 16m, 32m, then the ceiling.
	backoffFactor = 2

	// backoffMax — 1 hour: 24 attempts a day rather than 288. Smaller turns a
	// provider outage into a steady drum on the customer's zone; larger leaves a
	// domain that would have healed by itself dark until somebody notices. It sits
	// inside a closed lane's 24-hour grant, so a registration never spends its
	// whole credential in one wait.
	backoffMax = time.Hour

	// maxPasses — 288, exactly 24 hours of five-minute passes. It bounds the STUCK
	// registration: proof published, grant live, and something outside both — a
	// certificate wedged in validation, a name pointed at another provider
	// mid-flight — means the desired state is never reached, and trying forever
	// costs the customer reads and rate limit with no path to an outcome. Tied to
	// the 24-hour grant on lanes 1 and 3 so the passes run out about when the
	// credential does; on lane 2, whose grant is standing, this is the ONLY
	// declared end to a futile run. It counts passes, not hours — a backing-off
	// registration spans far longer in wall-clock time, deliberately, because
	// passes touch a zone and hours do not.
	maxPasses = 288

	// quiet — true, and no code path here sets it false. See Cadence.Quiet.
	quiet = true
)

// Declared is the cadence this build publishes.
//
// A constant in this file rather than an environment variable, a flag or a
// parameter: configuration would let someone see the shape of the clock and none
// of its numbers, which is the situation §8 exists to end. Changing one is a
// customer-visible change to how often we may touch a zone, so it should be a
// reviewable diff in a public repository.
//
// A diff is only half of it: knowing WHICH revision is deployed needs health() to
// name a commit. If this build's health response carries no revision, these
// numbers are checkable in the source and not in the deployment.
//
// It returns the whole struct rather than the fields one by one, so a caller
// cannot take half a cadence: an interval without its floor is not a promise.
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
// 🔴 THE REQUIRED GAP IS THE LARGER OF Interval AND MinInterval. A Cadence
// whose interval was set below the floor — by a bug, by a test, by some future
// per-lane variation — cannot beat the floor here, because the comparison is made
// at the decision rather than trusted to whoever assembled the struct. That is
// the whole of what this function guarantees: the floor binds every caller that
// ASKS, and nothing in this service makes one ask.
//
// Three edges fall out of the arithmetic, all failing safe. A registration with
// no pass yet carries the zero time and is due at once — no special case to get
// wrong. A last in the FUTURE (clock skew) is not due, so skew may delay a pass
// and never accelerate one. A zero-value Cadence has a non-positive gap and is
// never due, since the opposite default would make a forgotten field the most
// permissive schedule in the file.
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
// already holds — the anchor and the lane are the obvious one — and it must not
// change between passes: a key that changes re-rolls the phase and un-spreads the
// fleet it was there to spread.
//
// It is DERIVED rather than random so a registration keeps its phase across
// restarts, redeploys and any number of processes — the events most likely to
// re-align a fleet, and the ones a per-pass random offset does nothing about —
// and so a reader can recompute it instead of taking "we call rand" on trust.
//
// 🔴 SPREAD ONLY EVER DELAYS. The result is in [0, Jitter), it is ADDED to a
// pass time, and Due deliberately does not consult it. Jitter widens the tick a
// customer is promised and never narrows it.
//
// FNV need not be a security primitive here: the modulo bias across a 64-bit hash
// is orders of magnitude below anything observable in a schedule, and an adversary
// who can choose a key can choose their own phase but gains nothing, because the
// floor and the ceiling bound every registration identically.
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
	// 🔴 attempt IS THE PRIVATE HALF'S COUNT, SO IT IS UNTRUSTED, like every
	// other value crossing that boundary. The loop therefore stops the moment
	// another step would reach the ceiling: a runaway or corrupt counter costs a
	// handful of iterations rather than 2^n, and the multiplication can never wrap
	// int64 into a NEGATIVE duration. A negative delay would re-arm a failing
	// registration instantly, turning the one mechanism that protects a customer's
	// zone during an outage into the thing hammering it.
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
