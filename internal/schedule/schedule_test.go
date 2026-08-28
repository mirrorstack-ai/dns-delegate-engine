package schedule

import (
	"testing"
	"time"
)

// base is an arbitrary fixed instant. Nothing in this package reads the wall
// clock, and nothing in these tests does either: a scheduler test that consults
// time.Now() is a test that behaves differently at 23:59, and one that sleeps is
// a test that pays the cadence it is measuring.
var base = time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

// The boundary is the whole of Due. One nanosecond either side of it is the
// difference between the cadence this repository declares and one silently a
// tick slower — a strict > would defer a scheduler that fires exactly on the
// dot by a full interval, every interval, and the customer would be told five
// minutes while being given ten.
func TestDueBoundaryIsInclusive(t *testing.T) {
	c := Declared()
	gap := c.Interval

	cases := []struct {
		name string
		last time.Time
		now  time.Time
		want bool
	}{
		{"no time at all has passed", base, base, false},
		{"one nanosecond before the gap elapses", base, base.Add(gap - time.Nanosecond), false},
		{"exactly at the gap", base, base.Add(gap), true},
		{"well past the gap", base, base.Add(2 * gap), true},

		// A registration that has never been advanced carries the zero time.
		// It must be due at once — a domain that just completed is the case
		// most obviously waiting on a first pass.
		{"never advanced", time.Time{}, base, true},

		// Clock skew may delay a pass; it must never accelerate one. A row
		// stamped by a machine running ahead is the realistic source of this,
		// and treating it as due would be the one direction that costs the
		// customer writes they did not expect.
		{"last pass stamped in the future", base.Add(time.Hour), base, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.Due(tc.last, tc.now); got != tc.want {
				t.Fatalf("Due(last=%v, now=%v) = %v, want %v (gap %v)",
					tc.last, tc.now, got, tc.want, gap)
			}
		})
	}
}

// A zero Cadence is the empty declaration, and the empty declaration must answer
// "no". If a missing field made the schedule maximally permissive, the most
// dangerous cadence in this file would be the one nobody wrote down.
func TestZeroCadenceIsNeverDue(t *testing.T) {
	var c Cadence
	for _, now := range []time.Time{base, base.Add(time.Hour), base.AddDate(1, 0, 0)} {
		if c.Due(base, now) {
			t.Fatalf("a zero Cadence reported due at %v; an undeclared clock must refuse, not permit", now)
		}
	}
	if c.Due(time.Time{}, base) {
		t.Fatal("a zero Cadence reported a never-advanced registration due; both unknowns must fail closed")
	}
}

// 🔴 THE FLOOR MUST BEAT THE INTERVAL, not merely sit beside it in a struct.
//
// This is the shape that matters: a Cadence whose Interval was set below
// MinInterval — by a bug, a test double, or some future per-lane variation — is
// exactly the input a caller would use to advance faster than declared. Due
// takes the LARGER of the two, so the floor holds without anyone remembering to
// check it at the call site.
func TestMinIntervalIsAHardFloor(t *testing.T) {
	c := Cadence{Interval: time.Second, MinInterval: time.Minute}

	if c.Due(base, base.Add(59*time.Second)) {
		t.Fatal("Due honoured a one-second Interval under a one-minute MinInterval; the floor is not enforced")
	}
	if !c.Due(base, base.Add(time.Minute)) {
		t.Fatal("Due refused at exactly MinInterval; the floor must permit at its own boundary, not one tick later")
	}

	// The declared cadence must not be able to lose the floor either: with
	// Interval above MinInterval, Interval is what governs.
	d := Declared()
	if d.Due(base, base.Add(d.MinInterval)) {
		t.Fatalf("Declared() advanced at MinInterval (%v); the ordinary gap is Interval (%v)", d.MinInterval, d.Interval)
	}
}

// The declared backoff sequence, pinned. Written out rather than computed so a
// reader can see the actual waits a failing registration imposes on a customer's
// zone: 1m, 2m, 4m, 8m, 16m, 32m, then an hour forever.
func TestDeclaredBackoffSteps(t *testing.T) {
	b := Declared().Backoff

	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{-1, 0},
		{0, 0},
		{1, time.Minute},
		{2, 2 * time.Minute},
		{3, 4 * time.Minute},
		{4, 8 * time.Minute},
		{5, 16 * time.Minute},
		{6, 32 * time.Minute},
		{7, time.Hour}, // doubling 32m would overshoot the ceiling, so the ceiling is taken
		{8, time.Hour},
		{99, time.Hour},
	}

	for _, tc := range cases {
		if got := b.Delay(tc.attempt); got != tc.want {
			t.Fatalf("Delay(%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}

	// Zero failures is not a backoff: the ordinary Interval governs, and a
	// first pass must not wait as though it had already failed.
	if b.Delay(0) != 0 {
		t.Fatal("Delay(0) must be zero; a pass that has not failed is not backing off")
	}
}

// Monotonicity and the cap are the two properties a customer can rely on: the
// wait after a failure never shrinks, so a persistently failing registration
// applies strictly decreasing pressure to their zone, and it never grows past
// the declared ceiling, so a domain that would have healed is not abandoned to a
// wait measured in days.
func TestBackoffIsMonotoneAndCapped(t *testing.T) {
	b := Declared().Backoff

	var previous time.Duration
	reachedCap := false
	for attempt := 1; attempt <= 64; attempt++ {
		got := b.Delay(attempt)
		if got <= 0 {
			t.Fatalf("Delay(%d) = %v; a failed pass must wait, and a non-positive wait re-arms it immediately", attempt, got)
		}
		if got < previous {
			t.Fatalf("Delay(%d) = %v is shorter than Delay(%d) = %v; backoff must never speed up under repeated failure",
				attempt, got, attempt-1, previous)
		}
		if got > b.Max {
			t.Fatalf("Delay(%d) = %v exceeds the declared ceiling %v", attempt, got, b.Max)
		}
		if got == b.Max {
			reachedCap = true
		}
		previous = got
	}
	if !reachedCap {
		t.Fatalf("the backoff never reached its ceiling %v within 64 failures; the declared cap is decorative", b.Max)
	}
}

// 🔴 attempt CROSSES A REPOSITORY BOUNDARY, so it is untrusted like every other
// value from the private half's rows. The failure this guards is not slowness:
// an unguarded doubling wraps int64 and returns a NEGATIVE wait, which would
// turn the mechanism that protects a customer's zone during a provider outage
// into the thing hammering it.
func TestBackoffRefusesRunawayAttemptCounts(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	b := Declared().Backoff

	for _, attempt := range []int{1000, 1 << 20, maxInt - 1, maxInt} {
		if got := b.Delay(attempt); got != b.Max {
			t.Fatalf("Delay(%d) = %v, want the ceiling %v", attempt, got, b.Max)
		}
	}

	// Without a declared ceiling the wait may grow without bound, but it must
	// still never wrap into a negative — an undeclared cap is a misconfiguration
	// and it must degrade toward waiting longer, never toward waiting less.
	uncapped := Backoff{First: time.Hour, Factor: 2}
	if got := uncapped.Delay(maxInt); got <= 0 {
		t.Fatalf("an uncapped backoff returned %v after a runaway count; a non-positive wait is an instant retry", got)
	}

	// A factor that does not grow is a degenerate declaration, not a hang: it
	// must return a flat wait rather than loop attempt times multiplying by one.
	flat := Backoff{First: time.Minute, Factor: 1, Max: time.Hour}
	if got := flat.Delay(maxInt); got != time.Minute {
		t.Fatalf("a factor of 1 returned %v, want a flat %v", got, time.Minute)
	}
}

// The declared cadence has to satisfy the invariants the rest of this package's
// prose assumes. A number that drifts out from under its own justification is
// how a documented clock stops matching the running one.
func TestDeclaredSatisfiesItsOwnInvariants(t *testing.T) {
	c := Declared()

	if c.MinInterval > c.Interval {
		t.Fatalf("MinInterval (%v) is above Interval (%v): the ordinary pass would be the one the floor refuses",
			c.MinInterval, c.Interval)
	}
	if c.Jitter >= c.Interval {
		t.Fatalf("Jitter (%v) is not smaller than Interval (%v): the spread would exceed the gap it is spreading",
			c.Jitter, c.Interval)
	}
	if c.MaxPasses <= 0 {
		t.Fatalf("MaxPasses is %d: a registration would be advanced zero times or forever", c.MaxPasses)
	}

	// The first retry is deliberately the fastest the floor permits and no
	// faster. If this ever slipped below MinInterval, Due would silently refuse
	// the retry the backoff had just scheduled.
	if c.Backoff.First < c.MinInterval {
		t.Fatalf("Backoff.First (%v) is below MinInterval (%v): the first retry would be scheduled and then refused",
			c.Backoff.First, c.MinInterval)
	}
	if c.Backoff.Max <= c.Backoff.First || c.Backoff.Factor < 2 {
		t.Fatalf("backoff %+v does not grow toward a higher ceiling", c.Backoff)
	}

	// The 24-hour argument for MaxPasses only holds if the two numbers still
	// agree. If Interval changes, this is the test that says MaxPasses now
	// means something different from what its comment claims.
	if elapsed := time.Duration(c.MaxPasses) * c.Interval; elapsed != 24*time.Hour {
		t.Fatalf("MaxPasses (%d) x Interval (%v) = %v, want 24h — the ceiling is documented as a day of passes and is tied to a 24-hour grant",
			c.MaxPasses, c.Interval, elapsed)
	}

	// §8 promises a pass that finds nothing missing writes nothing. It is a
	// declared field precisely so that turning it off is a visible change.
	if !c.Quiet {
		t.Fatal("Quiet is false: an unchanged pass would write, and a customer auditing their zone could not tell enforcement from repair")
	}

	// The tick a customer should actually plan around is Interval + Jitter, and
	// both halves must be positive for that number to mean anything.
	if c.Interval <= 0 || c.Jitter <= 0 {
		t.Fatalf("Interval (%v) and Jitter (%v) must both be positive; the promised tick is their sum", c.Interval, c.Jitter)
	}
}

// Spread has to be bounded, non-negative, stable, and actually spread. The
// non-negative half is the load-bearing one: an offset that could be negative
// would be a route around MinInterval, which is the only bound in this package
// a caller cannot otherwise weaken.
func TestSpreadIsBoundedStableAndSpreading(t *testing.T) {
	c := Declared()

	// Anchors stand in for registration keys. example.com / .net / .org only —
	// never a real customer domain, in code, comment or test.
	keys := []string{
		"platform|example.com",
		"app_domain|example.net",
		"app|example.org",
		"app|shop.example.org",
		"platform|example.net",
	}

	seen := make(map[time.Duration]struct{}, len(keys))
	for _, key := range keys {
		got := c.Spread(key)
		if got < 0 {
			t.Fatalf("Spread(%q) = %v; a negative offset would pull a pass EARLIER and defeat MinInterval", key, got)
		}
		if got >= c.Jitter {
			t.Fatalf("Spread(%q) = %v, which is outside [0, Jitter=%v); the promised tick is Interval + Jitter", key, got, c.Jitter)
		}
		if again := c.Spread(key); again != got {
			t.Fatalf("Spread(%q) returned %v then %v; an unstable phase re-rolls on every pass and spreads nothing", key, got, again)
		}
		seen[got] = struct{}{}
	}
	if len(seen) < 2 {
		t.Fatalf("%d keys produced %d distinct offsets; a fleet that lands in one slot is the thundering herd this exists to prevent",
			len(keys), len(seen))
	}

	// A cadence that declares no jitter gets no offset, rather than an offset
	// derived from a zero modulus.
	none := Cadence{Interval: time.Minute}
	if got := none.Spread("platform|example.com"); got != 0 {
		t.Fatalf("Spread with Jitter=0 returned %v, want 0", got)
	}
}
