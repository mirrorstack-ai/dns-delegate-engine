package observe

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// This file answers one operational question the rest of the package cannot:
// are the vantage points this deployment was CONFIGURED with reachable from
// where it runs? Nothing here participates in a lookup, and nothing in a lookup
// reads anything here.

// ─── naming a vantage point ─────────────────────────────────────────────────

// Named is the optional interface by which a Resolver says how it is addressed.
// Only Probe reads it: no lookup depends on a vantage point's name.
type Named interface {
	Vantage() string
}

// Vantaged is the optional interface by which a composite Resolver lists the
// vantage points it is made of, so each can be measured separately.
type Vantaged interface {
	Vantages() []Resolver
}

// Vantage implements Named.
func (n NetResolver) Vantage() string {
	if n.Server == "" {
		return "resolv.conf"
	}
	return n.Server
}

// Vantage implements Named. There is no address to report: a zone's own
// nameservers are chosen per name, so which server answers is decided inside
// each lookup.
func (a Authoritative) Vantage() string { return "authoritative" }

// Vantages implements Vantaged.
func (q Quorum) Vantages() []Resolver { return q.Resolvers }

// vantagesOf lists what r is made of, ONE level deep: a member that is itself
// composite is measured as the unit its own threshold makes it.
func vantagesOf(r Resolver) []Resolver {
	if v, ok := r.(Vantaged); ok {
		return v.Vantages()
	}
	return []Resolver{r}
}

// vantageName is how one vantage point is reported. A Resolver that does not
// name itself is reported by type, which is still something to grep for.
func vantageName(r Resolver) string {
	if n, ok := r.(Named); ok {
		return n.Vantage()
	}
	return fmt.Sprintf("%T", r)
}

// ─── the reading ────────────────────────────────────────────────────────────

// Reachability is one vantage point's answer to the only question a probe asks:
// can this deployment reach you at all?
type Reachability struct {
	// Vantage is how the vantage point is addressed — a nameserver address, or
	// the container's own resolver. It is the string an operator has to act on.
	Vantage string

	// Reachable is true only for a lookup that COMPLETED and found the name. The
	// probe name must always resolve, so a vantage point answering "no such
	// name" is a vantage point that cannot read a customer's proof either.
	Reachable bool

	// Explain is why it did not answer; empty when Reachable.
	Explain string
}

// Reach is one sweep: every configured vantage point, beside the threshold the
// deployment declares through intent.Capabilities.
type Reach struct {
	Vantages  []Reachability
	Threshold int

	// CheckedAt is when the sweep ran. The zero value means UNMEASURED — no
	// probe is wired — which is not the same as nothing being reachable.
	CheckedAt time.Time
}

// Reachable counts the vantage points that answered.
func (r Reach) Reachable() int {
	n := 0
	for _, v := range r.Vantages {
		if v.Reachable {
			n++
		}
	}
	return n
}

// Degraded reports a deployment that cannot use the resolvers it was configured
// with: too few vantage points answer to ever meet the threshold, so every proof
// reads StateUnknown and every authorization is refused.
//
// 🔴 IT IS A REPORT OF A BROKEN DEPLOYMENT, NOT A SMALLER QUORUM. The threshold
// stands; see Probe.
func (r Reach) Degraded() bool {
	return !r.CheckedAt.IsZero() && r.Reachable() < r.Threshold
}

// ─── the probe ──────────────────────────────────────────────────────────────

// probeTTL is how long one sweep is reused. Long enough that a per-request
// caller costs nothing, short enough that an operator who fixes egress sees the
// answer change without a redeploy.
const probeTTL = 5 * time.Minute

// probeTimeout bounds a WHOLE sweep rather than one lookup: a health check has
// to answer even when every vantage point is a black hole.
const probeTimeout = 2 * time.Second

// Probe measures whether the configured vantage points can be reached, by
// resolving a name that must always resolve at each of them.
//
// It exists because the resolver policy is the one deployment setting nothing
// else checks. A vantage point this service has no egress to answers no lookup,
// every proof then reads StateUnknown, and every Authorize is refused — a fault
// whose only symptom is a customer who cannot connect their domain. So the
// running service measures its own egress and publishes what it found, rather
// than an operator having to remember to measure it by hand.
//
// 🔴 IT REPORTS. IT NEVER GATES.
//
// Nothing here drops an unreachable vantage point from a Quorum or lowers a
// threshold to fit what is left. Dropping one would turn a network fault into a
// quiet reduction of the rule the customer read before authorizing: "2 of 3"
// would silently become 1. A reachable set too small for the threshold is a
// broken deployment, and Reach.Degraded is how health() says so.
//
// It is never on a publish path: no lookup in this package reads a Probe, and
// the only callers are intent.Capabilities and the health check.
type Probe struct {
	// Resolver is the wired resolver, read for its vantage points and for the
	// threshold they have to meet. Nil leaves every reading unmeasured.
	Resolver Resolver

	// Name is resolved at every vantage point: a name this deployment ALREADY
	// depends on and that must always resolve — the org routing target, in the
	// binary. Empty leaves every reading unmeasured rather than probing a name
	// this package invented.
	Name string

	// TTL is how long one sweep is reused; zero means probeTTL.
	TTL time.Duration

	// Now is the clock; nil means time.Now.
	Now func() time.Time

	// mu is held across a sweep, so concurrent callers wait for the one in
	// flight instead of each starting their own.
	mu     sync.Mutex
	cached Reach
}

// Reach returns the current reading, re-measuring when the cached one has aged
// past the TTL. Bounded: one lookup per vantage point, in parallel, the whole
// sweep inside probeTimeout.
func (p *Probe) Reach(ctx context.Context) Reach {
	if p == nil || p.Resolver == nil || p.Name == "" {
		return Reach{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if !p.cached.CheckedAt.IsZero() && now.Sub(p.cached.CheckedAt) < p.ttl() {
		return p.cached
	}
	p.cached = p.sweep(ctx, now)
	return p.cached
}

func (p *Probe) sweep(ctx context.Context, now time.Time) Reach {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	points := vantagesOf(p.Resolver)
	out := Reach{
		Vantages:  make([]Reachability, len(points)),
		Threshold: PolicyOf(p.Resolver).Threshold,
		CheckedAt: now,
	}
	var wg sync.WaitGroup
	for i, r := range points {
		wg.Add(1)
		go func(i int, r Resolver) {
			defer wg.Done()
			out.Vantages[i] = probeOne(ctx, r, p.Name)
		}(i, r)
	}
	wg.Wait()

	// Logged on every re-measurement, not once: a deployment refusing every
	// authorization has to keep saying why for as long as it is doing it.
	if out.Degraded() {
		slog.Error("observe: too few DNS vantage points are reachable to meet this deployment's threshold",
			"reachable", out.Reachable(), "threshold", out.Threshold, "probe", p.Name)
	}
	return out
}

// probeOne resolves the probe name at ONE vantage point. LookupCNAME is used
// because the Resolver contract makes it answerable for any name that resolves:
// a name holding no CNAME comes back unchanged rather than as an error.
func probeOne(ctx context.Context, r Resolver, name string) Reachability {
	out := Reachability{Vantage: vantageName(r)}
	if _, err := r.LookupCNAME(ctx, name); err != nil {
		out.Explain = fmt.Sprintf("no answer for %q: %v", name, err)
		return out
	}
	out.Reachable = true
	return out
}

func (p *Probe) ttl() time.Duration {
	if p.TTL <= 0 {
		return probeTTL
	}
	return p.TTL
}

func (p *Probe) now() time.Time {
	if p.Now == nil {
		return time.Now()
	}
	return p.Now()
}
