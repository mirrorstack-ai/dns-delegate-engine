package observe

import (
	"reflect"
	"testing"
)

// clearResolverEnv keeps one case from inheriting another's configuration.
func clearResolverEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{resolversEnv, authoritativeEnv, quorumEnv} {
		t.Setenv(key, "")
	}
}

// 🔴 The documented default: unchanged behaviour, and it says so through Policy
// rather than implying more.
func TestTheDefaultIsOneRecursiveVantagePoint(t *testing.T) {
	clearResolverEnv(t)
	r := ResolverFromEnv()
	if _, ok := r.(NetResolver); !ok {
		t.Fatalf("resolver %T; want the container's own", r)
	}
	if got := PolicyOf(r); got != (Policy{Vantages: 1, Threshold: 1}) {
		t.Fatalf("policy %+v; want one vantage point", got)
	}
}

func TestConfiguredResolversBecomeAQuorumAtAMajority(t *testing.T) {
	clearResolverEnv(t)
	t.Setenv(resolversEnv, "192.0.2.1, 192.0.2.2:5353 ,192.0.2.3")
	q, ok := ResolverFromEnv().(Quorum)
	if !ok {
		t.Fatal("three configured resolvers did not become a quorum")
	}
	want := []Resolver{
		NetResolver{Server: "192.0.2.1:53"},
		NetResolver{Server: "192.0.2.2:5353"},
		NetResolver{Server: "192.0.2.3:53"},
	}
	if !reflect.DeepEqual(q.Resolvers, want) {
		t.Fatalf("vantage points %+v; want %+v — a bare address defaults to port 53", q.Resolvers, want)
	}
	if q.Threshold != 2 {
		t.Fatalf("threshold %d; want a majority of 3", q.Threshold)
	}
}

func TestTheAuthoritativeVantagePointIsOptIn(t *testing.T) {
	clearResolverEnv(t)
	t.Setenv(resolversEnv, "192.0.2.1")
	t.Setenv(authoritativeEnv, "true")
	got := PolicyOf(ResolverFromEnv())
	if got != (Policy{Vantages: 2, Threshold: 2, Authoritative: true}) {
		t.Fatalf("policy %+v; want two vantage points, one authoritative", got)
	}
}

// A single vantage point is not dressed up as a quorum.
func TestOneConfiguredResolverIsNotAQuorum(t *testing.T) {
	clearResolverEnv(t)
	t.Setenv(resolversEnv, "192.0.2.1")
	if got := PolicyOf(ResolverFromEnv()); got != (Policy{Vantages: 1, Threshold: 1}) {
		t.Fatalf("policy %+v; want one vantage point believed on its own", got)
	}
}

// 🔴 An operator asked for something this code could not honour, so it verifies
// LESS than they asked, never more.
func TestAnUnusableQuorumBecomesUnanimity(t *testing.T) {
	for _, value := range []string{"0", "-1", "4", "most", "2.5"} {
		t.Run(value, func(t *testing.T) {
			clearResolverEnv(t)
			t.Setenv(resolversEnv, "192.0.2.1,192.0.2.2,192.0.2.3")
			t.Setenv(quorumEnv, value)
			if got := PolicyOf(ResolverFromEnv()).Threshold; got != 3 {
				t.Fatalf("threshold %d; want every vantage point", got)
			}
		})
	}
}

func TestAnExplicitQuorumIsHonoured(t *testing.T) {
	clearResolverEnv(t)
	t.Setenv(resolversEnv, "192.0.2.1,192.0.2.2,192.0.2.3")
	t.Setenv(quorumEnv, "3")
	if got := PolicyOf(ResolverFromEnv()).Threshold; got != 3 {
		t.Fatalf("threshold %d; want 3", got)
	}
}

func TestAnUnparseableResolverAddressIsDroppedRatherThanDialled(t *testing.T) {
	clearResolverEnv(t)
	t.Setenv(resolversEnv, "192.0.2.1,   ,192.0.2.2")
	if got := PolicyOf(ResolverFromEnv()).Vantages; got != 2 {
		t.Fatalf("vantages %d; want the two real addresses", got)
	}
}
