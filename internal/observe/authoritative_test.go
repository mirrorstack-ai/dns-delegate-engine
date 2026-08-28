package observe

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// fakeDelegation is a zone's NS set as a table. NetDelegation itself is the one
// implementation no test can drive — finding a real zone's nameservers needs a
// network — so it is held to the interface by a compile-time assertion instead.
type fakeDelegation struct {
	servers []string
	err     error
}

func (f fakeDelegation) Nameservers(context.Context, string) ([]string, error) {
	return f.servers, f.err
}

// dialled records which servers Authoritative actually asked, in order.
type dialled struct {
	mu   sync.Mutex
	seen []string
	at   map[string]Resolver
}

func (d *dialled) At(server string) Resolver {
	d.mu.Lock()
	d.seen = append(d.seen, server)
	d.mu.Unlock()
	return d.at[server]
}

func (d *dialled) order() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.seen...)
}

func authoritativeOver(servers []string, at map[string]Resolver) (Authoritative, *dialled) {
	d := &dialled{at: at}
	return Authoritative{Delegation: fakeDelegation{servers: servers}, At: d.At}, d
}

func TestAuthoritativeAsksTheZonesOwnNameservers(t *testing.T) {
	a, d := authoritativeOver(
		[]string{"ns1.example.net:53", "ns2.example.net:53"},
		map[string]Resolver{
			"ns1.example.net:53": serving(accepted[0]),
			"ns2.example.net:53": missing(),
		})
	ok, obs, err := read(t, a)
	if err != nil || !ok || obs.State != StatePresent {
		t.Fatalf("state %q ok %v err %v; want the first nameserver's answer", obs.State, ok, err)
	}
	if got := d.order(); len(got) != 1 || got[0] != "ns1.example.net:53" {
		t.Fatalf("dialled %q; the nameservers of one zone are replicas, so the first answer is taken", got)
	}
}

func TestAuthoritativeMovesPastANameserverThatDoesNotAnswer(t *testing.T) {
	a, d := authoritativeOver(
		[]string{"ns1.example.net:53", "ns2.example.net:53"},
		map[string]Resolver{
			"ns1.example.net:53": failing(servfail(proofName)),
			"ns2.example.net:53": serving(accepted[0]),
		})
	if ok, obs, err := read(t, a); !ok || obs.State != StatePresent {
		t.Fatalf("state %q ok %v err %v; one dead nameserver must not lose the answer", obs.State, ok, err)
	}
	if got := d.order(); len(got) != 2 {
		t.Fatalf("dialled %q; want both", got)
	}
}

// 🔴 A nameserver we could not reach is not a nameserver saying no.
func TestNoReachableNameserverIsNeverAbsence(t *testing.T) {
	a, _ := authoritativeOver(
		[]string{"ns1.example.net:53", "ns2.example.net:53"},
		map[string]Resolver{
			"ns1.example.net:53": failing(servfail(proofName)),
			"ns2.example.net:53": failing(timedOut(proofName)),
		})
	ok, obs, err := read(t, a)
	if ok || obs.State != StateUnknown {
		t.Fatalf("state %q ok %v; want unknown", obs.State, ok)
	}
	if isNotFound(err) {
		t.Fatal("two unreachable nameservers were reported as a withdrawn proof")
	}
}

// The customer's stop control, read from the zone itself.
func TestAnAuthoritativeNXDOMAINIsAbsence(t *testing.T) {
	a, _ := authoritativeOver(
		[]string{"ns1.example.net:53"},
		map[string]Resolver{"ns1.example.net:53": missing()})
	ok, obs, err := read(t, a)
	if ok || obs.State != StateAbsent || err != nil {
		t.Fatalf("state %q ok %v err %v; want absent", obs.State, ok, err)
	}
}

func TestADelegationThatCannotBeFoundIsNotAbsence(t *testing.T) {
	for _, tc := range []struct {
		name string
		a    Authoritative
	}{
		{"the NS lookup failed", Authoritative{
			Delegation: fakeDelegation{err: errors.New("SERVFAIL")},
			At:         func(string) Resolver { return missing() },
		}},
		{"no zone publishes NS records", Authoritative{
			Delegation: fakeDelegation{},
			At:         func(string) Resolver { return missing() },
		}},
		{"nothing is wired", Authoritative{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, obs, err := read(t, tc.a)
			if ok || obs.State != StateUnknown {
				t.Fatalf("state %q ok %v; want unknown", obs.State, ok)
			}
			if isNotFound(err) {
				t.Fatal("a delegation we could not read was reported as absence")
			}
		})
	}
}

func TestAHostileNSSetIsCapped(t *testing.T) {
	servers := make([]string, 0, 40)
	at := make(map[string]Resolver, 40)
	for i := range 40 {
		server := fmt.Sprintf("ns%d.example.net:53", i)
		servers = append(servers, server)
		at[server] = failing(servfail(proofName))
	}
	a, d := authoritativeOver(servers, at)
	if _, _, err := read(t, a); err == nil {
		t.Fatal("want an error from a delegation where nothing answers")
	}
	if got := len(d.order()); got != maxNameservers {
		t.Fatalf("dialled %d nameservers; want at most %d", got, maxNameservers)
	}
}

func TestAuthoritativeDeclaresItselfAuthoritative(t *testing.T) {
	want := Policy{Vantages: 1, Threshold: 1, Authoritative: true}
	if got := PolicyOf(Authoritative{}); got != want {
		t.Fatalf("policy %+v; want %+v", got, want)
	}
}

// Composition is the point: an authoritative vantage point beside a recursive
// one, neither trusted alone.
func TestAnAuthoritativeVantagePointComposesIntoAQuorum(t *testing.T) {
	a, _ := authoritativeOver(
		[]string{"ns1.example.net:53"},
		map[string]Resolver{"ns1.example.net:53": serving(accepted[0])})
	q := Quorum{Resolvers: []Resolver{a, serving(accepted[0]), missing()}, Threshold: 2}
	ok, obs, err := read(t, q)
	if !ok || obs.State != StatePresent || err != nil {
		t.Fatalf("state %q ok %v err %v; want present", obs.State, ok, err)
	}
	if obs.Agreement != (Agreement{Asked: 3, Agreed: 2, Threshold: 2}) {
		t.Fatalf("agreement %+v; want 2 of 3", obs.Agreement)
	}
}
