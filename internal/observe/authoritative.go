package observe

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
)

// maxNameservers bounds how many of a zone's nameservers are dialled. A zone
// publishes two to four; a hostile or broken NS set must not become a fan-out at
// addresses somebody else chose.
const maxNameservers = 8

// Delegation names the servers authoritative for a DNS name. It is an interface
// so this package's tests need no network.
type Delegation interface {
	// Nameservers returns dial addresses (host:port) for the nearest zone cut at
	// or above name, in a stable order so two reports are comparable.
	Nameservers(ctx context.Context, name string) ([]string, error)
}

// Authoritative asks a zone's OWN nameservers instead of a recursive resolver,
// which removes the recursive cache from the answer entirely.
//
// 🔴 THE DELEGATION IS STILL LEARNED RECURSIVELY, AND THAT IS THE HONEST LIMIT.
// Nameservers reads NS and address records through an ordinary resolver, so an
// attacker who can forge THOSE can still point us at a server of their own. What
// this removes is the poisoned cache entry for the proof itself; what it does
// not remove is a poisoned delegation. Wire it as one vantage point of a Quorum
// rather than as the whole answer.
//
// It validates no signatures: see Quorum's DNSSEC note.
type Authoritative struct {
	// Delegation finds the zone's nameservers.
	Delegation Delegation

	// At builds a Resolver bound to ONE server address. A field, not a package
	// default, so a test can supply fakes — the same rule intent.Service.Resolver
	// states.
	At func(server string) Resolver
}

// Policy implements Policied.
func (a Authoritative) Policy() Policy {
	return Policy{Vantages: 1, Threshold: 1, Authoritative: true}
}

// LookupCNAME implements Resolver.
func (a Authoritative) LookupCNAME(ctx context.Context, name string) (string, error) {
	values, err := a.ask(ctx, name, func(r Resolver) ([]string, error) {
		value, err := r.LookupCNAME(ctx, name)
		return []string{value}, err
	})
	if err != nil {
		return "", err
	}
	return values[0], nil
}

// LookupTXT implements Resolver.
func (a Authoritative) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return a.ask(ctx, name, func(r Resolver) ([]string, error) {
		return r.LookupTXT(ctx, name)
	})
}

// ask queries the zone's nameservers in order and takes the FIRST that answers.
//
// 🔴 ONLY A SUCCESS OR "NO SUCH NAME" COUNTS AS AN ANSWER. A refused, timed-out
// or unreachable server moves to the next one and is never read as absence, so
// one dead nameserver cannot look like a withdrawn proof.
//
// The nameservers of one zone are replicas of one another, so the first answer
// is taken rather than several being compared: requiring them to agree would
// read ordinary replication lag as a split. Agreement between INDEPENDENT
// vantage points is Quorum's job.
func (a Authoritative) ask(ctx context.Context, name string, lookup func(Resolver) ([]string, error)) ([]string, error) {
	if a.Delegation == nil || a.At == nil {
		return nil, fmt.Errorf("%w: no delegation lookup is wired", ErrObserve)
	}
	servers, err := a.Delegation.Nameservers(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("the authoritative nameservers for %q could not be found: %w", name, err)
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no authoritative nameserver was found for %q", name)
	}
	if len(servers) > maxNameservers {
		servers = servers[:maxNameservers]
	}

	var last error
	for _, server := range servers {
		r := a.At(server)
		if r == nil {
			continue
		}
		values, err := lookup(r)
		if err == nil || isNotFound(err) {
			return values, err
		}
		last = err
	}
	return nil, fmt.Errorf("no authoritative nameserver for %q answered: %w", name, last)
}

// NetDelegation is the production Delegation, over the standard library.
type NetDelegation struct {
	// Via is the resolver the NS set and its addresses are read through; the
	// zero value is the container's own. It is a field because the delegation is
	// the part this design cannot take off the recursive path, so a deployment
	// should be able to choose which resolver it trusts for it.
	Via NetResolver

	// Port is the port the nameservers are dialled on; empty means 53.
	Port string
}

// Nameservers implements Delegation. It walks up from name to the nearest
// ancestor that publishes NS records, then resolves those to addresses.
//
// The walk stops before the last label: a single-label name is a TLD, and this
// service has no business querying the root.
func (d NetDelegation) Nameservers(ctx context.Context, name string) ([]string, error) {
	zone := strings.TrimSuffix(strings.TrimSpace(name), ".")
	if zone == "" {
		return nil, fmt.Errorf("%w: no name to delegate", ErrObserve)
	}
	var last error
	for strings.Count(zone, ".") >= 1 {
		servers, err := d.at(ctx, zone)
		if err == nil && len(servers) > 0 {
			return servers, nil
		}
		if err != nil && !isNotFound(err) {
			last = err
		}
		_, rest, found := strings.Cut(zone, ".")
		if !found {
			break
		}
		zone = rest
	}
	if last != nil {
		return nil, last
	}
	return nil, fmt.Errorf("no zone at or above %q publishes NS records", name)
}

// at reads one candidate zone's NS records and resolves them to dial addresses.
func (d NetDelegation) at(ctx context.Context, zone string) ([]string, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, d.Via.timeout())
	defer cancel()
	nameservers, err := d.Via.resolver().LookupNS(lookupCtx, rooted(zone))
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, len(nameservers))
	seen := make(map[string]bool, len(nameservers))
	var last error
	for _, ns := range nameservers {
		addrs, err := d.addresses(ctx, ns.Host)
		if err != nil {
			last = err
			continue
		}
		for _, addr := range addrs {
			target := net.JoinHostPort(addr, d.port())
			if seen[target] {
				continue
			}
			seen[target] = true
			out = append(out, target)
		}
	}
	if len(out) == 0 && last != nil {
		return nil, last
	}
	// Sorted so the same nameserver is asked first on every pass, which makes a
	// report reproducible.
	sort.Strings(out)
	return out, nil
}

func (d NetDelegation) addresses(ctx context.Context, host string) ([]string, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, d.Via.timeout())
	defer cancel()
	return d.Via.resolver().LookupHost(lookupCtx, rooted(host))
}

func (d NetDelegation) port() string {
	if strings.TrimSpace(d.Port) == "" {
		return "53"
	}
	return strings.TrimSpace(d.Port)
}

// NetResolverAt builds a NetResolver bound to one nameserver, and is what
// Authoritative.At is wired to in production.
func NetResolverAt(server string) Resolver {
	return NetResolver{Server: server}
}

// NewAuthoritative assembles the production authoritative resolver: the NS set
// read through via, the proof read from the servers it names.
func NewAuthoritative(via NetResolver) Authoritative {
	return Authoritative{
		Delegation: NetDelegation{Via: via},
		At:         NetResolverAt,
	}
}
