package observe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
)

// ErrNoQuorum means the vantage points did not agree, so there is no reading.
//
// 🔴 IT IS DELIBERATELY NOT A *net.DNSError WITH IsNotFound SET. isNotFound is
// the one error this package reads as absence, and a disagreement folded into it
// would let a single unreachable vantage point look like a customer withdrawing
// their proof.
var ErrNoQuorum = errors.New("observe: the vantage points did not agree")

// Agreement is how many independent vantage points a reading rests on.
//
// The zero value means no lookup was issued — the ownership row inside Plan, and
// a record whose value is not known yet.
type Agreement struct {
	// Asked is how many vantage points were queried, Agreed how many served the
	// reading reported beside this, and Threshold how many had to.
	Asked     int
	Agreed    int
	Threshold int
}

// Policy is how a Resolver was assembled. It is published through
// intent.Capabilities so a customer can read the rule BEFORE authorizing
// (docs/DESIGN.md §4).
type Policy struct {
	Vantages      int
	Threshold     int
	Authoritative bool
}

// Policied is the optional interface by which a Resolver declares its Policy.
type Policied interface {
	Policy() Policy
}

// PolicyOf reports how r was assembled, falling back to the honest description
// of a plain Resolver: one vantage point, believed on its own.
func PolicyOf(r Resolver) Policy {
	if p, ok := r.(Policied); ok {
		return p.Policy()
	}
	return Policy{Vantages: 1, Threshold: 1}
}

// Attesting is an OPTIONAL extension to Resolver: the same two questions, plus
// how many vantage points the answer rests on. Optional because a plain Resolver
// is still a complete implementation — see attestedTXT.
type Attesting interface {
	Resolver
	AttestedCNAME(ctx context.Context, name string) (string, Agreement, error)
	AttestedTXT(ctx context.Context, name string) ([]string, Agreement, error)
}

// Quorum asks N independent Resolvers the same question and reports only what at
// least Threshold of them agree on. It narrows — never closes — the largest
// unclosed assumption in docs/THREAT-MODEL.md: a single recursive resolver that
// lies.
//
// 🔴 IT FAILS CLOSED, AND ITS THREE OUTCOMES ARE NOT TWO.
//
//   - Threshold vantage points served the same value → that value.
//   - Threshold vantage points served NOTHING → absence, as a *net.DNSError with
//     IsNotFound set, because a customer's stop control must keep working when
//     the vantage points agree the proof is gone.
//   - Anything else → ErrNoQuorum, which observe reads as StateUnknown. A split
//     answer is a failure to get an answer, and this package already forbids an
//     unknown reading from counting as a withdrawal (see StateUnknown).
//
// It is a Resolver itself, so it composes: a Quorum may hold recursive
// resolvers, an Authoritative, or both.
//
// # What this closes, and what it does not
//
// Closes: a single lying recursive resolver, and an off-path cache poisoner who
// has to win the race at every vantage point rather than at one.
//
// Does NOT close: an attacker who controls the customer's registrar or their
// authoritative nameservers — every vantage point then agrees on the same
// forged answer. Nor an on-path attacker who can rewrite our egress traffic.
//
// 🔴 NOTHING HERE VALIDATES DNSSEC. Go's net.Resolver does not, this type does
// not, and no signature is checked anywhere in this repository.
type Quorum struct {
	// Resolvers are the vantage points. Independence is a property of what is
	// wired here, not something this type can check.
	Resolvers []Resolver

	// Threshold is how many must agree. Outside [1, len(Resolvers)] every lookup
	// answers ErrNoQuorum, so a misconfigured quorum verifies nothing rather than
	// everything.
	Threshold int
}

// Policy implements Policied.
func (q Quorum) Policy() Policy {
	out := Policy{Vantages: len(q.Resolvers), Threshold: q.Threshold}
	for _, r := range q.Resolvers {
		if PolicyOf(r).Authoritative {
			out.Authoritative = true
		}
	}
	return out
}

// LookupCNAME implements Resolver.
func (q Quorum) LookupCNAME(ctx context.Context, name string) (string, error) {
	value, _, err := q.AttestedCNAME(ctx, name)
	return value, err
}

// LookupTXT implements Resolver.
func (q Quorum) LookupTXT(ctx context.Context, name string) ([]string, error) {
	values, _, err := q.AttestedTXT(ctx, name)
	return values, err
}

// AttestedCNAME implements Attesting.
//
// DNS names are case-insensitive, so vantage points are grouped case-folded; the
// spelling returned is the first one seen for the winning group.
func (q Quorum) AttestedCNAME(ctx context.Context, name string) (string, Agreement, error) {
	values, agreement, err := q.agree(ctx, name, strings.ToLower,
		func(ctx context.Context, r Resolver) ([]string, error) {
			value, err := r.LookupCNAME(ctx, name)
			if err == nil && strings.TrimSpace(value) == "" {
				// The Resolver contract has no such answer, so it is not counted as
				// one: vantage points returning an empty string must not become a
				// quorum for absence.
				return nil, fmt.Errorf("%w: %q returned neither a CNAME nor an error", ErrObserve, name)
			}
			return []string{value}, err
		})
	switch {
	case err != nil:
		return "", agreement, err
	// A CNAME owner holds one value, so two winning groups is a split rather
	// than a set.
	case len(values) != 1:
		return "", Agreement{Asked: agreement.Asked, Threshold: agreement.Threshold},
			fmt.Errorf("%w: %d different CNAME targets each reached the threshold at %q", ErrNoQuorum, len(values), name)
	}
	return values[0], agreement, nil
}

// AttestedTXT implements Attesting.
//
// 🔴 AGREEMENT IS PER VALUE, NOT PER ANSWER. A TXT owner may hold many values,
// so a value one vantage point invented is dropped from the set while the values
// the others agree on survive — which is what stops a single liar forging a
// proof beside a customer's real records.
//
// Values are compared byte for byte after trimming: a TXT value is an octet
// string, and normalizeTXT does not fold its case either.
func (q Quorum) AttestedTXT(ctx context.Context, name string) ([]string, Agreement, error) {
	return q.agree(ctx, name, strings.TrimSpace,
		func(ctx context.Context, r Resolver) ([]string, error) {
			return r.LookupTXT(ctx, name)
		})
}

// vantageAnswer is what ONE vantage point said. answered is false for every
// error that is not "no such name", keeping a failure out of the absence count.
type vantageAnswer struct {
	values   []string
	answered bool
}

// agree runs one lookup at every vantage point and applies the threshold.
// group is the comparison form; the spelling reported is the first one seen.
func (q Quorum) agree(
	ctx context.Context,
	name string,
	group func(string) string,
	lookup func(context.Context, Resolver) ([]string, error),
) ([]string, Agreement, error) {
	asked := len(q.Resolvers)
	threshold := q.Threshold
	if threshold < 1 || threshold > asked {
		return nil, Agreement{Asked: asked, Threshold: threshold},
			fmt.Errorf("%w: a quorum of %d over %d vantage points cannot be met", ErrNoQuorum, threshold, asked)
	}

	answers := make([]vantageAnswer, asked)
	var wg sync.WaitGroup
	for i, r := range q.Resolvers {
		wg.Add(1)
		go func(i int, r Resolver) {
			defer wg.Done()
			values, err := lookup(ctx, r)
			switch {
			case err == nil:
				answers[i] = vantageAnswer{values: values, answered: true}
			case isNotFound(err):
				answers[i] = vantageAnswer{answered: true}
			}
		}(i, r)
	}
	wg.Wait()

	counts := make(map[string]int, asked)
	spelling := make(map[string]string, asked)
	order := make([]string, 0, asked)
	empty := 0
	for _, a := range answers {
		if !a.answered {
			continue
		}
		// Counted once per vantage point: a server repeating a value must not
		// reach the threshold by itself.
		seen := make(map[string]bool, len(a.values))
		held := 0
		for _, value := range a.values {
			key := group(value)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			held++
			if _, ok := counts[key]; !ok {
				order = append(order, key)
				spelling[key] = value
			}
			counts[key]++
		}
		if held == 0 {
			empty++
		}
	}

	// The reading is every value the threshold agrees on, and Agreed reports the
	// WEAKEST leg it rests on rather than the strongest.
	agreed := make([]string, 0, len(order))
	weakest := 0
	for _, key := range order {
		if counts[key] < threshold {
			continue
		}
		if weakest == 0 || counts[key] < weakest {
			weakest = counts[key]
		}
		agreed = append(agreed, spelling[key])
	}
	if len(agreed) > 0 {
		return agreed, Agreement{Asked: asked, Agreed: weakest, Threshold: threshold}, nil
	}
	if empty >= threshold {
		return nil, Agreement{Asked: asked, Agreed: empty, Threshold: threshold}, nxdomain(name)
	}
	return nil, Agreement{Asked: asked, Threshold: threshold},
		fmt.Errorf("%w: no value reached %d of %d vantage points at %q", ErrNoQuorum, threshold, asked, name)
}

// nxdomain is the quorum's absence, in the one shape isNotFound recognises.
func nxdomain(name string) error {
	return &net.DNSError{
		Err:        "the vantage points agree that no record is published here",
		Name:       name,
		IsNotFound: true,
	}
}

// soleVantage is what a plain Resolver's completed lookup rests on, stated
// rather than left blank so a customer reading `1 of 1` sees the exposure.
var soleVantage = Agreement{Asked: 1, Agreed: 1, Threshold: 1}

// attestedCNAME reads r through Attesting when it offers it.
func attestedCNAME(ctx context.Context, r Resolver, name string) (string, Agreement, error) {
	if a, ok := r.(Attesting); ok {
		return a.AttestedCNAME(ctx, name)
	}
	value, err := r.LookupCNAME(ctx, name)
	if err != nil && !isNotFound(err) {
		return value, Agreement{Asked: 1, Threshold: 1}, err
	}
	return value, soleVantage, err
}

// attestedTXT reads r through Attesting when it offers it.
func attestedTXT(ctx context.Context, r Resolver, name string) ([]string, Agreement, error) {
	if a, ok := r.(Attesting); ok {
		return a.AttestedTXT(ctx, name)
	}
	values, err := r.LookupTXT(ctx, name)
	if err != nil && !isNotFound(err) {
		return values, Agreement{Asked: 1, Threshold: 1}, err
	}
	return values, soleVantage, err
}

// Majority is the default threshold: more than half the vantage points.
func Majority(vantages int) int {
	if vantages < 1 {
		return 1
	}
	return vantages/2 + 1
}
