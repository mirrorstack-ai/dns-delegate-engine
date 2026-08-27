package dnsplan

import "fmt"

// This file is the documentation-support half of the package: it renders a plan
// the way README.md and docs/RECORDS.md describe one, and nothing here enforces
// anything. The rules it renders live in purpose.go and plan.go.
//
// It is in this package rather than beside the documents on purpose. Coupling
// the rendering to the domain type is what makes the tables checkable — the
// examples in example_test.go print real plans through Explain, with `// Output:`
// blocks, so `go test` fails when a record shape changes and the documents do
// not.

// Explanation is one record, rendered the way the plan is described to a
// customer.
//
// It carries the record ALONE and derives the purpose on demand, rather than
// storing both: a stored pair could be built with a purpose that does not match
// its record, and this type exists precisely so that the tables in README.md and
// docs/RECORDS.md cannot say one thing while the code does another.
type Explanation struct {
	Record Record
}

// Purpose is what this record is for. See Classify.
func (e Explanation) Purpose() Purpose { return Classify(e.Record) }

// String renders one record as a documentation row.
func (e Explanation) String() string {
	proxy := "DNS-only"
	if e.Record.Proxied {
		proxy = "proxied"
	}
	return fmt.Sprintf("%-11s %-5s %-44s %-44s %s",
		e.Purpose(), e.Record.Type, e.Record.Name, e.Record.Value, proxy)
}

// Explain names every record in a plan, in publication order.
//
// It is what makes the record tables in README.md and docs/RECORDS.md checkable
// rather than merely asserted: the examples in this package print real plans
// through this function, and `go test` fails if the output drifts from what the
// documentation claims.
func (s Snapshot) Explain() []Explanation {
	out := make([]Explanation, 0, len(s.Records))
	for _, record := range s.Records {
		out = append(out, Explanation{Record: record})
	}
	return out
}
