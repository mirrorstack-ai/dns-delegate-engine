package dnsplan

import (
	"fmt"
	"strings"
)

// Purpose is what a record in a plan is FOR, in the vocabulary a customer's own
// developers use when they ask "why is MirrorStack asking to write this?".
//
// It is READ FROM THE NAME, and that is the whole design. Working out WHICH
// records a given domain needs is MirrorStack edge topology and stays in the
// private half — but naming what a record already in a plan is doing needs no
// topology at all, so it can live here, where it is readable, and be pinned by
// the examples in this package.
//
// Three purposes cover every record this service can publish, because the plan
// vocabulary is CNAME and TXT only:
//
//	ownership    the one record that proves the anchor is yours
//	certificate  a record a certificate authority reads, so TLS can issue
//	routing      the record that actually sends traffic to MirrorStack
type Purpose string

const (
	// PurposeOwnership is the shared proof record. There is exactly one per
	// connected domain, it sits AT the anchor, and it is what every later stage
	// is gated on — MirrorStack will not create a custom hostname, and therefore
	// no certificate record can exist, until a public lookup finds it.
	PurposeOwnership Purpose = "ownership"

	// PurposeCertificate is a validation record. A certificate authority reads
	// it by name to prove MirrorStack may issue for that hostname. It carries a
	// token neither side chooses, it is answered by a machine and never by a
	// browser, and it must be RETAINED: a certificate renews against it months
	// after issuance.
	PurposeCertificate Purpose = "certificate"

	// PurposeRouting is the record that makes the hostname resolve to
	// MirrorStack. It is the only kind of record in a plan that a visitor's
	// browser ever follows, and deleting one takes that hostname down.
	PurposeRouting Purpose = "routing"
)

// OwnershipLabel is the first label of the ownership proof record. It is a
// literal rather than a pattern so that the one record placed AT your anchor —
// the only record in a plan that is not under a reserved underscore name — is
// identifiable on sight.
const OwnershipLabel = "_mirrorstack-challenge"

// Classify names what a record is for.
//
// The rule is the DNS convention, not a MirrorStack one: a name whose first
// label begins with an underscore is a reserved name, reachable only by
// something that already knows to look there. No browser resolves one, so no
// record under one can carry traffic. That is why a validation record is
// distinguishable from a routing record without knowing anything about
// MirrorStack's topology.
func Classify(record Record) Purpose {
	label, _, _ := strings.Cut(NormalizeName(record.Name), ".")
	switch {
	case label == OwnershipLabel:
		return PurposeOwnership
	case strings.HasPrefix(label, "_"):
		return PurposeCertificate
	default:
		return PurposeRouting
	}
}

// IsValidation reports whether a record exists to be read by a certificate
// authority or by MirrorStack's own ownership check, rather than to carry
// traffic.
func IsValidation(record Record) bool {
	return Classify(record) != PurposeRouting
}

// assertNoProxiedValidation refuses a plan that would put a validation record
// behind Cloudflare's proxy.
//
// 🔴 CLOUDFLARE DOES NOT REFUSE THIS, AND THAT IS WHY IT IS CHECKED HERE.
//
// Measured 2026-08-23: the API accepts proxied=true on a validation name with no
// error and no warning, and then FLATTENS the CNAME to A records. A certificate
// authority following the record finds addresses instead of the token it came
// for, and issuance fails — or, far worse, a RENEWAL fails silently months
// later, with the hostname serving happily on the certificate it already has
// until the day that certificate expires.
//
// Nothing downstream catches it. A proxied validation record looks correct in
// every dashboard, resolves, and returns a 200. So the plan is refused before
// anything is written, and the customer's certificates cannot be broken by a
// derivation bug on the private side.
func assertNoProxiedValidation(records []Record) error {
	for _, record := range records {
		if !record.Proxied {
			continue
		}
		if purpose := Classify(record); purpose != PurposeRouting {
			return fmt.Errorf("%w: %q is a %s record and may not be proxied",
				ErrProxiedValidation, NormalizeName(record.Name), purpose)
		}
	}
	return nil
}
