package observe

import (
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
)

// Environment variables that assemble this deployment's Resolver.
const (
	resolversEnv     = "DNS_DELEGATE_RESOLVERS"
	authoritativeEnv = "DNS_DELEGATE_AUTHORITATIVE"
	quorumEnv        = "DNS_DELEGATE_QUORUM"
)

// ResolverFromEnv assembles the Resolver a binary hands to the intent service.
//
//	DNS_DELEGATE_RESOLVERS      comma-separated recursive nameservers, host[:port]
//	DNS_DELEGATE_AUTHORITATIVE  1/true/yes/on adds the zone's own nameservers as a vantage point
//	DNS_DELEGATE_QUORUM         how many vantage points must agree; default a majority
//
// 🔴 THE DEFAULT IS ONE RECURSIVE RESOLVER, WHICH IS THIS SERVICE'S BEHAVIOUR
// BEFORE THIS CODE EXISTED. Making a quorum the default would put every
// registration behind egress this deployment has not been measured to have —
// port 53 to addresses a customer's zone chooses — and a vantage point that
// cannot be reached answers unknown, which refuses every Authorize.
//
// Whatever it returns, PolicyOf reports it and intent.Capabilities publishes it,
// so a deployment running on the default says so rather than implying more.
func ResolverFromEnv() Resolver {
	container := NetResolver{}
	vantages := make([]Resolver, 0, 4)
	for _, server := range splitServers(os.Getenv(resolversEnv)) {
		vantages = append(vantages, NetResolver{Server: server})
	}
	if boolEnv(authoritativeEnv) {
		vantages = append(vantages, NewAuthoritative(container))
	}

	switch len(vantages) {
	case 0:
		return container
	case 1:
		// A quorum of one is a quorum in name only, and Policy would then claim a
		// threshold that decided nothing.
		return vantages[0]
	}
	return Quorum{Resolvers: vantages, Threshold: thresholdFromEnv(len(vantages))}
}

// thresholdFromEnv reads DNS_DELEGATE_QUORUM.
//
// 🔴 AN UNREADABLE OR OUT-OF-RANGE VALUE BECOMES UNANIMITY, NEVER A MAJORITY.
// The operator asked for something this code could not honour, and the strictest
// reading is the one that cannot silently verify more than they intended.
func thresholdFromEnv(vantages int) int {
	raw := strings.TrimSpace(os.Getenv(quorumEnv))
	if raw == "" {
		return Majority(vantages)
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > vantages {
		slog.Error("observe: unusable resolver quorum, requiring every vantage point instead",
			"env", quorumEnv, "value", raw, "vantages", vantages)
		return vantages
	}
	return n
}

// splitServers parses the resolver list, defaulting each entry to port 53.
// An entry that is not an address is dropped with a log line rather than
// becoming a vantage point that fails every lookup.
func splitServers(raw string) []string {
	out := make([]string, 0, 4)
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(field); err != nil {
			field = net.JoinHostPort(field, "53")
		}
		if host, _, err := net.SplitHostPort(field); err != nil || host == "" {
			slog.Error("observe: ignoring an unparseable resolver address", "env", resolversEnv, "value", field)
			continue
		}
		out = append(out, field)
	}
	return out
}

func boolEnv(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
