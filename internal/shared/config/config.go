// Package config provides startup-time helpers shared by the binaries in cmd/.
// The functions here are intentionally fail-fast: a missing required env var
// calls os.Exit so misconfiguration surfaces loudly at process start, never as a
// confusing 500 mid-traffic.
//
// 🔴 THERE IS NO DATABASE HELPER HERE, AND THAT IS DELIBERATE.
//
// This service owns no table and opens no connection. api-platform holds every
// row — including the sealed grants, as ciphertext it has no key for — and this
// service holds the credentials, which it has nowhere to persist. Neither half
// can act alone, and a reader auditing what can reach their DNS zone does not
// also have to reason about a database.
package config

import (
	"log/slog"
	"os"
)

// IsLambda reports whether the process is running inside an AWS Lambda runtime.
// Every Lambda execution environment sets AWS_LAMBDA_FUNCTION_NAME and nothing
// else does, which makes it a stable transport-selection sentinel.
func IsLambda() bool {
	return os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != ""
}

// MustEnv returns the value of the given env var, exiting if unset or empty.
// Use it for required configuration at startup — never inside a handler.
func MustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("required env var not set", "key", key)
		os.Exit(1)
	}
	return v
}

// Port resolves a local HTTP listener port: the service-specific env var, then
// the generic PORT, then the fallback. Production Lambda does not bind a port.
func Port(envKey, fallback string) string {
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	if v := os.Getenv("PORT"); v != "" {
		return v
	}
	return fallback
}
