// Package config provides startup-time helpers shared by the binaries in cmd/.
// The functions here are intentionally fail-fast: a missing required env var
// calls os.Exit so misconfiguration surfaces loudly at process start, never as a
// confusing 500 mid-traffic.
package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Auth mode values for the DB_AUTH env var, read by MustPgxPool.
const (
	// AuthPassword authenticates with the password embedded in DATABASE_URL.
	// Local dev default.
	AuthPassword = "password"
	// AuthRDSIAM authenticates through RDS Proxy with a locally-signed
	// 15-minute RDS-IAM token minted per new connection (any password in
	// DATABASE_URL is overwritten before each dial).
	AuthRDSIAM = "rds-iam"
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

// MustPgxPool reads DATABASE_URL, opens a pgxpool, and exits on construction
// failure. The returned pool is lazily connected — call Ping to fail fast on an
// unreachable database.
func MustPgxPool() *pgxpool.Pool {
	dsn := MustEnv("DATABASE_URL")
	poolCfg, err := PgxPoolConfig(dsn, os.Getenv("DB_AUTH"))
	if err != nil {
		slog.Error("pgxpool config failed", "error", err)
		os.Exit(1)
	}
	// NewWithConfig, not New(ctx, poolCfg.ConnString()): ConnString() returns
	// the ORIGINAL DSN, so re-parsing it would silently drop the programmatic
	// BeforeConnect hook set in rds-iam mode — and the pool would then dial with
	// whatever password the DSN carries, which in production is none.
	pool, err := pgxpool.NewWithConfig(context.Background(), poolCfg)
	if err != nil {
		slog.Error("pgxpool init failed", "error", err)
		os.Exit(1)
	}
	return pool
}

// PgxPoolConfig parses the DSN and applies the DB_AUTH mode. It rejects
// combinations that would otherwise fail at dial time with an opaque server
// error: RDS-IAM tokens are only accepted over TLS, so a non-TLS DATABASE_URL
// would be a silent downgrade — and would put the token on the wire in clear.
func PgxPoolConfig(dsn, authMode string) (*pgxpool.Config, error) {
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	switch authMode {
	case "", AuthPassword:
		return poolCfg, nil
	case AuthRDSIAM:
		// TLSConfig == nil means the parsed DSN resolved to a plaintext primary
		// connection (sslmode=disable or allow) — reject loudly.
		if poolCfg.ConnConfig.TLSConfig == nil {
			return nil, fmt.Errorf("config: DB_AUTH=rds-iam requires TLS, set sslmode=require in DATABASE_URL")
		}
		poolCfg.BeforeConnect = newRDSIAMBeforeConnect()
		return poolCfg, nil
	default:
		return nil, fmt.Errorf("config: unknown DB_AUTH %q (want %q or %q)", authMode, AuthPassword, AuthRDSIAM)
	}
}
