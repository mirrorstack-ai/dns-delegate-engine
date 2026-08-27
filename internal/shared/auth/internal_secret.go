// Package auth contains service-authentication middleware for this service's
// HTTP transport. The name matches api-platform's and billing-engine's package
// so a developer moving between the repos finds the same thing doing the same job.
package auth

import (
	"crypto/subtle"
	"net/http"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/shared/httputil"
)

const headerInternalSecret = "X-MS-Internal-Secret" //nolint:gosec // header name, not a credential

// InternalSecret gates a request group behind the X-MS-Internal-Secret header,
// compared in constant time.
//
// An EMPTY secret refuses every request with 503 rather than allowing them: an
// unset secret is a misconfiguration, and the fail-open reading of it is exactly
// how an internal service ends up answering the internet. Callers should still
// fail fast at startup instead of relying on this.
//
// Production does not use this path — the engine is invoked via lambda.Invoke
// and IAM gates the call. It exists for local development and for any future
// HTTP transport.
func InternalSecret(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if secret == "" {
				httputil.WriteError(w, http.StatusServiceUnavailable, "unavailable", "internal secret not configured")
				return
			}
			got := r.Header.Get(headerInternalSecret)
			if subtle.ConstantTimeCompare([]byte(got), []byte(secret)) != 1 {
				httputil.WriteError(w, http.StatusUnauthorized, "unauthorized", "")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
