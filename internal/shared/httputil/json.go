// Package httputil holds the RPC envelope this service answers in.
package httputil

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// Envelope is the {ok, response|error} shape api-platform's client expects. It
// matches billing-engine's contract so one client shape serves both internal
// services.
type Envelope struct {
	OK       bool   `json:"ok"`
	Response any    `json:"response,omitempty"`
	Error    *Error `json:"error,omitempty"`
}

// Error is a machine-readable failure. The code is the caller's contract; the
// message is for a human reading logs.
//
// 🔴 NEVER PUT A PROVIDER RESPONSE BODY IN HERE. A Cloudflare error can quote
// zone contents, and this envelope reaches a browser.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// WriteJSON writes a success envelope.
func WriteJSON(w http.ResponseWriter, status int, response any) {
	write(w, status, Envelope{OK: true, Response: response})
}

// WriteError writes a failure envelope.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	write(w, status, Envelope{OK: false, Error: &Error{Code: code, Message: message}})
}

func write(w http.ResponseWriter, status int, body Envelope) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// The status line is already on the wire; there is nothing to say to the
		// client. Log it so a truncated response is not silent.
		slog.Error("httputil: encode response", "error", err)
	}
}
