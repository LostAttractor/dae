// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

// requireAdmin returns the access mode along with the authorization decision.
// LAN access is verified on every request; a saved cookie cannot replace it.
func (s *handler) requireAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	if localAPISocket(r) {
		return "unix", true
	}
	if s.options.APIKey == "" {
		_, _, ok := apiDevice(w, r, s.options.ResolveClient)
		return "lan", ok
	}
	// An explicit Authorization header takes precedence over a saved session.
	if r.Header.Get("Authorization") == "" && s.validSession(r) {
		return "api_key", true
	}
	return "api_key", s.requireAPIKey(w, r)
}

// Callers choose LAN authorization before reaching key/session authentication,
// so these paths always have a configured, nonempty API key.
func (s *handler) requireAPIKey(w http.ResponseWriter, r *http.Request) bool {
	actual, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	got, want := sha256.Sum256([]byte(actual)), sha256.Sum256([]byte(s.options.APIKey))
	if !bearer || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="dae"`)
		apiError(w, http.StatusUnauthorized, "API key is missing or incorrect; log in to view administration status")
		return false
	}
	return true
}
