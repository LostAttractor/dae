// SPDX-License-Identifier: AGPL-3.0-only
package apiserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

func keyMatches(actual, expected string) bool {
	got, want := sha256.Sum256([]byte(actual)), sha256.Sum256([]byte(expected))
	return expected != "" && subtle.ConstantTimeCompare(got[:], want[:]) == 1
}
func authenticationError(w http.ResponseWriter) bool {
	w.Header().Set("WWW-Authenticate", `Bearer realm="dae"`)
	apiError(w, 401, "API credentials are missing or incorrect")
	return false
}
func (s *Handler) keyRole(r *http.Request) (accessRole, bool) {
	if len(r.Header.Values("Authorization")) != 1 {
		return 0, false
	}
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if ok && strings.EqualFold(scheme, "Bearer") {
		if keyMatches(token, s.options.AdminKey) {
			return roleAdmin, true
		}
		if keyMatches(token, s.options.UserKey) {
			return roleUser, true
		}
		return 0, false
	}
	// Basic is a tool compatibility encoding for the same administrator key.
	if strings.HasPrefix(r.URL.Path, "/debug/pprof/") {
		name, password, ok := r.BasicAuth()
		if ok && name == "dae" && keyMatches(password, s.options.AdminKey) {
			return roleAdmin, true
		}
	}
	return 0, false
}
