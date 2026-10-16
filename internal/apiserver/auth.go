// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

// authorize calls this only with a configured, nonempty API key.
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
