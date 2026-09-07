// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	contract "github.com/daeuniverse/dae/api"
)

func (s *server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if localAPISocket(r) {
		return true
	}
	if s.options.Token == "" {
		apiError(w, 403, "global.api_token is not configured; administration is disabled")
		return false
	}
	actual, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	got, want := sha256.Sum256([]byte(actual)), sha256.Sum256([]byte(s.options.Token))
	if !bearer || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="dae"`)
		apiError(w, 401, "API token is missing or incorrect")
		return false
	}
	return true
}

func (s *server) serveSelectors(w http.ResponseWriter, r *http.Request) {
	if !apiBody(w, r, nil) {
		return
	}
	writeAPI(w, contract.SelectorsResponse{Selectors: s.options.Selectors.Selectors(), AdminEnabled: localAPISocket(r) || s.options.Token != ""})
}

func (s *server) serveSelector(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id := ""
	if r.Method == http.MethodPut {
		var request contract.SelectNodeRequest
		if !apiBody(w, r, &request) {
			return
		}
		if request.NodeID == "" {
			apiError(w, 400, "node_id is required")
			return
		}
		id = request.NodeID
	} else if !apiBody(w, r, nil) {
		return
	}
	state, err := s.options.Selectors.Select(r.PathValue("group"), id, r.RemoteAddr)
	if err != nil {
		switch {
		case errors.Is(err, ErrSelectorNotFound):
			apiError(w, 404, err.Error())
		case errors.Is(err, ErrSelectorNode):
			apiError(w, 400, err.Error())
		default:
			apiSaveError(w, err)
		}
		return
	}
	writeAPI(w, state)
}
