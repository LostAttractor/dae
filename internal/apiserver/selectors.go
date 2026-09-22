// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"errors"
	"net/http"

	contract "github.com/daeuniverse/dae/api"
)

func (s *handler) serveSelectors(w http.ResponseWriter, r *http.Request) {
	mode, ok := s.requireAdmin(w, r)
	if !ok || !apiBody(w, r, nil) {
		return
	}
	writeAPI(w, contract.SelectorsResponse{
		Selectors: s.options.Selectors.Selectors(), AdminEnabled: true,
		AuthMode: mode,
	})
}

func (s *handler) serveSelector(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
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
