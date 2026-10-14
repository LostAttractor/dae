// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"net/http"

	"github.com/daeuniverse/dae/api"
)

func (s *handler) serveResources(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok || !apiBody(w, r, nil) {
		return
	}
	if s.options.Operations == nil {
		apiError(w, http.StatusServiceUnavailable, "resource refresh is unavailable")
		return
	}
	if r.Method == http.MethodGet {
		writeAPI(w, s.options.Operations.ResourceRefreshStatus())
		return
	}
	s.submitOperation(w, api.OperationRequest{Kind: "refresh"})
}
