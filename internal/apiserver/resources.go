// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"net/http"

	"github.com/daeuniverse/dae/api"
)

func (s *Handler) serveResources(w http.ResponseWriter, r *http.Request, who caller) {
	if !apiBody(w, r, nil) {
		return
	}
	if s.options.Operations == nil {
		apiError(w, http.StatusServiceUnavailable, "resource refresh is unavailable")
		return
	}
	if r.Method == http.MethodPost {
		s.submitOperation(w, api.OperationRequest{Kind: "refresh"})
		return
	}
	writeAPI(w, s.options.Operations.ResourceRefreshStatus())
}
