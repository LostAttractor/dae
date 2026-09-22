// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"errors"
	"net/http"

	"github.com/daeuniverse/dae/api"
)

func (s *handler) serveProbe(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	var request api.ProbeRequest
	if !apiBody(w, r, &request) {
		return
	}
	if request.Outbound == "" {
		apiError(w, http.StatusBadRequest, "outbound is required")
		return
	}
	response, err := s.options.Probes.Probe(request, r.RemoteAddr)
	if err != nil {
		switch {
		case errors.Is(err, ErrProbeOutbound):
			apiError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, ErrProbeNode):
			apiError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, ErrProbeUnsupported):
			apiError(w, http.StatusConflict, err.Error())
		default:
			apiError(w, http.StatusInternalServerError, "could not request connectivity probe")
		}
		return
	}
	writeAPIStatus(w, response, http.StatusAccepted)
}
