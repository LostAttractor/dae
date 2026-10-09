// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"errors"
	"net/http"

	"github.com/daeuniverse/dae/api"
)

var ErrRefreshBusy = errors.New("resource refresh is already queued or running")

type ResourceStore interface {
	RefreshResources() (api.ResourceRefreshStatus, error)
	ResourceRefreshStatus() api.ResourceRefreshStatus
}

func (s *handler) serveResources(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok || !apiBody(w, r, nil) {
		return
	}
	if s.options.Resources == nil {
		apiError(w, http.StatusServiceUnavailable, "resource refresh is unavailable")
		return
	}
	if r.Method == http.MethodGet {
		writeAPI(w, s.options.Resources.ResourceRefreshStatus())
		return
	}
	status, err := s.options.Resources.RefreshResources()
	if err != nil {
		if errors.Is(err, ErrRefreshBusy) {
			apiError(w, http.StatusConflict, err.Error())
		} else {
			apiError(w, http.StatusInternalServerError, "could not request resource refresh")
		}
		return
	}
	writeAPIStatus(w, status, http.StatusAccepted)
}
