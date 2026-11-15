// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"context"
	"errors"
	"net/http"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

func (s *handler) serveScript(w http.ResponseWriter, r *http.Request, who caller) {
	var request api.ScriptRunRequest
	if !apiBody(w, r, &request) {
		return
	}
	if request.Script == "" {
		apiError(w, http.StatusBadRequest, "script is required")
		return
	}
	if s.options.Scripts == nil {
		apiError(w, http.StatusServiceUnavailable, "script plugins are unavailable")
		return
	}
	response, err := s.options.Scripts.TriggerScript(r.Context(), r.PathValue("instance"), request)
	if err != nil {
		switch {
		case errors.Is(err, plugin.ErrScriptNotFound):
			apiError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, plugin.ErrScriptAmbiguous), errors.Is(err, plugin.ErrScriptDeviceUnsupported), errors.Is(err, plugin.ErrScriptDeviceInvalid):
			apiError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, plugin.ErrScriptBusy), errors.Is(err, plugin.ErrScriptDeviceDisabled):
			apiError(w, http.StatusConflict, err.Error())
		case errors.Is(err, plugin.ErrScriptInactive), errors.Is(err, plugin.ErrScriptDeviceUnavailable), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			apiError(w, http.StatusServiceUnavailable, err.Error())
		default:
			apiError(w, http.StatusInternalServerError, "could not trigger script task")
		}
		return
	}
	writeAPIStatus(w, response, http.StatusAccepted)
}
