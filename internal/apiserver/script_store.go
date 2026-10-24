// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/macaddr"
	"github.com/daeuniverse/dae/common/persist"
	"github.com/daeuniverse/dae/component/plugin"
)

func (s *Handler) serveScriptStoreMigration(w http.ResponseWriter, r *http.Request, _ caller) {
	var request api.ScriptStoreMigrateRequest
	if !apiBody(w, r, &request) {
		return
	}
	from, fromErr := macaddr.ParseClient(request.FromMAC)
	to, toErr := macaddr.ParseClient(request.ToMAC)
	if fromErr != nil || toErr != nil || from == to {
		apiError(w, http.StatusBadRequest, plugin.ErrScriptStoreInvalid.Error())
		return
	}
	request.FromMAC, request.ToMAC = net.HardwareAddr(from[:]).String(), net.HardwareAddr(to[:]).String()
	if s.options.ScriptStorage == nil {
		apiError(w, http.StatusServiceUnavailable, plugin.ErrScriptStoreUnavailable.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	response, err := s.options.ScriptStorage.MigrateScriptStore(ctx, r.PathValue("instance"), request)
	if err != nil {
		switch {
		case persist.Published(err):
			apiError(w, http.StatusInternalServerError, "script store migration was published, but durability is unconfirmed; do not automatically retry")
		case errors.Is(err, plugin.ErrScriptStoreInvalid):
			apiError(w, http.StatusBadRequest, plugin.ErrScriptStoreInvalid.Error())
		case errors.Is(err, plugin.ErrScriptStoreNotFound):
			apiError(w, http.StatusNotFound, plugin.ErrScriptStoreNotFound.Error())
		case errors.Is(err, plugin.ErrScriptStoreConflict):
			apiError(w, http.StatusConflict, plugin.ErrScriptStoreConflict.Error())
		case errors.Is(err, plugin.ErrScriptStoreBusy):
			apiError(w, http.StatusConflict, plugin.ErrScriptStoreBusy.Error())
		case errors.Is(err, plugin.ErrScriptStoreUnavailable), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			apiError(w, http.StatusServiceUnavailable, plugin.ErrScriptStoreUnavailable.Error())
		default:
			apiError(w, http.StatusInternalServerError, "could not migrate script storage")
		}
		return
	}
	writeAPI(w, response)
}
