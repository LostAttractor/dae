// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

func (h *Host) MigrateScriptStore(ctx context.Context, instance string, request api.ScriptStoreMigrateRequest) (api.ScriptStoreMigrateResponse, error) {
	if h == nil {
		return api.ScriptStoreMigrateResponse{}, plugin.ErrScriptStoreUnavailable
	}
	h.mu.Lock()
	if !h.started || h.closed || h.workersStopped || h.forceContext.Err() != nil {
		h.mu.Unlock()
		return api.ScriptStoreMigrateResponse{}, plugin.ErrScriptStoreUnavailable
	}
	for _, p := range h.instances {
		if p.ID != instance {
			continue
		}
		migrator, ok := p.Plugin.(plugin.ScriptStoreMigrator)
		if !ok || !p.owner.Retain() {
			h.mu.Unlock()
			return api.ScriptStoreMigrateResponse{}, plugin.ErrScriptStoreUnavailable
		}
		h.requests.Add(1)
		h.mu.Unlock()
		// Retain protects resources; request admission also joins the host drain.
		defer h.requests.Done()
		defer p.owner.Release()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stop := context.AfterFunc(h.forceContext, cancel)
		defer stop()
		response, err := migrator.MigrateScriptStore(ctx, request)
		response.Instance = instance
		return response, err
	}
	h.mu.Unlock()
	return api.ScriptStoreMigrateResponse{}, plugin.ErrScriptStoreNotFound
}
