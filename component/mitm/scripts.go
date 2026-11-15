// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

func (h *Host) TriggerScript(ctx context.Context, instance string, request api.ScriptRunRequest) (api.ScriptRunResponse, error) {
	h.mu.Lock()
	if h.closed || !h.started || h.workersStopped || h.forceContext.Err() != nil {
		h.mu.Unlock()
		return api.ScriptRunResponse{}, plugin.ErrScriptInactive
	}
	for _, p := range h.instances {
		if p.ID != instance {
			continue
		}
		runner, ok := p.Plugin.(plugin.ScriptTrigger)
		if !ok {
			break
		}
		if !p.owner.Retain() {
			h.mu.Unlock()
			return api.ScriptRunResponse{}, plugin.ErrScriptInactive
		}
		h.requests.Add(1)
		h.mu.Unlock()
		defer h.requests.Done()
		defer p.owner.Release()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stop := context.AfterFunc(h.forceContext, cancel)
		defer stop()
		result, err := runner.TriggerScript(ctx, request)
		result.Instance = instance
		return result, err
	}
	h.mu.Unlock()
	return api.ScriptRunResponse{}, plugin.ErrScriptNotFound
}
