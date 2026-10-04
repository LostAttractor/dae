// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

func (h *Host) TriggerScript(instance string, request api.ScriptRunRequest) (api.ScriptRunResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.cancel == nil {
		return api.ScriptRunResponse{}, plugin.ErrScriptInactive
	}
	for _, p := range h.instances {
		if p.ID != instance {
			continue
		}
		if runner, ok := p.Plugin.(plugin.ScriptTrigger); ok {
			result, err := runner.TriggerScript(request)
			result.Instance = instance
			return result, err
		}
		break
	}
	return api.ScriptRunResponse{}, plugin.ErrScriptNotFound
}
