// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"encoding/json"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

func (h *Host) Status() api.PluginStatus {
	h.mu.Lock()
	state := "prepared"
	if h.started {
		state = "active"
	}
	if h.closed {
		state = "draining"
	}
	result := make([]plugin.InstanceStatus, 0, len(h.instances))
	for _, p := range h.instances {
		reason := ""
		switch {
		case len(p.owner.Plan.Scopes) == 0:
			reason = "no_scopes"
		case h.options.DisableHTTP:
			reason = "mitm_disabled"
		case state != "active":
			reason = state
		}
		result = append(result, plugin.InstanceStatus{
			ID: p.ID, Type: p.Type, Enabled: true, State: state,
			DeclaredScopes: len(p.owner.Plan.Scopes), Scopes: len(p.plan.Scopes),
			HTTPActive: reason == "", HTTPReason: reason, DestinationRules: len(p.plan.Destinations),
		})
	}
	h.mu.Unlock()
	for i, p := range h.instances {
		if reporter, ok := p.Plugin.(plugin.Reporter); ok {
			result[i].Details, _ = json.Marshal(reporter.Report())
		}
	}
	return api.PluginStatus{Plugins: result, BufferMemory: api.BufferMemoryStatus(h.options.bodyMemory().Status())}
}
