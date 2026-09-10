// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"encoding/json"

	"github.com/daeuniverse/dae/component/mitm/plugin"
)

func (h *Host) Status() []plugin.InstanceStatus {
	h.mu.Lock()
	state := "prepared"
	if h.cancel != nil {
		state = "active"
	}
	if h.closed {
		state = "draining"
	}
	result := make([]plugin.InstanceStatus, 0, len(h.instances))
	memory := plugin.BodyMemory.Status()
	for _, p := range h.instances {
		result = append(result, plugin.InstanceStatus{BufferMemory: &memory, ID: p.ID, Type: p.Type, State: state, Scopes: len(p.plan.Scopes), DestinationRules: len(p.plan.Destinations)})
	}
	h.mu.Unlock()
	for i, p := range h.instances {
		if reporter, ok := p.Plugin.(plugin.Reporter); ok {
			result[i].Details, _ = json.Marshal(reporter.Report())
		}
	}
	return result
}
