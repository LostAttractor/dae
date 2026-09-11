// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"slices"

	"github.com/daeuniverse/dae/api"
)

func (m *Module) Status() api.ModuleStatus {
	state := m.cacheState
	if state == "" {
		state = "loaded"
	}
	return api.ModuleStatus{
		Name: m.Name, Source: m.source, State: state,
		Scripts: len(m.Scripts), Hostnames: len(m.Hostnames), HostMappings: len(m.Hosts) + len(m.DNSHosts),
		URLRewrites: len(m.URLRewrites), HeaderRewrites: len(m.HeaderRewrites),
		BodyRewrites: len(m.BodyRewrites), MapLocals: len(m.MapLocals), Rules: len(m.Rules),
		Warnings: slices.Clone(m.Warnings),
	}
}

func (e *Engine) Status() api.SurgeStatus {
	status := api.SurgeStatus{Enabled: true, Modules: make([]api.ModuleStatus, 0, len(e.options.Modules))}
	for _, module := range e.options.Modules {
		status.Modules = append(status.Modules, module.Status())
	}
	return status
}

func (e *Engine) Report() any { return e.Status() }
