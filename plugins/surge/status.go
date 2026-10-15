// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"slices"

	surgeapi "github.com/daeuniverse/dae/plugins/surge/api"
)

type resourceStatus struct{ modules []surgeapi.ModuleStatus }

// AcceptResources changes observation metadata only. Runtime modules remain
// immutable and retain their script state, caches, metrics and task identities.
func (e *Engine) AcceptResources(value any) {
	modules, ok := value.([]*Module)
	if !ok {
		return
	}
	status := &resourceStatus{modules: make([]surgeapi.ModuleStatus, 0, len(modules))}
	for _, module := range modules {
		status.modules = append(status.modules, module.Status())
	}
	e.resourceStatus.Store(status)
}

func (m *Module) Status() surgeapi.ModuleStatus {
	state := m.cacheState
	if state == "" {
		state = "loaded"
	}
	if m.disabled {
		state = "disabled"
	}
	return surgeapi.ModuleStatus{
		Name: m.Name, Source: m.source, State: state,
		Scripts: len(m.Scripts) + len(m.TaskScripts), Hostnames: len(m.Hostnames), HostMappings: len(m.Hosts) + len(m.DNSHosts),
		URLRewrites: len(m.URLRewrites), HeaderRewrites: len(m.HeaderRewrites),
		BodyRewrites: len(m.BodyRewrites), MapLocals: len(m.MapLocals), Rules: len(m.Rules),
		Warnings: slices.Clone(m.Warnings),
	}
}

func (e *Engine) Status() surgeapi.SurgeStatus {
	status := surgeapi.SurgeStatus{Enabled: true, Modules: make([]surgeapi.ModuleStatus, 0, len(e.options.Modules))}
	if e.options.Runtime != nil {
		status.Runtimes = []surgeapi.SurgeRuntimeStatus{e.options.Runtime.backend.status()}
		status.Notifications = e.options.Runtime.notifications.snapshot()
	}
	indices := make(map[*Module]int, len(e.options.Modules))
	resources := e.resourceStatus.Load()
	for _, module := range e.options.Modules {
		indices[module] = len(status.Modules)
		entry := module.Status()
		if resources != nil && len(resources.modules) == len(e.options.Modules) {
			entry = resources.modules[len(status.Modules)]
			entry.Warnings = slices.Clone(entry.Warnings)
		}
		status.Modules = append(status.Modules, entry)
	}
	if e.tasks != nil {
		e.tasks.mu.Lock()
		defer e.tasks.mu.Unlock()
		for _, job := range e.tasks.jobs {
			if index, ok := indices[job.module]; ok {
				status.Modules[index].Tasks = append(status.Modules[index].Tasks, job.status)
			}
		}
	}
	return status
}

func (e *Engine) Report() any { return e.Status() }
