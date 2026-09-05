// SPDX-License-Identifier: AGPL-3.0-only

package surgemodule

import "slices"

// Status describes the modules of one initialized engine. It does not probe
// traffic or execute scripts; a loaded module may not have matched any request.
type Status struct {
	Enabled bool           `json:"enabled"`
	Modules []ModuleStatus `json:"modules"`
}

type ModuleStatus struct {
	Name           string   `json:"name"`
	Source         string   `json:"source"`
	State          string   `json:"state"`
	Scripts        int      `json:"scripts"`
	Hostnames      int      `json:"hostnames"`
	HostMappings   int      `json:"host_mappings"`
	URLRewrites    int      `json:"url_rewrites"`
	HeaderRewrites int      `json:"header_rewrites"`
	BodyRewrites   int      `json:"body_rewrites"`
	MapLocals      int      `json:"map_locals"`
	Rules          int      `json:"rules"`
	Warnings       []string `json:"warnings"`
	Error          string   `json:"error,omitempty"`
}

func (m *Module) Status() ModuleStatus {
	state := m.cacheState
	if state == "" {
		state = "loaded"
	}
	return ModuleStatus{
		Name: m.Name, Source: m.source, State: state,
		Scripts: len(m.Scripts), Hostnames: len(m.Hostnames), HostMappings: len(m.Hosts),
		URLRewrites: len(m.URLRewrites), HeaderRewrites: len(m.HeaderRewrites),
		BodyRewrites: len(m.BodyRewrites), MapLocals: len(m.MapLocals), Rules: len(m.Rules),
		Warnings: slices.Clone(m.Warnings),
	}
}

func (e *Engine) Status() Status {
	status := Status{Enabled: true, Modules: make([]ModuleStatus, 0, len(e.options.Modules))}
	for _, module := range e.options.Modules {
		status.Modules = append(status.Modules, module.Status())
	}
	return status
}
