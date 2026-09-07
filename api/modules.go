// SPDX-License-Identifier: AGPL-3.0-only

package api

import "encoding/json"

// SurgeStatus describes the modules of one initialized engine. It does not probe
// traffic or execute scripts; a loaded module may not have matched any request.
type SurgeStatus struct {
	Enabled bool           `json:"enabled"`
	Modules []ModuleStatus `json:"modules"`
}

type ModuleStatus struct {
	Instance       string   `json:"instance,omitempty"`
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

// MITMInstanceStatus intentionally excludes plugin configuration and credentials.
type MITMInstanceStatus struct {
	BufferMemory     *BufferMemoryStatus `json:"buffer_memory,omitempty"`
	ID               string              `json:"id"`
	Type             string              `json:"type"`
	State            string              `json:"state"`
	Scopes           int                 `json:"scopes"`
	DestinationRules int                 `json:"destination_rules"`
	Details          json.RawMessage     `json:"details,omitempty"`
}

// BufferMemoryStatus describes the process-wide MITM body buffer budget.
// Limit, Used and Peak are bytes; Denied counts rejected reservations.
type BufferMemoryStatus struct {
	Limit  int64  `json:"limit"`
	Used   int64  `json:"used"`
	Peak   int64  `json:"peak"`
	Denied uint64 `json:"denied"`
}
