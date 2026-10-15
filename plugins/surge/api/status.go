// SPDX-License-Identifier: AGPL-3.0-only

// Package api defines the Surge plugin report carried in a host instance report.
package api

import (
	"time"

	"github.com/daeuniverse/dae/api"
)

// SurgeStatus describes the modules and cached runtime state of one initialized
// engine. It does not probe traffic or execute scripts; a loaded module may not
// have matched any request.
type SurgeStatus struct {
	Enabled       bool                 `json:"enabled"`
	Modules       []ModuleStatus       `json:"modules"`
	Runtimes      []SurgeRuntimeStatus `json:"runtimes,omitempty"`
	Notifications []SurgeNotification  `json:"notifications,omitempty"`
}

// Each Surge instance reports its selected backend. Clients add Instance when
// combining reports, as they do for modules and notifications.
type SurgeRuntimeStatus struct {
	Instance string               `json:"instance,omitempty"`
	Backend  string               `json:"backend"`
	NodeJS   *NodeJSRuntimeStatus `json:"nodejs,omitempty"`
}

// NodeJSRuntimeStatus contains pool-lifetime counters and cached process memory.
// Memory sums cover MemorySampledWorkers; MemorySampledAt is the oldest included
// sample. A missing sample is not evidence of zero memory usage.
type NodeJSRuntimeStatus struct {
	Active               int       `json:"active"`
	Idle                 int       `json:"idle"`
	Limit                int       `json:"limit"`
	Started              uint64    `json:"started"`
	Reused               uint64    `json:"reused"`
	StartFailures        uint64    `json:"start_failures"`
	IdleReaped           uint64    `json:"idle_reaped"`
	Discarded            uint64    `json:"discarded"`
	RSSBytes             uint64    `json:"rss_bytes"`
	PSSBytes             uint64    `json:"pss_bytes"`
	MemorySampledWorkers int       `json:"memory_sampled_workers"`
	MemorySampledAt      time.Time `json:"memory_sampled_at,omitzero"`
	IdleTimeoutSeconds   float64   `json:"idle_timeout_seconds"`
}

// SurgeNotification is explicit script output, independent of runtime success.
// Each script (module/name/type) retains up to 50 entries within an instance-wide
// 1 MiB conservative JSON budget; longer histories are trimmed first.
// IDs are per instance, increase in arrival order and reset on reload.
type SurgeNotification struct {
	Instance   string    `json:"instance,omitempty"` // Added by clients combining reports.
	ID         uint64    `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	Module     string    `json:"module"`
	Script     string    `json:"script"`
	ScriptType string    `json:"script_type"`
	Title      string    `json:"title"`
	Subtitle   string    `json:"subtitle"`
	Body       string    `json:"body"`
	Truncated  bool      `json:"truncated,omitzero"`
}

type ModuleStatus struct {
	Instance       string                 `json:"instance,omitempty"`
	Name           string                 `json:"name"`
	Source         string                 `json:"source"`
	State          string                 `json:"state"`
	Scripts        int                    `json:"scripts"`
	Hostnames      int                    `json:"hostnames"`
	HostMappings   int                    `json:"host_mappings"`
	URLRewrites    int                    `json:"url_rewrites"`
	HeaderRewrites int                    `json:"header_rewrites"`
	BodyRewrites   int                    `json:"body_rewrites"`
	MapLocals      int                    `json:"map_locals"`
	Rules          int                    `json:"rules"`
	Warnings       []string               `json:"warnings"`
	Error          string                 `json:"error,omitempty"`
	Tasks          []api.ScriptTaskStatus `json:"tasks,omitempty"`
}
