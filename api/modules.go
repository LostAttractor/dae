// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"time"
)

// SurgeStatus describes the modules of one initialized engine. It does not probe
// traffic or execute scripts; a loaded module may not have matched any request.
type SurgeStatus struct {
	Enabled       bool                `json:"enabled"`
	Modules       []ModuleStatus      `json:"modules"`
	Notifications []SurgeNotification `json:"notifications,omitempty"`
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
	Instance       string             `json:"instance,omitempty"`
	Name           string             `json:"name"`
	Source         string             `json:"source"`
	State          string             `json:"state"`
	Scripts        int                `json:"scripts"`
	Hostnames      int                `json:"hostnames"`
	HostMappings   int                `json:"host_mappings"`
	URLRewrites    int                `json:"url_rewrites"`
	HeaderRewrites int                `json:"header_rewrites"`
	BodyRewrites   int                `json:"body_rewrites"`
	MapLocals      int                `json:"map_locals"`
	Rules          int                `json:"rules"`
	Warnings       []string           `json:"warnings"`
	Error          string             `json:"error,omitempty"`
	Tasks          []ScriptTaskStatus `json:"tasks,omitempty"`
}

// ScriptTaskStatus reports background execution outcomes, not application-level success.
// LastError is a bounded category, never a script exception or response body.
type ScriptTaskStatus struct {
	Name           string    `json:"name"`
	Type           string    `json:"type"`
	CronExp        string    `json:"cronexp,omitempty"`
	Timezone       string    `json:"timezone,omitempty"`
	TimeoutSeconds float64   `json:"timeout_seconds"`
	State          string    `json:"state"`
	NextRun        time.Time `json:"next_run,omitzero"`
	LastStartedAt  time.Time `json:"last_started_at,omitzero"`
	LastFinishedAt time.Time `json:"last_finished_at,omitzero"`
	LastDurationMS int64     `json:"last_duration_ms"`
	LastResult     string    `json:"last_result,omitempty"`
	LastTrigger    string    `json:"last_trigger,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
	Runs           uint64    `json:"runs"`
	Failures       uint64    `json:"failures"`
	Skipped        uint64    `json:"skipped"`
}

// PluginInstanceStatus excludes plugin configuration and its credentials.
// Reports may include explicit script output, such as Surge notifications.
type PluginInstanceStatus struct {
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
