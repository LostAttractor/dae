// SPDX-License-Identifier: AGPL-3.0-only

package api

import "time"

// ScriptRunRequest selects an existing task, never a script URL or source text.
type ScriptRunRequest struct {
	Module string `json:"module,omitempty"`
	Script string `json:"script"`
}

// ScriptRunResponse is an acceptance snapshot for daemon execution, not a completed
// result. Run corresponds to Status.Runs.
type ScriptRunResponse struct {
	Instance string           `json:"instance"`
	Module   string           `json:"module"`
	Run      uint64           `json:"run"`
	Status   ScriptTaskStatus `json:"status"`
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
