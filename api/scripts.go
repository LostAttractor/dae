// SPDX-License-Identifier: AGPL-3.0-only

package api

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
