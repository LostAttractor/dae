// SPDX-License-Identifier: AGPL-3.0-only

package api

import "encoding/json"

// PluginInstanceStatus excludes plugin configuration and its credentials.
// Reports may include explicit script output, such as notifications.
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
