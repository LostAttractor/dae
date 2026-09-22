// SPDX-License-Identifier: AGPL-3.0-only

package api

// ProbeRequest targets configured outbound paths, never an arbitrary URL.
// An omitted or empty NodeID requests one round for every path in the outbound.
type ProbeRequest struct {
	Outbound string `json:"outbound"`
	NodeID   string `json:"node_id,omitempty"`
}

// ProbeResponse acknowledges work accepted by the existing connectivity checker.
// Acceptance includes coalescing with a queued/running check; it is not a health
// result and does not change selection or continuous monitoring configuration.
type ProbeResponse struct {
	Outbound string   `json:"outbound"`
	NodeIDs  []string `json:"node_ids"`
}
