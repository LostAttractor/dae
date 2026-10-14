// SPDX-License-Identifier: AGPL-3.0-only

package api

import "time"

// Operation identifies one daemon-owned configuration transaction. IDs are
// unique across daemon restarts; polling never aliases a later transaction.
type Operation struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	State      string    `json:"state"`
	Trigger    string    `json:"trigger"`
	QueuedAt   time.Time `json:"queued_at"`
	StartedAt  time.Time `json:"started_at,omitzero"`
	FinishedAt time.Time `json:"finished_at,omitzero"`
	Progress   string    `json:"progress,omitempty"`
	Result     string    `json:"result,omitempty"`
	Error      string    `json:"error,omitempty"`
}

type OperationRequest struct {
	Kind        string `json:"kind"`
	Abort       bool   `json:"abort,omitempty"`
	ExpectedPID int    `json:"expected_pid,omitempty"`
}
