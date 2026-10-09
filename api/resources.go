// SPDX-License-Identifier: AGPL-3.0-only

package api

import "time"

type ResourceRefreshStatus struct {
	Run        uint64    `json:"run"`
	State      string    `json:"state"`
	Trigger    string    `json:"trigger,omitempty"`
	StartedAt  time.Time `json:"started_at,omitzero"`
	FinishedAt time.Time `json:"finished_at,omitzero"`
	NextCheck  time.Time `json:"next_check,omitzero"`
	Result     string    `json:"result,omitempty"`
	Error      string    `json:"error,omitempty"`
}
