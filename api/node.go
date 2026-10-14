// SPDX-License-Identifier: AGPL-3.0-only

package api

import "time"

// LatencyStats is a coherent view of the latency samples of a dialer.
type LatencyStats struct {
	Last      time.Duration `json:"last"`
	Avg10     time.Duration `json:"average_10"`
	MovingAvg time.Duration `json:"moving_average"`
}

// SelectionStatus distinguishes observations from the group's scheduling policy.
type SelectionStatus struct {
	Tracking        string        `json:"tracking"`
	Degraded        bool          `json:"degraded"`
	RecoveryElapsed time.Duration `json:"recovery_elapsed"`
	FailureRecovery time.Duration `json:"failure_recovery"`
	Priority        int           `json:"priority"`
	Score           time.Duration `json:"score"`
	MeasuredAt      time.Time     `json:"measured_at,omitzero"`
}

// NetworkSupportState describes protocol/remote capability, not current
// reachability. Confirmed modes share the dialer's canonical health result.
type NetworkSupportState string

const (
	NetworkSupportUnknown     NetworkSupportState = "unknown"
	NetworkSupportConfirmed   NetworkSupportState = "confirmed"
	NetworkSupportUnsupported NetworkSupportState = "unsupported"
)
