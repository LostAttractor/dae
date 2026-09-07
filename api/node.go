// SPDX-License-Identifier: AGPL-3.0-only

package api

import "time"

// LatencyStats is a coherent view of the latency samples of a dialer.
type LatencyStats struct {
	Last            time.Duration `json:"last"`
	Avg10           time.Duration `json:"average_10"`
	MovingAvg       time.Duration `json:"moving_average"`
	Avg10HasFailure bool          `json:"average_10_failed"`
}

// NetworkSupportState describes protocol/remote capability, not current
// reachability. Confirmed modes share the dialer's canonical health result.
type NetworkSupportState string

const (
	NetworkSupportUnknown     NetworkSupportState = "unknown"
	NetworkSupportConfirmed   NetworkSupportState = "confirmed"
	NetworkSupportUnsupported NetworkSupportState = "unsupported"
)
