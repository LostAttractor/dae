// SPDX-License-Identifier: AGPL-3.0-only

package api

import "time"

// Availability is a point-in-time view of the uptime of a node or group.
type Availability struct {
	Seen                 bool          `json:"seen"`
	Alive                bool          `json:"alive"`
	AliveSince           time.Time     `json:"alive_since"`
	LastFailureStartedAt time.Time     `json:"last_failure_started_at"`
	LastFailureDuration  time.Duration `json:"last_failure_duration"`
	LastCheckAt          time.Time     `json:"last_check_at"`
	LastConnFailAt       time.Time     `json:"last_connection_failure_at"`
	UpRatio              float64       `json:"up_ratio"`

	ChecksTotal      int64 `json:"checks_total"`
	ChecksFailed     int64 `json:"checks_failed"`
	ChecksSinceAlive int64 `json:"checks_since_alive"`

	Recent24h AvailabilityWindow `json:"recent_24h"`
}

// GroupAvailability adds current and recent aggregate connectivity states to
// the time-weighted availability statistics of an outbound group.
type GroupAvailability struct {
	Availability
	Recent GroupStateWindow `json:"recent"`
}

// AvailabilityWindow summarizes availability over a bounded observation
// window. UpRatio is time-weighted, while check counters count discrete health
// checks in the same window.
type AvailabilityWindow struct {
	UpRatio      float64 `json:"up_ratio"`
	ChecksTotal  int64   `json:"checks_total"`
	ChecksFailed int64   `json:"checks_failed"`
}

const (
	GroupStateWindowDuration = time.Hour
	GroupStateBucketCount    = 10
)

// GroupState describes the aggregate connectivity of a checked outbound group.
type GroupState string

const (
	GroupStateAvailable   GroupState = "available"
	GroupStateChecking    GroupState = "checking"
	GroupStateUnavailable GroupState = "unavailable"
)

type GroupHistoryState string

const (
	GroupHistoryUnknown     GroupHistoryState = "unknown"
	GroupHistoryAvailable   GroupHistoryState = "available"
	GroupHistoryUnavailable GroupHistoryState = "unavailable"
)

type GroupStateWindow struct {
	States []GroupHistoryState `json:"states"`
}
