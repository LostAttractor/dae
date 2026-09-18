// SPDX-License-Identifier: AGPL-3.0-only

package api

import "time"

const (
	TrafficHistoryInterval    = 5 * time.Second
	TrafficHistorySampleCount = 12
)

// TrafficCounters contains cumulative payload bytes for both directions.
type TrafficCounters struct {
	UploadBytes   uint64 `json:"upload_bytes"`
	DownloadBytes uint64 `json:"download_bytes"`
}

type TrafficHistory struct {
	UploadBytesPerSecond   []uint64 `json:"upload_bytes_per_second"`
	DownloadBytesPerSecond []uint64 `json:"download_bytes_per_second"`
}

// PathStats is the process-lifetime state and recent traffic history of one
// outbound path.
type PathStats struct {
	ActiveConnections int64 `json:"active_connections"`
	TotalConnections  int64 `json:"total_connections"`
	TrafficCounters
	History TrafficHistory `json:"history"`
}
