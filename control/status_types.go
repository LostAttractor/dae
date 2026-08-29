/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

const GroupRecentBucketCount = stats.GroupStateBucketCount

type HealthStatus string

const (
	HealthHealthy  HealthStatus = "healthy"
	HealthWarning  HealthStatus = "warning"
	HealthDegraded HealthStatus = "degraded"
)

type StatusSnapshot struct {
	Version      string                    `json:"version"`
	Health       HealthStatus              `json:"health"` // aggregate connectivity of visible groups
	StartedAt    time.Time                 `json:"started_at"`
	LastReloadAt *time.Time                `json:"last_reload_at,omitempty"`
	ActiveConns  int64                     `json:"active_conns"`
	TotalConns   int64                     `json:"total_conns"`
	Traffic      TrafficStatus             `json:"traffic"`
	Networks     []NetworkConnectionStatus `json:"networks"`
	Tables       []TableUsage              `json:"tables"`
	Groups       []GroupStatus             `json:"groups"`
}

type NetworkConnectionStatus struct {
	Network     string `json:"network"`
	ActiveConns int64  `json:"active_conns"`
	TotalConns  int64  `json:"total_conns"`
}

// TableUsage is the fill level of one capacity-limited DNS/domain table.
type TableUsage struct {
	Name      string               `json:"name"`
	Used      int                  `json:"used"`
	Limit     int                  `json:"limit"`
	Breakdown *TableUsageBreakdown `json:"breakdown,omitempty"`
}

type TableUsageBreakdown struct {
	Live     int    `json:"live"`
	Retained int    `json:"retained"`
	LimitGC  uint64 `json:"limit_gc"`
}

type GroupStatus struct {
	Name         string                   `json:"name"`
	TargetKind   string                   `json:"target_kind"`
	Policy       string                   `json:"policy"`
	Health       HealthStatus             `json:"health"`                 // operational impact after applying group criticality
	Connectivity *GroupConnectivityStatus `json:"connectivity,omitempty"` // nil when the group has no connectivity checks
	Networks     []NetworkStatus          `json:"networks"`
	Nodes        []NodeStatus             `json:"nodes"`
	ActiveConns  int64                    `json:"active_conns"`
	Traffic      TrafficStatus            `json:"traffic"`
}

type GroupConnectivityStatus struct {
	State       GroupConnectivityState `json:"state"`
	UpRatio     *float64               `json:"up_ratio"`     // process-lifetime ratio; nil before the first observation
	UpRatio24h  *float64               `json:"up_ratio_24h"` // trailing 24-hour ratio; nil before the first observation
	Recent      GroupRecentStatus      `json:"recent"`
	UpSince     *time.Time             `json:"up_since,omitempty"`
	LastFailure *FailureStatus         `json:"last_failure,omitempty"`
}

type GroupRecentStatus struct {
	WindowSeconds int64              `json:"window_seconds"`
	Buckets       []GroupBucketState `json:"buckets"`
}

type NetworkStatus struct {
	Network      string               `json:"network"`
	SupportState NetworkSupportStatus `json:"support_state"`
	Selected     *SelectedNodeStatus  `json:"selected,omitempty"`
	ActiveConns  int64                `json:"active_conns"`
	TotalConns   int64                `json:"total_conns"`
}

type SelectedNodeStatus struct {
	Index int `json:"index"`
}

type SessionStatus struct {
	State SessionState `json:"state"`
	Seq   uint64       `json:"seq"`
	Error string       `json:"error,omitempty"`
}

type LatencyStatus struct {
	LastMs          float64 `json:"last_ms"`
	Average10Ms     float64 `json:"average_10_ms"`
	MovingAverageMs float64 `json:"moving_average_ms"`
	Average10Failed bool    `json:"average_10_failed"`
}

type NodeNetworkStatus struct {
	Network      string               `json:"network"`
	SupportState NetworkSupportStatus `json:"support_state"`
}

type FailureStatus struct {
	StartedAt  time.Time `json:"started_at"`
	DurationMs int64     `json:"duration_ms"`
}

type NodeHealthState string
type SessionState string
type NetworkSupportStatus string
type GroupConnectivityState string
type GroupBucketState string

const (
	NodeHealthUnknown    NodeHealthState = "unknown"
	NodeHealthHealthy    NodeHealthState = "healthy"
	NodeHealthConfirming NodeHealthState = "confirming"
	NodeHealthUnhealthy  NodeHealthState = "unhealthy"

	GroupConnectivityAvailable   GroupConnectivityState = "available"
	GroupConnectivityChecking    GroupConnectivityState = "checking"
	GroupConnectivityUnavailable GroupConnectivityState = "unavailable"

	GroupBucketUnknown     GroupBucketState = "unknown"
	GroupBucketAvailable   GroupBucketState = "available"
	GroupBucketUnavailable GroupBucketState = "unavailable"

	SessionDisconnected SessionState = "disconnected"
	SessionConnecting   SessionState = "connecting"
	SessionConnected    SessionState = "connected"
	SessionClosed       SessionState = "closed"

	NetworkSupportUnknown     NetworkSupportStatus = "unknown"
	NetworkSupportConfirmed   NetworkSupportStatus = "confirmed"
	NetworkSupportUnsupported NetworkSupportStatus = "unsupported"
)

type NodeStatus struct {
	ID                      string                `json:"id"`
	Name                    string                `json:"name"`
	Subtag                  string                `json:"subtag"`
	Protocol                string                `json:"protocol"`
	Address                 string                `json:"address"`
	Hops                    []dialer.Hop          `json:"hops,omitempty"`
	Annotation              *NodeAnnotationStatus `json:"annotation,omitempty"`
	CheckAsync              bool                  `json:"check_async,omitempty"`
	Session                 *SessionStatus        `json:"session,omitempty"`
	Health                  *NodeHealthStatus     `json:"health,omitempty"`
	Networks                []NodeNetworkStatus   `json:"networks"`
	LastConnectionFailureAt *time.Time            `json:"last_connection_failure_at,omitempty"`
	ActiveConns             int64                 `json:"active_conns"`
	TotalConns              int64                 `json:"total_conns"`
	Traffic                 TrafficStatus         `json:"traffic"`
}

type TrafficStatus struct {
	WindowSeconds          int64  `json:"window_seconds"`
	UploadBytesPerSecond   uint64 `json:"upload_bytes_per_second"`
	DownloadBytesPerSecond uint64 `json:"download_bytes_per_second"`
	UploadBytes            uint64 `json:"upload_bytes"`
	DownloadBytes          uint64 `json:"download_bytes"`
}

func (s *TrafficStatus) UnmarshalJSON(data []byte) error {
	var fields struct {
		WindowSeconds          *int64  `json:"window_seconds"`
		UploadBytesPerSecond   *uint64 `json:"upload_bytes_per_second"`
		DownloadBytesPerSecond *uint64 `json:"download_bytes_per_second"`
		UploadBytes            *uint64 `json:"upload_bytes"`
		DownloadBytes          *uint64 `json:"download_bytes"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fields); err != nil {
		return err
	}
	if fields.WindowSeconds == nil {
		return fmt.Errorf("traffic rate is missing window_seconds")
	}
	if fields.UploadBytesPerSecond == nil {
		return fmt.Errorf("traffic rate is missing upload_bytes_per_second")
	}
	if fields.DownloadBytesPerSecond == nil {
		return fmt.Errorf("traffic rate is missing download_bytes_per_second")
	}
	if fields.UploadBytes == nil {
		return fmt.Errorf("traffic is missing upload_bytes")
	}
	if fields.DownloadBytes == nil {
		return fmt.Errorf("traffic is missing download_bytes")
	}
	*s = TrafficStatus{
		WindowSeconds:          *fields.WindowSeconds,
		UploadBytesPerSecond:   *fields.UploadBytesPerSecond,
		DownloadBytesPerSecond: *fields.DownloadBytesPerSecond,
		UploadBytes:            *fields.UploadBytes,
		DownloadBytes:          *fields.DownloadBytes,
	}
	return nil
}

type NodeAnnotationStatus struct {
	AddLatency          string `json:"add_latency,omitempty"`
	Priority            *int   `json:"priority,omitempty"`
	PriorityConditional bool   `json:"priority_conditional,omitempty"`
}

type NodeHealthStatus struct {
	State              NodeHealthState `json:"state"`
	Latency            *LatencyStatus  `json:"latency,omitempty"`
	UpRatio            float64         `json:"up_ratio"`
	UpRatio24h         float64         `json:"up_ratio_24h"`
	HealthySince       *time.Time      `json:"healthy_since,omitempty"`
	Failure            *FailureStatus  `json:"failure,omitempty"`
	LastCheckAt        *time.Time      `json:"last_check_at,omitempty"`
	ChecksTotal        int64           `json:"checks_total"`
	ChecksFailed       int64           `json:"checks_failed"`
	ChecksTotal24h     int64           `json:"checks_total_24h"`
	ChecksFailed24h    int64           `json:"checks_failed_24h"`
	ChecksSinceHealthy int64           `json:"checks_since_healthy"`
}
