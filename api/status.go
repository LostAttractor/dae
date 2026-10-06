/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package api

import "time"

const StatusSchemaVersion = 12

type NetworkValues[T any] [NetworkTypeCount]T

type StatusSnapshot struct {
	Schema                    int                      `json:"schema"`
	Version                   string                   `json:"version"`
	StartedAt                 time.Time                `json:"started_at"`
	LastReloadAt              time.Time                `json:"last_reload_at"`
	Stats                     PathStats                `json:"stats"`
	DirectFallbackConnections int64                    `json:"direct_fallback_connections"`
	Networks                  NetworkValues[PathStats] `json:"networks"`
	Tables                    []TableUsage             `json:"tables"`
	Groups                    []GroupStatus            `json:"groups"`
	Plugins                   []PluginInstanceStatus   `json:"plugins,omitempty"`
}

// TableUsage describes a domain table. Limit zero means no capacity limit.
type TableUsage struct {
	Name       string               `json:"name"`
	Used       int                  `json:"used"` // IPs for domain-kernel; domain-IP pairs for domain-registry
	Limit      int                  `json:"limit"`
	Candidates int                  `json:"candidates,omitempty"`
	Breakdown  *TableUsageBreakdown `json:"breakdown,omitempty"`
}

type TableUsageBreakdown struct {
	Domains int    `json:"domains"` // distinct retained domain names
	IPs     int    `json:"ips"`     // distinct retained IPs across all domains
	IPv4    int    `json:"ipv4"`    // distinct IPv4 addresses, not pairs
	IPv6    int    `json:"ipv6"`    // distinct IPv6 addresses, not pairs
	GC      uint64 `json:"gc"`      // pairs removed by time-based GC; cumulative across reload
}

type GroupStatus struct {
	Name               string                   `json:"name"`
	TargetKind         string                   `json:"target_kind"`
	Policy             string                   `json:"policy"`
	Critical           bool                     `json:"critical"`
	ChecksConnectivity bool                     `json:"checks_connectivity"`
	CheckAsync         bool                     `json:"check_async,omitempty"`
	Connectivity       GroupState               `json:"connectivity,omitempty"`
	Availability       GroupAvailability        `json:"availability"`
	Stats              PathStats                `json:"stats"`
	Networks           NetworkValues[PathStats] `json:"networks"`
	SelectedNodeIDs    NetworkValues[string]    `json:"selected_node_ids"`
	Nodes              []NodeStatus             `json:"nodes"`
}

type NodeStatus struct {
	Revision           uint64                             `json:"revision"`
	ObservedSessionSeq uint64                             `json:"observed_session_seq"`
	SessionDetail      *SessionStatus                     `json:"session_detail,omitempty"`
	Recovery           RecoverySnapshot                   `json:"recovery"`
	Failure            *FailureSnapshot                   `json:"failure,omitempty"`
	ID                 string                             `json:"id"`
	Name               string                             `json:"name"`
	Subtag             string                             `json:"subtag"`
	Protocol           string                             `json:"protocol"`
	Address            string                             `json:"address"`
	Annotation         *NodeAnnotationStatus              `json:"annotation,omitempty"`
	Egress             *NodeEgress                        `json:"egress,omitempty"`
	ChecksConnectivity bool                               `json:"checks_connectivity"`
	InitialCheckDone   bool                               `json:"-"` // Current runtime only, for startup logs.
	Healthy            bool                               `json:"healthy"`
	Dormant            bool                               `json:"dormant,omitzero"`
	ConfirmingFailure  bool                               `json:"confirming_failure"`
	Availability       Availability                       `json:"availability"`
	Latency            *LatencyStats                      `json:"latency,omitempty"`
	Selection          *SelectionStatus                   `json:"selection,omitempty"`
	Support            NetworkValues[NetworkSupportState] `json:"support"`
	Stats              PathStats                          `json:"stats"`
}

type SessionStatus struct {
	State            string      `json:"state"`
	Seq              uint64      `json:"seq"`
	ReadinessVersion uint64      `json:"readiness_version"`
	Resource         ResourceRef `json:"resource"`
	EpisodeID        uint64      `json:"episode_id"`
	Accepting        bool        `json:"accepting"`
	UsableCapacity   int         `json:"usable_capacity"`
	RecoveryRequired bool        `json:"recovery_required"`
}

type NodeAnnotationStatus struct {
	AddLatency          string `json:"add_latency,omitempty"`
	Priority            *int   `json:"priority,omitempty"`
	PriorityConditional bool   `json:"priority_conditional,omitempty"`
}

// NodeEgress describes the local socket to the first proxy. IPVersion is
// independent of Support, which describes the proxy's destination capabilities.
type NodeEgress struct {
	IPVersion int    `json:"ipversion"`
	Mark      uint32 `json:"mark"`
	Interface string `json:"interface,omitempty"`
}
