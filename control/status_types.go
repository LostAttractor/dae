/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	jsonv1 "encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

const StatusSchemaVersion = 2

type NetworkValues[T any] [common.NetworkTypeCount]T

type StatusSnapshot struct {
	Schema       int                            `json:"schema"`
	Version      string                         `json:"version"`
	StartedAt    time.Time                      `json:"started_at"`
	LastReloadAt time.Time                      `json:"last_reload_at"`
	Stats        stats.PathStats                `json:"stats"`
	Networks     NetworkValues[stats.PathStats] `json:"networks"`
	Tables       []TableUsage                   `json:"tables"`
	Groups       []GroupStatus                  `json:"groups"`
}

func decodeStatusObject(data []byte, value any) error {
	return jsonv2.Unmarshal(data, value,
		jsonv1.FormatDurationAsNano(true), jsonv2.RejectUnknownMembers(true))
}

func (s *StatusSnapshot) UnmarshalJSON(data []byte) error {
	type plain StatusSnapshot
	*s = StatusSnapshot{}
	fields := struct {
		*plain
		Stats *stats.PathStats `json:"stats"`
	}{plain: (*plain)(s)}
	if err := decodeStatusObject(data, &fields); err != nil {
		return err
	}
	if fields.Stats == nil {
		return errors.New("status response is missing stats")
	}
	s.Stats = *fields.Stats
	return nil
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
	Name               string                         `json:"name"`
	TargetKind         string                         `json:"target_kind"`
	Policy             string                         `json:"policy"`
	Critical           bool                           `json:"critical"`
	ChecksConnectivity bool                           `json:"checks_connectivity"`
	Connectivity       stats.GroupState               `json:"connectivity,omitempty"`
	Availability       stats.GroupAvailability        `json:"availability"`
	Stats              stats.PathStats                `json:"stats"`
	Networks           NetworkValues[stats.PathStats] `json:"networks"`
	SelectedNodeIDs    NetworkValues[string]          `json:"selected_node_ids"`
	Nodes              []NodeStatus                   `json:"nodes"`
}

func (s *GroupStatus) UnmarshalJSON(data []byte) error {
	type plain GroupStatus
	*s = GroupStatus{}
	fields := struct {
		*plain
		Critical           *bool            `json:"critical"`
		ChecksConnectivity *bool            `json:"checks_connectivity"`
		Stats              *stats.PathStats `json:"stats"`
	}{plain: (*plain)(s)}
	if err := decodeStatusObject(data, &fields); err != nil {
		return err
	}
	if fields.Critical == nil {
		return errors.New("group status is missing critical")
	}
	if fields.ChecksConnectivity == nil {
		return errors.New("group status is missing checks_connectivity")
	}
	if fields.Stats == nil {
		return errors.New("group status is missing stats")
	}
	s.Critical = *fields.Critical
	s.ChecksConnectivity = *fields.ChecksConnectivity
	s.Stats = *fields.Stats
	return nil
}

type NodeStatus struct {
	ID                 string                                    `json:"id"`
	Name               string                                    `json:"name"`
	Subtag             string                                    `json:"subtag"`
	Protocol           string                                    `json:"protocol"`
	Address            string                                    `json:"address"`
	Annotation         *NodeAnnotationStatus                     `json:"annotation,omitempty"`
	ChecksConnectivity bool                                      `json:"checks_connectivity"`
	CheckAsync         bool                                      `json:"check_async,omitempty"`
	Session            string                                    `json:"session,omitempty"`
	Healthy            bool                                      `json:"healthy"`
	ConfirmingFailure  bool                                      `json:"confirming_failure"`
	Availability       stats.Availability                        `json:"availability"`
	Latency            *dialer.LatencyStats                      `json:"latency,omitempty"`
	Support            NetworkValues[dialer.NetworkSupportState] `json:"support"`
	Stats              stats.PathStats                           `json:"stats"`
}

func (s *NodeStatus) UnmarshalJSON(data []byte) error {
	type plain NodeStatus
	*s = NodeStatus{}
	fields := struct {
		*plain
		ChecksConnectivity *bool            `json:"checks_connectivity"`
		Healthy            *bool            `json:"healthy"`
		ConfirmingFailure  *bool            `json:"confirming_failure"`
		Stats              *stats.PathStats `json:"stats"`
	}{plain: (*plain)(s)}
	if err := decodeStatusObject(data, &fields); err != nil {
		return err
	}
	if fields.ChecksConnectivity == nil {
		return errors.New("node status is missing checks_connectivity")
	}
	if fields.Healthy == nil {
		return errors.New("node status is missing healthy")
	}
	if fields.ConfirmingFailure == nil {
		return errors.New("node status is missing confirming_failure")
	}
	if fields.Stats == nil {
		return errors.New("node status is missing stats")
	}
	s.ChecksConnectivity = *fields.ChecksConnectivity
	s.Healthy = *fields.Healthy
	s.ConfirmingFailure = *fields.ConfirmingFailure
	s.Stats = *fields.Stats
	return nil
}

type NodeAnnotationStatus struct {
	AddLatency          string `json:"add_latency,omitempty"`
	Priority            *int   `json:"priority,omitempty"`
	PriorityConditional bool   `json:"priority_conditional,omitempty"`
}
