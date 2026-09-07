// SPDX-License-Identifier: AGPL-3.0-only
package api

import (
	"errors"
	"net/netip"
)

// SelectorStore owns live selections and their persistent overrides.
type SelectorStore interface {
	Selectors() []SelectorState
	Select(group, node, source string) (SelectorState, error)
}

// DeviceStore owns membership, MITM overrides, and atomic persistence.
type DeviceStore interface {
	HasClientSet(string) bool
	DeviceState(netip.Addr, [6]byte) DeviceState
	UpdateClientSet(string, netip.Addr, [6]byte, bool) (DeviceState, error)
	UpdateMITM(netip.Addr, [6]byte, *bool) (DeviceState, error)
}

var (
	ErrSelectorNotFound = errors.New("selector group not found")
	ErrSelectorNode     = errors.New("node_id is not a path in this selector")
)

type ClientSetState struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Joined      bool   `json:"joined"`
}

type MITMState struct {
	Enabled       bool   `json:"enabled"`
	Override      *bool  `json:"override"`
	CAFingerprint string `json:"ca_fingerprint"`
}

type DeviceState struct {
	SourceIP string           `json:"source_ip"`
	MAC      string           `json:"mac"`
	Sets     []ClientSetState `json:"sets"`
	MITM     *MITMState       `json:"mitm,omitempty"`
}

type SelectorNode struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Healthy   bool     `json:"healthy"`
	Checking  bool     `json:"checking"`
	LatencyMS *float64 `json:"latency_ms,omitempty"`
}

type SelectorState struct {
	Name          string         `json:"name"`
	DefaultNodeID string         `json:"default_node_id"`
	NodeID        string         `json:"node_id"`
	Overridden    bool           `json:"overridden"`
	Nodes         []SelectorNode `json:"nodes"`
}
