// SPDX-License-Identifier: AGPL-3.0-only

package api

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

type SelectorsResponse struct {
	Selectors    []SelectorState `json:"selectors"`
	AdminEnabled bool            `json:"admin_enabled"`
	// AuthMode is api_key (Bearer/session), lan (verified direct LAN), or unix.
	AuthMode string `json:"auth_mode"`
}
type SelectNodeRequest struct {
	NodeID string `json:"node_id"`
}
type SetMITMRequest struct {
	Enabled *bool `json:"enabled"`
}
type Certificate struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
}
