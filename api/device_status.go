// SPDX-License-Identifier: AGPL-3.0-only

package api

import "time"

// DeviceStatus describes the requesting LAN device. Traffic has the same
// upstream payload/connection semantics as global PathStats, excluding kernel
// passthrough, local responses and daemon-originated work.
type DeviceStatus struct {
	Device                    DeviceState              `json:"device"`
	Scope                     string                   `json:"scope"`
	StartedAt                 time.Time                `json:"started_at"`
	Stats                     PathStats                `json:"stats"`
	Networks                  NetworkValues[PathStats] `json:"networks"`
	DirectFallbackConnections int64                    `json:"direct_fallback_connections"`
	Outbounds                 []DeviceOutboundStatus   `json:"outbounds"`
}

type DeviceOutboundStatus struct {
	Name  string    `json:"name"`
	Stats PathStats `json:"stats"`
}
