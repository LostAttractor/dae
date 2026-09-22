// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"slices"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/internal/apiserver"
	log "github.com/sirupsen/logrus"
)

// Probe reuses the bounded checker for any instantiated, checked outbound.
// The API owner keeps this plane alive until the request has returned.
func (c *ControlPlane) Probe(request api.ProbeRequest, source string) (api.ProbeResponse, error) {
	group := c.outboundGroup(request.Outbound)
	if group == nil {
		return api.ProbeResponse{}, apiserver.ErrProbeOutbound
	}
	if !group.ChecksConnectivity() {
		return api.ProbeResponse{}, apiserver.ErrProbeUnsupported
	}
	if request.NodeID != "" && !slices.ContainsFunc(group.Dialers, func(d *dialer.Dialer) bool { return d.StatsID() == request.NodeID }) {
		return api.ProbeResponse{}, apiserver.ErrProbeNode
	}
	response := api.ProbeResponse{Outbound: group.Name, NodeIDs: make([]string, 0, len(group.Dialers))}
	for _, d := range group.Dialers {
		if request.NodeID == "" || d.StatsID() == request.NodeID {
			d.RequestManualCheck()
			response.NodeIDs = append(response.NodeIDs, d.StatsID())
		}
	}
	log.WithFields(log.Fields{"event": "outbound_probe", "outbound": group.Name, "node_id": request.NodeID, "source_ip": source}).Debug("Connectivity probe requested")
	return response, nil
}
