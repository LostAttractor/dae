// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"

	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

// The endpoint owns the intercepted association, while each final HTTP request
// owns its upstream policy and accounting. Auxiliary requests use TCP rules.
func (c *ControlPlane) newMITMQUIC(p *RouteParam, packetPlan mitm.UpstreamPlanner, release func(), routeLease *netproxy.Lease) net.PacketConn {
	ingress, server := newMITMPacketPair(p.Src, p.Dest, routeLease)
	lease := netproxy.DependencyOf(ingress)
	stop := watchAbort(lease, nil, nil, func() {
		_ = server.Close()
	})
	packetPlan = mitmPlannerWithLease(packetPlan, lease)
	host := c.MITMHost()
	plan := c.mitmUpstreamPlanner("tcp", p.Domain, p.Src, p.Dest, *p.routingResult, nil)
	plan = mitmPlannerWithLease(plan, lease)
	flow := plugin.Flow{Host: p.Domain, Port: p.Dest.Port(), Source: p.Src, Destination: p.Dest}
	go func() {
		defer stop()
		if release != nil {
			defer release()
		}
		defer server.Close()
		err := host.ServePacketConn(server, flow, plan, packetPlan)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.WithFields(log.Fields{"event": "http3_connection_failed", "host": flow.Host,
				"source": flow.Source, "destination": flow.Destination}).WithError(resource.RedactError(err)).Debug("MITM HTTP/3 connection failed")
		}
	}()
	return ingress
}
