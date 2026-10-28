// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"net"

	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

// The endpoint owns the intercepted association, while each final HTTP request
// owns its upstream policy and accounting. Auxiliary requests use TCP rules.
// This constructor takes ownership of route, including on admission failure.
func (c *ControlPlane) newMITMQUIC(ctx context.Context, budget *netproxy.PacketBudget, p *RouteParam, route *mitmRoute, routeLease *netproxy.Lease) (net.PacketConn, error) {
	conn, err := budget.Open(ctx, "", func(context.Context, string) (net.PacketConn, error) {
		ingress, server := newMITMPacketPair(p.Src, p.Dest, routeLease)
		lease := netproxy.DependencyOf(ingress)
		stop := watchAbort(lease, nil, nil, func() {
			_ = server.Close()
		})
		packetPlan := mitmPlannerWithLease(route.planner, lease)
		plan := c.mitmUpstreamPlanner("tcp", p.Domain, p.Src, p.Dest, *p.routingResult, nil)
		plan = mitmPlannerWithLease(plan, lease)
		flow := plugin.Flow{Host: p.Domain, Port: p.Dest.Port(), Source: p.Src, Destination: p.Dest, SourceMAC: p.routingResult.Mac}
		go func() {
			defer route.Release()
			defer stop()
			defer server.Close()
			err := route.admission.ServePacketConn(server, flow, plan, packetPlan)
			if err != nil && !errors.Is(err, net.ErrClosed) {
				log.WithFields(log.Fields{"event": "http3_connection_failed", "host": flow.Host,
					"source": flow.Source, "destination": flow.Destination}).WithError(resource.RedactError(err)).Debug("MITM HTTP/3 connection failed")
			}
		}()
		return ingress, nil
	})
	if err != nil {
		route.Release()
	}
	return conn, err
}
