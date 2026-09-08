// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"
	"net/netip"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/plugin"
	log "github.com/sirupsen/logrus"
)

// The endpoint owns the intercepted association, while each final HTTP request
// owns its upstream policy and accounting. Auxiliary requests use TCP rules.
func (c *ControlPlane) newMITMQUIC(p *RouteParam, packetPlan mitm.UpstreamPlanner, release func()) net.PacketConn {
	ingress, server := newMITMPacketPair(p.Src, p.Dest)
	host := c.mitmHost
	plan := c.mitmUpstreamPlanner("tcp", p.Domain, p.Src, p.Dest, *p.routingResult, nil)
	flow := plugin.Flow{Host: p.Domain, Port: p.Dest.Port(), Source: p.Src, Destination: p.Dest}
	go func() {
		if release != nil {
			defer release()
		}
		defer server.Close()
		err := host.ServePacketConn(server, flow, plan, packetPlan)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.WithFields(log.Fields{"event": "http3_connection_failed", "host": flow.Host,
				"source": flow.Source, "destination": flow.Destination}).WithError(err).Warn("mitm")
		}
	}()
	return ingress
}

func (c *ControlPlane) mitmUDPEndpointKey(source, destination netip.AddrPort, result *bpfRoutingResult, sniffed *packetSniff) udpEndpointKey {
	host := sniffed.domain
	if host == "" {
		host = destination.Addr().String()
	}
	scoped := result.CaptureFlags&(captureDestination|captureHTTP) != 0 ||
		sniffed.http3 && c.mitmHost != nil && c.mitmHost.Match(host, destination.Port()) != mitm.HTTPBypass
	return c.udpEndpoints.keyForPacket(source, destination, result.Ifindex, scoped)
}
