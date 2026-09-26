// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net"
	"net/netip"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

// Each rewritten UDP association owns a socket and a fixed destination. This
// keeps replies unambiguous even if multiple original IPs map to the same peer.
type destinationPacketConn struct {
	net.PacketConn
	original, target netip.AddrPort
}

func (c *destinationPacketConn) WriteTo(data []byte, _ net.Addr) (int, error) {
	return c.PacketConn.WriteTo(data, net.UDPAddrFromAddrPort(c.target))
}

func (c *destinationPacketConn) ReadFrom(data []byte) (int, net.Addr, error) {
	for {
		n, from, err := c.PacketConn.ReadFrom(data)
		if err != nil {
			return n, from, err
		}
		if common.ConvergeAddrPort(addrPortOf(from)) == c.target {
			return n, net.UDPAddrFromAddrPort(c.original), nil
		}
	}
}

func (c *destinationPacketConn) DependencyLease() *netproxy.Lease {
	return netproxy.DependencyOf(c.PacketConn)
}

// Rewritten destinations need separate sockets to distinguish replies when
// several original addresses map to one server. They share their source's
// route, node, idle timer and termination; none performs another selection.
func (ue *UdpEndpoint) socketTarget(dst netip.AddrPort) (netip.AddrPort, error) {
	if target, ok := ue.destinations[dst]; ok {
		return target, nil
	}
	param := ue.destinationParam
	param.Dest = dst
	param.Domain = "" // Only the first destination participates in sniffing.
	param.networkType.IpVersion = consts.IpVersionStrFromAddr(dst.Addr())
	decision, err := ue.destinationMatcher.matchDestination(&param)
	if err != nil {
		return netip.AddrPort{}, err
	}
	target := decision
	if !target.IsValid() {
		target = dst
	}
	ue.destinations[dst] = target
	return target, nil
}

// The caller holds the source lock throughout socket creation and use.
func (ue *UdpEndpoint) socket(ctx context.Context, p *UdpEndpointPool, src, dst netip.AddrPort) (net.PacketConn, error) {
	if ue.sockets == nil || ue.mitm && dst == ue.firstDst {
		return ue.conn, nil
	}
	target, err := ue.socketTarget(dst)
	if err != nil {
		return nil, err
	}
	var key netip.AddrPort
	if target != dst {
		key = dst
	}
	if conn := ue.sockets[key]; conn != nil {
		return conn, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := watchAbort(ue.lease, ue.policyLease, ue.routeLease, cancel)
	defer stop()
	conn, err := ue.packetDialer.ListenPacket(ctx, target.String())
	if cause := connectionAbortCause(ue.lease, ue.policyLease, ue.routeLease); cause != nil {
		closeInBackground(conn)
		return nil, cause
	}
	if err != nil {
		return nil, netproxy.WrapFailure(err, netproxy.Failure{Phase: netproxy.OpDial, Origin: ue.origin})
	}
	if err := ctx.Err(); err != nil {
		closeInBackground(conn)
		return nil, err
	}
	if key.IsValid() {
		conn = &destinationPacketConn{PacketConn: conn, original: dst, target: target}
	}
	if ue.mitm && ue.traffic == nil {
		ue.traffic = stats.DefaultStore.OpenConnection(ue.statsPath, ue.fallback)
	}
	ue.startSocket(p, src, dst, key, conn)
	return conn, nil
}

func (ue *UdpEndpoint) startSocket(p *UdpEndpointPool, src, dst, key netip.AddrPort, conn net.PacketConn) {
	ue.mu.Lock()
	if ue.sockets != nil {
		ue.sockets[key] = conn
	}
	ue.stopWatching = append(ue.stopWatching, watchAbort(netproxy.DependencyOf(conn), ue.policyLease, ue.routeLease, func() {
		// Interrupt writes before waiting for the source lock.
		ue.interrupt()
		p.removeInBackground(src, ue)
	}))
	ue.mu.Unlock()
	go func() {
		err := ue.run(p, src, dst, conn)
		p.remove(src, ue)
		if !(ue.mitm && conn == ue.conn) && recordDataPlaneError(ue.dialer, ue.statsPath, err) {
			log.WithFields(log.Fields{
				"source": src, "destination": dst,
				"outbound": ue.statsPath.Outbound, "dialer": ue.statsPath.Dialer,
			}).WithError(err).Debug("UDP association failed")
		}
	}()
}
