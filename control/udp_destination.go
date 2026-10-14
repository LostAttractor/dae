// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"hash/maphash"
	"net"
	"net/netip"
	"time"

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
// several original addresses map to one server. Their expiry never changes the
// source's retained route, node, destination program or random seed.
func (ue *UdpEndpoint) socketTarget(dst netip.AddrPort) (netip.AddrPort, error) {
	now := time.Now()
	ue.mu.Lock()
	defer ue.mu.Unlock()
	if cached, ok := ue.destinations[dst]; ok {
		cached.lastUsed = now
		ue.destinations[dst] = cached
		return cached.target, nil
	}
	if ue.destinationSeed == (maphash.Seed{}) {
		ue.destinationSeed = maphash.MakeSeed()
	}
	param := ue.destinationParam
	param.destinationSeed = &ue.destinationSeed
	param.Dest, param.Domain = dst, ""
	if dst == ue.firstDst {
		param.Domain = ue.domain
	}
	param.networkType.IpVersion = consts.IpVersionStrFromAddr(dst.Addr())
	target, err := ue.destinationMatcher.matchDestination(&param)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if !target.IsValid() {
		target = dst
	}
	if ue.destinations == nil {
		ue.destinations = make(map[netip.AddrPort]udpDestination)
	}
	if len(ue.destinations) >= maxUDPDestinationsPerSource {
		var oldest netip.AddrPort
		var at time.Time
		for key, cached := range ue.destinations {
			if !oldest.IsValid() || cached.lastUsed.Before(at) {
				oldest, at = key, cached.lastUsed
			}
		}
		delete(ue.destinations, oldest)
	}
	ue.destinations[dst] = udpDestination{target, now}
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
	ue.mu.Lock()
	if child := ue.sockets[key]; child != nil {
		child.lastUsed = time.Now()
		ue.mu.Unlock()
		return child.conn, nil
	}
	expired, cause := ue.expireChildrenLocked(time.Now())
	full := len(ue.sockets) >= maxUDPSocketsPerSource
	ue.mu.Unlock()
	for _, conn := range expired {
		closeInBackground(conn)
	}
	if cause != nil {
		return nil, cause
	}
	if full {
		return nil, netproxy.PacketCapacityError()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := watchAbort(ue.lease, ue.policyLease, ue.routeLease, cancel)
	defer stop()
	conn, err := p.packetBudget().Open(ctx, target.String(), ue.packetDialer.ListenPacket)
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
		ue.traffic = stats.DefaultStore.OpenDeviceConnection(ue.statsPath, ue.fallback, ue.destinationParam.routingResult.Mac)
	}
	ue.startSocket(p, src, dst, key, conn)
	return conn, nil
}

func (ue *UdpEndpoint) startSocket(p *UdpEndpointPool, src, dst, key netip.AddrPort, conn net.PacketConn) {
	ue.mu.Lock()
	var child *udpSocket
	if ue.sockets != nil {
		child = &udpSocket{conn: conn, lastUsed: time.Now()}
		ue.sockets[key] = child
	}
	stop := watchAbort(netproxy.DependencyOf(conn), ue.policyLease, ue.routeLease, func() {
		ue.mu.Lock()
		// An expired target cannot abort a replacement for the same key or
		// its source. Check membership while publishing the abort instruction.
		if ue.closed.Load() || child != nil && (child.retired.Load() || ue.sockets[key] != child) {
			ue.mu.Unlock()
			return
		}
		ue.lease.Abort(connectionAbortCause(netproxy.DependencyOf(conn), ue.policyLease, ue.routeLease))
		ue.mu.Unlock()
		ue.interrupt()
		p.removeInBackground(src, ue)
	})
	if child != nil {
		child.stopWatching = stop
	} else {
		ue.stopWatching = append(ue.stopWatching, stop)
	}
	ue.mu.Unlock()
	go func() {
		err := ue.run(p, src, dst, conn, child)
		lock, _ := p.UdpEndpointKeyLocker.Lock(src)
		retired := child != nil && child.retired.Load()
		if !retired {
			p.removeInBackgroundLocked(src, ue)
		}
		p.UdpEndpointKeyLocker.Unlock(src, lock)
		if !retired && !(ue.mitm && conn == ue.conn) && recordDataPlaneError(ue.dialer, ue.statsPath, err) {
			log.WithFields(log.Fields{
				"source": src, "destination": dst,
				"outbound": ue.statsPath.Outbound, "dialer": ue.statsPath.Dialer,
			}).WithError(err).Debug("UDP association failed")
		}
	}()
}

// Caller holds the source key and endpoint.mu. A write owns that key until it
// finishes; replies refresh lastUsed under mu before forwarding the packet.
func (ue *UdpEndpoint) expireChildrenLocked(now time.Time) (expired []net.PacketConn, cause error) {
	for key, child := range ue.sockets {
		if ue.mitm && child.conn == ue.conn || now.Sub(child.lastUsed) < udpChildIdleTimeout {
			continue
		}
		if err := netproxy.DependencyOf(child.conn).AbortCause(); err != nil {
			ue.lease.Abort(err)
			cause = err
			continue
		}
		delete(ue.sockets, key)
		child.retired.Store(true)
		if child.stopWatching != nil {
			child.stopWatching()
			child.stopWatching = nil
		}
		expired = append(expired, child.conn)
	}
	for key, value := range ue.destinations {
		if now.Sub(value.lastUsed) >= udpChildIdleTimeout {
			delete(ue.destinations, key)
		}
	}
	for key, value := range ue.activityTargets {
		if now.Sub(value.lastUsed) >= udpChildIdleTimeout {
			delete(ue.activityTargets, key)
		}
	}
	return expired, cause
}
