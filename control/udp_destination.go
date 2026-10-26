// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"
	"hash/maphash"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
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
		address, err := addrPortOf(from)
		if err != nil {
			return 0, nil, err
		}
		if common.ConvergeAddrPort(address) == c.target {
			return n, net.UDPAddrFromAddrPort(c.original), nil
		}
		dropDownloadFiltered.Add(1)
	}
}

// SetPacketHandler pushes replies as ReadFrom returns them: only those from
// target, as from original.
func (c *destinationPacketConn) SetPacketHandler(onPacket func([]byte, netip.AddrPort), onClose func(error)) bool {
	pusher, ok := netproxy.PacketConnAs[netproxy.PacketPusher](c.PacketConn)
	return ok && pusher.SetPacketHandler(func(payload []byte, from netip.AddrPort) {
		if common.ConvergeAddrPort(from) == c.target {
			onPacket(payload, c.original)
		} else {
			dropDownloadFiltered.Add(1)
		}
	}, onClose)
}

func (c *destinationPacketConn) DependencyLease() *netproxy.Lease {
	return netproxy.DependencyOf(c.PacketConn)
}

func newDestinationPacketConn(conn net.PacketConn, original, target netip.AddrPort) net.PacketConn {
	c := &destinationPacketConn{PacketConn: conn, original: original, target: target}
	if writer, ok := netproxy.PacketConnAs[netproxy.NonBlockingWriter](conn); ok {
		return &nonBlockingDestinationPacketConn{c, writer}
	}
	return c
}

// nonBlockingDestinationPacketConn is a destinationPacketConn over a transport
// that never waits, which it writes to as WriteTo does.
type nonBlockingDestinationPacketConn struct {
	*destinationPacketConn
	writer netproxy.NonBlockingWriter
}

func (c *nonBlockingDestinationPacketConn) TryWriteTo(data []byte, _ net.Addr) (int, error) {
	return c.writer.TryWriteTo(data, net.UDPAddrFromAddrPort(c.target))
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

// The caller holds the source lock throughout socket creation and use. ctx
// carries cancellation only; deadline bounds creating a socket.
func (ue *UdpEndpoint) socket(ctx context.Context, deadline time.Time, p *UdpEndpointPool, src, dst netip.AddrPort, slot *udpWriteSlot) (net.PacketConn, error) {
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return nil, context.DeadlineExceeded
	}
	if !slot.beginSlow() {
		dropSetupCapacity.Add(1)
		return nil, netproxy.ErrPacketDropped
	}
	defer slot.endSlow()
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	if ue.isQUIC {
		ctx = netproxy.WithQUIC(ctx)
	}
	upstream := upstreamDial{dialer: ue.dialer, path: ue.statsPath, origin: ue.origin,
		resource: ue.lease, policy: ue.policyLease, route: ue.routeLease}
	conn, err := upstream.establishUpstream(ctx, func(ctx context.Context) (net.PacketConn, error) {
		return p.packetBudget().Open(ctx, target.String(), ue.packetDialer.ListenPacket)
	})
	if err != nil {
		return nil, err
	}
	if key.IsValid() {
		conn = newDestinationPacketConn(conn, dst, target)
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
	// Before the first write, so that no reply waits unseen.
	if pusher, ok := netproxy.PacketConnAs[netproxy.PacketPusher](conn); ok && !(ue.mitm && conn == ue.conn) {
		r := &udpPushReceiver{ue: ue, p: p, src: src, dst: dst, conn: conn, child: child}
		if pusher.SetPacketHandler(r.onPacket, r.onClose) {
			return
		}
	}
	go func() {
		ue.endSocket(p, src, dst, conn, child, ue.run(p, src, dst, conn, child))
	}()
}

// udpPushReceiver delivers the replies a transport pushes for one socket. The
// transport's receive loop serves other streams too and must never block:
// replies it cannot forward without waiting go, followed by the later ones, to
// a goroutine started on demand, which also ends delivery.
type udpPushReceiver struct {
	ue       *UdpEndpoint
	p        *UdpEndpointPool
	src, dst netip.AddrPort
	conn     net.PacketConn
	child    *udpSocket
	mu       sync.Mutex
	backlog  []udpPushedReply // at most udpTaskQueueLength
	draining bool             // a goroutine works off backlog
	closed   bool             // the transport ended delivery with closeErr
	closeErr error
	done     bool // delivery ended; later callbacks do nothing
}

type udpPushedReply struct {
	packet udpPacket
	from   netip.AddrPort
}

func (r *udpPushReceiver) onPacket(payload []byte, from netip.AddrPort) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		netproxy.DropClosedStream.Add(1)
		return
	}
	if r.closed {
		return
	}
	if !r.draining {
		// Nothing is queued for this reply to overtake.
		r.mu.Unlock()
		done, err := r.ue.deliver(r.p, r.src, r.conn, r.child, payload, from, false)
		r.mu.Lock()
		if done && !r.done {
			r.endLocked(err)
		}
		if err != errReplyWouldBlock || r.done || r.closed {
			return
		}
	}
	if len(r.backlog) == udpTaskQueueLength {
		dropReplyQueue.Add(1)
		return
	}
	packet, ok := copyUDPPacket(payload, udpPacketMemory)
	if !ok {
		dropDownloadMemory.Add(1)
		return
	}
	r.backlog = append(r.backlog, udpPushedReply{packet, from})
	r.drainLocked()
}

// onClose may run on the transport's receive loop or on a closer holding the
// source lock, which ending delivery takes.
func (r *udpPushReceiver) onClose(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done || r.closed {
		return
	}
	r.closed, r.closeErr = true, err
	r.drainLocked()
}

func (r *udpPushReceiver) drainLocked() {
	if !r.draining {
		r.draining = true
		go r.drain()
	}
}

// endLocked ends delivery in the background and drops queued replies.
func (r *udpPushReceiver) endLocked(err error) {
	r.done = true
	netproxy.DropClosedStream.Add(uint64(len(r.backlog)))
	for _, reply := range r.backlog {
		reply.packet.release()
	}
	r.backlog = nil
	go r.ue.endSocket(r.p, r.src, r.dst, r.conn, r.child, err)
}

// drain delivers queued replies in order, then ends delivery once the
// transport has.
func (r *udpPushReceiver) drain() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for !r.done {
		if len(r.backlog) == 0 {
			if r.closed {
				failure, retry := r.ue.receiveFailure(r.conn, r.child, r.closeErr)
				if retry {
					// A reader could read on; delivery has ended anyway.
					failure = fmt.Errorf("receive UDP packet: %w", failure)
				}
				r.endLocked(failure)
			}
			break
		}
		reply := r.backlog[0]
		r.backlog = r.backlog[1:]
		r.mu.Unlock()
		done, err := r.ue.deliver(r.p, r.src, r.conn, r.child, reply.packet.data, reply.from, true)
		reply.packet.release()
		r.mu.Lock()
		if done && !r.done {
			r.endLocked(err)
		}
	}
	r.draining = false
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
