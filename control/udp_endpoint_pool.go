/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

type UdpHandler func(data []byte, from netip.AddrPort) error

// addrPortOf converts a net.Addr returned by a PacketConn into a netip.AddrPort.
// It avoids the string round-trip for the common *net.UDPAddr case.
func addrPortOf(addr net.Addr) netip.AddrPort {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		return udpAddr.AddrPort()
	}
	return netip.MustParseAddrPort(addr.String())
}

type UdpEndpoint struct {
	conn net.PacketConn
	mitm bool // The first destination is served by the HTTP/3 packet bridge.
	// mu protects the timer deadline and timer pointer.
	mu            sync.Mutex
	deadlineTimer *time.Timer
	timerDeadline time.Time
	handler       UdpHandler
	NatTimeout    time.Duration
	closed        atomic.Bool

	origin             netproxy.FailureOrigin
	dialer             *dialer.Dialer
	statsPath          stats.Path
	fallback           bool
	traffic            *stats.Connection
	lease              *netproxy.Lease
	routeLease         *netproxy.Lease
	policyLease        *netproxy.Lease
	stopWatching       []func()
	releaseDialer      func()
	packetDialer       netproxy.Dialer
	destinationMatcher *RoutingMatcher
	destinationParam   RouteParam
	destinations       map[netip.AddrPort]netip.AddrPort
	// Source lock protects socket selection; mu also protects cleanup snapshots.
	sockets map[netip.AddrPort]net.PacketConn
	unbind  func()

	// Only initialization uses these fields, under the source key lock.
	routingResult *bpfRoutingResult
	firstDst      netip.AddrPort
	firstIfindex  uint32
	sniffer       *sniffing.Sniffer
}

func (ue *UdpEndpoint) run(endpointPool *UdpEndpointPool, src, dst netip.AddrPort, conn net.PacketConn) error {
	buf := pool.GetBuffer(udpReceiveBufferSize)
	defer pool.PutBuffer(buf)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if cause := connectionAbortCause(netproxy.DependencyOf(conn), ue.policyLease, ue.routeLease); cause != nil {
				return cause
			}
			if (ue.IsClosed() || ue.mitm && conn == ue.conn) && plainClosedError(err) {
				break
			}
			err = netproxy.WrapFailure(err, netproxy.Failure{Phase: netproxy.OpRead, Origin: ue.origin})
			if temporaryUDPError(err) {
				_ = conn.SetReadDeadline(time.Time{})
				continue
			}
			return fmt.Errorf("receive UDP packet: %w", err)
		}
		if cause := connectionAbortCause(netproxy.DependencyOf(conn), ue.policyLease, ue.routeLease); cause != nil {
			return cause
		}
		if !endpointPool.refreshTimer(src, ue, time.Now()) {
			break
		}
		if err = ue.handler(buf[:n], addrPortOf(from)); err != nil {
			return netproxy.WrapFailure(err, netproxy.Failure{Phase: netproxy.OpWrite, Origin: netproxy.OriginCaller})
		}
		if !(ue.mitm && conn == ue.conn) && n > 0 && ue.traffic != nil {
			ue.traffic.RecordDownload(uint64(n))
		}
	}
	return nil
}

func (ue *UdpEndpoint) IsClosed() bool {
	return ue.closed.Load()
}

func (ue *UdpEndpoint) retire() {
	ue.mu.Lock()
	ue.retireLocked()
	ue.mu.Unlock()
}

func (ue *UdpEndpoint) retireLocked() {
	if ue.closed.Swap(true) {
		return
	}
	if ue.unbind != nil {
		ue.unbind()
		ue.unbind = nil
	}
	for _, stop := range ue.stopWatching {
		stop()
	}
	ue.stopWatching = nil
	if ue.releaseDialer != nil {
		ue.releaseDialer()
		ue.releaseDialer = nil
	}
	if ue.sniffer != nil {
		_ = ue.sniffer.Close()
		ue.sniffer = nil
	}
	ue.timerDeadline = time.Time{}
	if ue.deadlineTimer != nil {
		ue.deadlineTimer.Stop()
		ue.deadlineTimer = nil
	}
}

// Close retires the endpoint and closes its connection. A published endpoint
// must be removed from its pool before Close is called.
func (ue *UdpEndpoint) Close() error {
	ue.retire()
	ue.closeTrafficAccounting()
	var err error
	for _, conn := range ue.packetConnections() {
		err = errors.Join(err, conn.Close())
	}
	return err
}

func (ue *UdpEndpoint) packetConnections() []net.PacketConn {
	ue.mu.Lock()
	defer ue.mu.Unlock()
	if ue.sockets == nil {
		if ue.conn == nil {
			return nil
		}
		return []net.PacketConn{ue.conn}
	}
	connections := make([]net.PacketConn, 0, len(ue.sockets))
	for _, conn := range ue.sockets {
		connections = append(connections, conn)
	}
	return connections
}

func (ue *UdpEndpoint) interrupt() {
	for _, conn := range ue.packetConnections() {
		closeInBackground(conn)
	}
}

func (ue *UdpEndpoint) closeTrafficAccounting() {
	if ue.traffic != nil {
		ue.traffic.Close()
	}
}

// UdpEndpointPool is a full-cone udp conn pool
type UdpEndpointPool struct {
	pool                 sync.Map
	UdpEndpointKeyLocker common.KeyLocker[netip.AddrPort]
}

type UdpEndpointOptions struct {
	PacketConn net.PacketConn
	Handler    UdpHandler
	NatTimeout time.Duration

	Dialer *dialer.Dialer
	Path   stats.Path
}

var DefaultUdpEndpointPool = UdpEndpointPool{}

// deliverMITM admits only the established first-destination bridge during
// retirement. Other sockets keep the source's route, but cannot accept new work.
func (p *UdpEndpointPool) deliverMITM(src, dst netip.AddrPort, ifindex uint32, data []byte) {
	lock, _ := p.UdpEndpointKeyLocker.Lock(src)
	defer p.UdpEndpointKeyLocker.Unlock(src, lock)
	ue, ok := p.Get(src)
	if !ok || !ue.mitm || ue.firstDst != dst || ue.firstIfindex != ifindex {
		return
	}
	if connectionAbortCause(ue.lease, ue.policyLease, ue.routeLease) != nil {
		p.removeInBackgroundLocked(src, ue)
		return
	}
	_, _ = ue.conn.WriteTo(data, net.UDPAddrFromAddrPort(dst))
}

func (p *UdpEndpointPool) remove(key netip.AddrPort, endpoint *UdpEndpoint) {
	l, _ := p.UdpEndpointKeyLocker.Lock(key)
	removed := p.removeLocked(key, endpoint)
	if removed {
		endpoint.retire()
	}
	p.UdpEndpointKeyLocker.Unlock(key, l)
	endpoint.closeTrafficAccounting()
	if removed {
		_ = endpoint.Close()
	}
}

func (p *UdpEndpointPool) removeInBackground(key netip.AddrPort, endpoint *UdpEndpoint) {
	l, _ := p.UdpEndpointKeyLocker.Lock(key)
	p.removeInBackgroundLocked(key, endpoint)
	p.UdpEndpointKeyLocker.Unlock(key, l)
}

func (p *UdpEndpointPool) removeLocked(key netip.AddrPort, endpoint *UdpEndpoint) bool {
	return p.pool.CompareAndDelete(key, endpoint)
}

func (p *UdpEndpointPool) removeInBackgroundLocked(key netip.AddrPort, endpoint *UdpEndpoint) {
	if p.removeLocked(key, endpoint) {
		endpoint.retire()
		endpoint.closeTrafficAccounting()
		endpoint.interrupt()
	}
}

// closeAll sweeps endpoints observed in the pool. CompareAndDelete prevents a
// stale Range observation from closing a replacement published for the key.
func (p *UdpEndpointPool) closeAll() {
	p.pool.Range(func(key, value any) bool {
		p.removeInBackground(key.(netip.AddrPort), value.(*UdpEndpoint))
		return true
	})
}

// Pending sniffers have no connection to preserve across routing-table reloads.
func (p *UdpEndpointPool) removePending() {
	p.pool.Range(func(key, value any) bool {
		src, ue := key.(netip.AddrPort), value.(*UdpEndpoint)
		lock, _ := p.UdpEndpointKeyLocker.Lock(src)
		if ue.conn == nil {
			p.removeInBackgroundLocked(src, ue)
		}
		p.UdpEndpointKeyLocker.Unlock(src, lock)
		return true
	})
}

// Get refreshes the current endpoint. Packet-processing callers hold the key
// lock across Get and their packet use to serialize against timer expiry.
func (p *UdpEndpointPool) Get(key netip.AddrPort) (udpEndpoint *UdpEndpoint, ok bool) {
	_ue, ok := p.pool.Load(key)
	if !ok {
		return nil, ok
	}
	ue := _ue.(*UdpEndpoint)
	if !p.refreshTimerLocked(key, ue, time.Now()) {
		return nil, false
	}
	return ue, true
}

func newUdpEndpoint(createOption *UdpEndpointOptions) *UdpEndpoint {
	return &UdpEndpoint{
		conn:       createOption.PacketConn,
		handler:    createOption.Handler,
		NatTimeout: createOption.NatTimeout,
		dialer:     createOption.Dialer,
		statsPath:  createOption.Path,
	}
}

func (p *UdpEndpointPool) add(key netip.AddrPort, endpoint *UdpEndpoint) {
	l, _ := p.UdpEndpointKeyLocker.Lock(key)
	defer p.UdpEndpointKeyLocker.Unlock(key, l)
	p.addLocked(key, endpoint)
}

func (p *UdpEndpointPool) addLocked(key netip.AddrPort, endpoint *UdpEndpoint) {
	endpoint.mu.Lock()
	if endpoint.closed.Load() {
		endpoint.mu.Unlock()
		return
	}
	p.refreshTimerStateLocked(key, endpoint, time.Now())
	previous, replaced := p.pool.Swap(key, endpoint)
	endpoint.mu.Unlock()

	if replaced && previous != endpoint {
		oldEndpoint := previous.(*UdpEndpoint)
		oldEndpoint.retire()
		oldEndpoint.closeTrafficAccounting()
		oldEndpoint.interrupt()
	}
}

func (p *UdpEndpointPool) refreshTimerLocked(key netip.AddrPort, endpoint *UdpEndpoint, now time.Time) bool {
	current, ok := p.pool.Load(key)
	if !ok || current != endpoint || endpoint.IsClosed() {
		return false
	}
	return p.refreshTimer(key, endpoint, now)
}

// refreshTimer is also used after a successful inbound read, where taking the
// key lock would let an already-pending expiry win only due to lock scheduling.
func (p *UdpEndpointPool) refreshTimer(key netip.AddrPort, endpoint *UdpEndpoint, now time.Time) bool {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	if endpoint.closed.Load() {
		return false
	}
	p.refreshTimerStateLocked(key, endpoint, now)
	return true
}

func (p *UdpEndpointPool) refreshTimerStateLocked(key netip.AddrPort, endpoint *UdpEndpoint, now time.Time) {
	deadline := now.Add(endpoint.NatTimeout)
	delay := time.Until(deadline)
	endpoint.timerDeadline = deadline
	if endpoint.deadlineTimer == nil {
		endpoint.deadlineTimer = time.AfterFunc(delay, func() {
			p.expire(key, endpoint)
		})
		return
	}
	endpoint.deadlineTimer.Reset(delay)
}

func (p *UdpEndpointPool) expire(key netip.AddrPort, endpoint *UdpEndpoint) {
	p.expireAt(key, endpoint, time.Time{})
}

func (p *UdpEndpointPool) expireAt(key netip.AddrPort, endpoint *UdpEndpoint, now time.Time) {
	l, _ := p.UdpEndpointKeyLocker.Lock(key)
	current, ok := p.pool.Load(key)
	if !ok || current != endpoint {
		p.UdpEndpointKeyLocker.Unlock(key, l)
		return
	}

	endpoint.mu.Lock()
	if now.IsZero() {
		// Account for time spent waiting on both the key and timer state.
		now = time.Now()
	}
	if endpoint.closed.Load() {
		endpoint.mu.Unlock()
		p.UdpEndpointKeyLocker.Unlock(key, l)
		return
	}
	deadline := endpoint.timerDeadline
	if now.Before(deadline) {
		endpoint.deadlineTimer.Reset(deadline.Sub(now))
		endpoint.mu.Unlock()
		p.UdpEndpointKeyLocker.Unlock(key, l)
		return
	}
	removed := p.removeLocked(key, endpoint)
	if removed {
		endpoint.retireLocked()
	}
	endpoint.mu.Unlock()
	p.UdpEndpointKeyLocker.Unlock(key, l)
	if removed {
		endpoint.closeTrafficAccounting()
		_ = endpoint.Close()
	}
}
