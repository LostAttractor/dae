/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/samber/oops"
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

// Destination rewrites need one association per original destination so that two
// destinations mapped to the same server cannot receive each other's replies.
// An empty Destination retains ordinary full-cone behavior.
type udpEndpointKey struct {
	Source, Destination netip.AddrPort
	Interface           uint32
}

func udpRoutingKey(source, destination netip.AddrPort, result *bpfRoutingResult) udpEndpointKey {
	key := udpEndpointKey{Source: source}
	if result.CaptureFlags&captureDestination != 0 {
		key.Destination = destination
		key.Interface = result.Ifindex
	}
	return key
}

type UdpEndpoint struct {
	destination netip.AddrPort
	domain      string
	mitm        bool // The association belongs to HTTP; policy is selected per request.
	conn        net.PacketConn
	// mu protects the timer deadline and timer pointer.
	mu            sync.Mutex
	deadlineTimer *time.Timer
	timerDeadline time.Time
	handler       UdpHandler
	NatTimeout    time.Duration
	closed        atomic.Bool

	origin    netproxy.FailureOrigin
	dialer    *dialer.Dialer
	statsPath stats.Path
	traffic   *stats.Connection
}

func (ue *UdpEndpoint) run(endpointPool *UdpEndpointPool, key udpEndpointKey, dst netip.AddrPort) error {
	buf := pool.GetBuffer(consts.EthernetMtu)
	defer pool.PutBuffer(buf)
	for {
		n, from, err := ue.conn.ReadFrom(buf)
		if err != nil {
			if ue.IsClosed() && nativeSocket(ue.conn) && plainClosedError(err) || ue.mitm && errors.Is(err, net.ErrClosed) {
				break
			}
			if ue.mitm {
				return oops.Wrapf(err, "HTTP/3 association ReadFrom")
			}
			err = netproxy.WrapFailure(err, netproxy.Failure{Phase: netproxy.OpRead, Origin: ue.origin})
			return oops.With(
				"dialer", ue.dialer.Name,
				"outbound", ue.statsPath.Outbound,
				"network", ue.statsPath.Network.String(),
				"src", key.Source.String(),
				"dst", dst.String(),
			).Wrapf(err, "failed to ReadFrom")
		}
		if !endpointPool.refreshTimer(key, ue, time.Now()) {
			break
		}
		if err = ue.handler(buf[:n], addrPortOf(from)); err != nil {
			return netproxy.WrapFailure(err, netproxy.Failure{Phase: netproxy.OpWrite, Origin: netproxy.OriginCaller})
		}
		if n > 0 && ue.traffic != nil {
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
	return ue.conn.Close()
}

func (ue *UdpEndpoint) closeTrafficAccounting() {
	if ue.traffic != nil {
		ue.traffic.Close()
	}
}

// UdpEndpointPool is a full-cone udp conn pool
type UdpEndpointPool struct {
	pool                 sync.Map
	UdpEndpointKeyLocker common.KeyLocker[udpEndpointKey]
}

type UdpEndpointOptions struct {
	PacketConn net.PacketConn
	Handler    UdpHandler
	NatTimeout time.Duration

	Dialer *dialer.Dialer
	Path   stats.Path
}

var DefaultUdpEndpointPool = UdpEndpointPool{}

// deliverMITM keeps only an existing, exact QUIC association reachable while
// the owning plane drains. Never fall back to a full-cone endpoint or dial here.
func (p *UdpEndpointPool) deliverMITM(key udpEndpointKey, data []byte) {
	l, _ := p.UdpEndpointKeyLocker.Lock(key)
	defer p.UdpEndpointKeyLocker.Unlock(key, l)
	endpoint, ok := p.Get(key)
	if !ok || !endpoint.mitm {
		return
	}
	// MITM's in-memory packet bridge is nonblocking and wakes its reader on
	// closure. A concurrently closing association needs no retry or redial.
	n, _ := endpoint.conn.WriteTo(data, net.UDPAddrFromAddrPort(key.Destination))
	if n > 0 && endpoint.traffic != nil {
		endpoint.traffic.RecordUpload(uint64(n))
	}
}

// A proven HTTP/3 or destination rewrite association takes precedence over the
// source's ordinary full-cone endpoint, including later packets without SNI.
func (p *UdpEndpointPool) keyForPacket(source, destination netip.AddrPort, ifindex uint32, scoped bool) udpEndpointKey {
	key := udpEndpointKey{Source: source, Destination: destination, Interface: ifindex}
	if !scoped {
		_, scoped = p.pool.Load(key)
	}
	if scoped {
		return key
	}
	return udpEndpointKey{Source: source}
}

func (p *UdpEndpointPool) remove(key udpEndpointKey, endpoint *UdpEndpoint) {
	l, _ := p.UdpEndpointKeyLocker.Lock(key)
	removed := p.removeLocked(key, endpoint)
	if removed {
		endpoint.retire()
	}
	p.UdpEndpointKeyLocker.Unlock(key, l)
	endpoint.closeTrafficAccounting()
	if removed {
		_ = endpoint.conn.Close()
	}
}

func (p *UdpEndpointPool) removeInBackground(key udpEndpointKey, endpoint *UdpEndpoint) {
	l, _ := p.UdpEndpointKeyLocker.Lock(key)
	p.removeInBackgroundLocked(key, endpoint)
	p.UdpEndpointKeyLocker.Unlock(key, l)
}

func (p *UdpEndpointPool) removeLocked(key udpEndpointKey, endpoint *UdpEndpoint) bool {
	return p.pool.CompareAndDelete(key, endpoint)
}

func (p *UdpEndpointPool) removeInBackgroundLocked(key udpEndpointKey, endpoint *UdpEndpoint) {
	if p.removeLocked(key, endpoint) {
		endpoint.retire()
		endpoint.closeTrafficAccounting()
		closeInBackground(endpoint.conn)
	}
}

// closeAll sweeps endpoints observed in the pool. CompareAndDelete prevents a
// stale Range observation from closing a replacement published for the key.
func (p *UdpEndpointPool) closeAll() {
	p.pool.Range(func(key, value any) bool {
		endpoint := value.(*UdpEndpoint)
		if p.pool.CompareAndDelete(key, endpoint) {
			endpoint.retire()
			endpoint.closeTrafficAccounting()
			closeInBackground(endpoint.conn)
		}
		return true
	})
}

// Get refreshes the current endpoint. Packet-processing callers hold the key
// lock across Get and their packet use to serialize against timer expiry.
func (p *UdpEndpointPool) Get(key udpEndpointKey) (udpEndpoint *UdpEndpoint, ok bool) {
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

func (p *UdpEndpointPool) add(key udpEndpointKey, endpoint *UdpEndpoint) {
	l, _ := p.UdpEndpointKeyLocker.Lock(key)
	defer p.UdpEndpointKeyLocker.Unlock(key, l)
	p.addLocked(key, endpoint)
}

func (p *UdpEndpointPool) addLocked(key udpEndpointKey, endpoint *UdpEndpoint) {
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
		closeInBackground(oldEndpoint.conn)
	}
}

func (p *UdpEndpointPool) refreshTimerLocked(key udpEndpointKey, endpoint *UdpEndpoint, now time.Time) bool {
	current, ok := p.pool.Load(key)
	if !ok || current != endpoint || endpoint.IsClosed() {
		return false
	}
	return p.refreshTimer(key, endpoint, now)
}

// refreshTimer is also used after a successful inbound read, where taking the
// key lock would let an already-pending expiry win only due to lock scheduling.
func (p *UdpEndpointPool) refreshTimer(key udpEndpointKey, endpoint *UdpEndpoint, now time.Time) bool {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	if endpoint.closed.Load() {
		return false
	}
	p.refreshTimerStateLocked(key, endpoint, now)
	return true
}

func (p *UdpEndpointPool) refreshTimerStateLocked(key udpEndpointKey, endpoint *UdpEndpoint, now time.Time) {
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

func (p *UdpEndpointPool) expire(key udpEndpointKey, endpoint *UdpEndpoint) {
	p.expireAt(key, endpoint, time.Time{})
}

func (p *UdpEndpointPool) expireAt(key udpEndpointKey, endpoint *UdpEndpoint, now time.Time) {
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
		_ = endpoint.conn.Close()
	}
}
