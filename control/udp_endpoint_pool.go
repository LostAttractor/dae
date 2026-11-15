/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"hash/maphash"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	log "github.com/sirupsen/logrus"
)

// udpReplies sends an endpoint's replies to its client. send may wait to
// create a socket, never for a full one: it drops the reply instead, counted,
// with netproxy.ErrPacketDropped. trySend returns nil on success,
// netproxy.ErrPacketDropped for a counted drop, or errReplyWouldBlock to defer to send.
type udpReplies interface {
	send(data []byte, from netip.AddrPort) error
	trySend(data []byte, from netip.AddrPort) error
}

const (
	maxUDPSources               = 4096
	maxUDPPacketResources       = 2048
	maxUDPSocketsPerSource      = 64
	maxUDPDestinationsPerSource = 256
	udpChildIdleTimeout         = time.Minute
)

type udpSocket struct {
	conn         net.PacketConn
	lastUsed     time.Time // endpoint.mu; expiry also holds the source key lock.
	retired      atomic.Bool
	stopWatching func()
}

type udpDestination struct {
	target   netip.AddrPort
	lastUsed time.Time
}

type udpActivityTarget struct {
	key      domainActivityKey
	lastUsed time.Time
	queuedAt time.Time // latest enqueue, throttled by domainActivityInterval
}

// addrPortOf converts a net.Addr returned by a PacketConn into a netip.AddrPort.
// It avoids the string round-trip for the common *net.UDPAddr case.
func addrPortOf(addr net.Addr) (netip.AddrPort, error) {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if udpAddr != nil && udpAddr.AddrPort().IsValid() {
			return common.ConvergeAddrPort(udpAddr.AddrPort()), nil
		}
		return netip.AddrPort{}, errors.New("invalid UDP reply address")
	}
	if addr == nil {
		return netip.AddrPort{}, errors.New("missing UDP reply address")
	}
	address, err := netip.ParseAddrPort(addr.String())
	return common.ConvergeAddrPort(address), err
}

type UdpEndpoint struct {
	setupOwner atomic.Pointer[ControlPlane]
	generation uint32
	conn       net.PacketConn
	mitm       bool // The first destination is served by the HTTP/3 packet bridge.
	isQUIC     bool // Retained sniff result for every destination socket.
	activity   *domainActivity
	domain     string
	// mu protects timer state, observed destinations and cleanup snapshots.
	mu              sync.Mutex
	activityTargets map[netip.AddrPort]udpActivityTarget
	deadlineTimer   *time.Timer
	timerDeadline   time.Time
	replies         udpReplies
	NatTimeout      time.Duration
	closed          atomic.Bool

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
	destinationSeed    maphash.Seed
	destinations       map[netip.AddrPort]udpDestination
	// Source lock protects socket selection; mu also protects cleanup snapshots.
	sockets map[netip.AddrPort]*udpSocket
	unbind  func()

	// The source key lock serializes initialization and packet delivery.
	pending      *udpSetup
	firstDst     netip.AddrPort
	firstIfindex uint32
	binding      bpfUdpBinding  // Immutable after publication; queued packets cannot inherit another source's association.
	writeDst     netip.AddrPort // source key lock
	writeAddr    *net.UDPAddr
}

// udpSetup exists only while collecting the first destination's packets.
// An established endpoint retains its decisions, not its sniffing machinery.
type udpSetup struct {
	routingResult *routingResult
	sniffer       *sniffing.Sniffer
	packets       []udpPacket
	observedAt    time.Time // incomplete sniff activity, applied on setup or retirement
}

func (s *udpSetup) appendPacket(packet *udpPacket) bool {
	owned, ok := packet.take(udpPacketMemory)
	if !ok {
		return false
	}
	s.packets = append(s.packets, owned)
	s.sniffer.AppendBorrowedData(owned.data)
	return true
}

func (s *udpSetup) close() {
	_ = s.sniffer.Close()
	for i := range s.packets {
		s.packets[i].release()
	}
}

// run reads replies from conn until its delivery ends.
func (ue *UdpEndpoint) run(endpointPool *UdpEndpointPool, src, dst netip.AddrPort, conn net.PacketConn, child *udpSocket) error {
	buf := pool.GetBuffer(udpReceiveBufferSize)
	defer pool.PutBuffer(buf)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			failure, retry := ue.receiveFailure(conn, child, err)
			if retry {
				_ = conn.SetReadDeadline(time.Time{})
				continue
			}
			return failure
		}
		address, err := addrPortOf(from)
		if err != nil {
			return netproxy.WrapFailure(fmt.Errorf("receive UDP reply address: %w", err), netproxy.Failure{Phase: netproxy.OpRead, Origin: ue.origin})
		}
		if done, err := ue.deliver(endpointPool, src, conn, child, buf[:n], address, true); done {
			return err
		}
	}
}

// receiveFailure is the failure a receive error ends conn's delivery with, nil
// for a quiet end. A retry failure is one a reader may read past.
func (ue *UdpEndpoint) receiveFailure(conn net.PacketConn, child *udpSocket, err error) (failure error, retry bool) {
	if child != nil && child.retired.Load() {
		return nil, false
	}
	if cause := connectionAbortCause(netproxy.DependencyOf(conn), ue.policyLease, ue.routeLease); cause != nil {
		return cause, false
	}
	if (ue.IsClosed() || ue.mitm && conn == ue.conn) && plainClosedError(err) {
		return nil, false
	}
	err = netproxy.WrapFailure(err, netproxy.Failure{Phase: netproxy.OpRead, Origin: ue.origin})
	if temporaryUDPError(err) {
		return err, true
	}
	return fmt.Errorf("receive UDP packet: %w", err), false
}

// errReplyWouldBlock reports a reply deliver could not forward without
// waiting.
var errReplyWouldBlock = errors.New("UDP reply would block")

// deliver forwards a reply received on conn to the client. done reports that
// conn's delivery ended, with err as the failure to report or nil; a reply
// that cannot be sent is dropped, counted, without ending it. With wait it may
// wait to observe a target or create the client's socket, never for a full
// one. Without wait it does nothing that may block and returns
// errReplyWouldBlock instead, having at most refreshed the socket and observed
// a known target, which a repeat does again harmlessly.
func (ue *UdpEndpoint) deliver(p *UdpEndpointPool, src netip.AddrPort, conn net.PacketConn, child *udpSocket, payload []byte, from netip.AddrPort, wait bool) (done bool, err error) {
	from = common.ConvergeAddrPort(from)
	// A reply for an association ending here is dropped.
	if cause := connectionAbortCause(netproxy.DependencyOf(conn), ue.policyLease, ue.routeLease); cause != nil {
		dropClosedStream.Add(1)
		return true, cause
	}
	if !p.refreshSocket(src, ue, child, time.Now()) {
		dropClosedStream.Add(1)
		return true, nil
	}
	if !ue.observeTarget(from, wait) {
		return false, errReplyWouldBlock
	}
	if !wait {
		err = ue.replies.trySend(payload, from)
		if errors.Is(err, errReplyWouldBlock) {
			return false, errReplyWouldBlock
		}
	} else {
		err = ue.replies.send(payload, from)
	}
	if err != nil {
		// A reply lost on the way to the client does not end the association.
		if !errors.Is(err, netproxy.ErrPacketDropped) {
			dropReplySendFailed.Add(1)
		}
		return false, nil
	}
	if !(ue.mitm && conn == ue.conn) && len(payload) > 0 && ue.traffic != nil {
		ue.traffic.RecordDownload(uint64(len(payload)))
	}
	return false, nil
}

// endSocket ends conn's delivery: unless conn's socket was retired, the
// source loses its endpoint and err is reported.
func (ue *UdpEndpoint) endSocket(p *UdpEndpointPool, src, dst netip.AddrPort, conn net.PacketConn, child *udpSocket, err error) {
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
	ue.lease.Invalidate(net.ErrClosed)
	for _, child := range ue.sockets {
		child.retired.Store(true)
		if child.stopWatching != nil {
			child.stopWatching()
			child.stopWatching = nil
		}
	}
	if ue.releaseDialer != nil {
		ue.releaseDialer()
		ue.releaseDialer = nil
	}
	if ue.pending != nil {
		if !ue.pending.observedAt.IsZero() {
			ue.activity.observe(ue.firstDst.Addr(), ue.domain, ue.pending.observedAt)
		}
		ue.pending.close()
		ue.pending = nil
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
	for _, child := range ue.sockets {
		connections = append(connections, child.conn)
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
	sources              atomic.Int64
	resourceOnce         sync.Once
	resources            *netproxy.PacketBudget
	sourceLimit          int // zero uses the daemon default; immutable once used.
}

func (p *UdpEndpointPool) packetBudget() *netproxy.PacketBudget {
	p.resourceOnce.Do(func() {
		if p.resources == nil {
			p.resources = netproxy.NewPacketBudget(maxUDPPacketResources)
		}
	})
	return p.resources
}

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
	ue.observeDomain(dst)
}

func (p *UdpEndpointPool) removeInBackground(key netip.AddrPort, endpoint *UdpEndpoint) {
	l, _ := p.UdpEndpointKeyLocker.Lock(key)
	p.removeInBackgroundLocked(key, endpoint)
	p.UdpEndpointKeyLocker.Unlock(key, l)
}

func (p *UdpEndpointPool) removeLocked(key netip.AddrPort, endpoint *UdpEndpoint) bool {
	if !p.pool.CompareAndDelete(key, endpoint) {
		return false
	}
	p.sources.Add(-1)
	return true
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
func (p *UdpEndpointPool) removePending(owner *ControlPlane) {
	p.pool.Range(func(key, value any) bool {
		src, ue := key.(netip.AddrPort), value.(*UdpEndpoint)
		lock, _ := p.UdpEndpointKeyLocker.Lock(src)
		if ue.conn == nil && ue.setupOwner.Load() == owner {
			p.removeInBackgroundLocked(src, ue)
		}
		p.UdpEndpointKeyLocker.Unlock(src, lock)
		return true
	})
}

func (p *UdpEndpointPool) closeGeneration(generation uint32) {
	p.pool.Range(func(key, value any) bool {
		ue := value.(*UdpEndpoint)
		if ue.generation == generation {
			p.removeInBackground(key.(netip.AddrPort), ue)
		}
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

func (p *UdpEndpointPool) sourceCapacity() int {
	if p.sourceLimit > 0 {
		return p.sourceLimit
	}
	return maxUDPSources
}

func (p *UdpEndpointPool) addLocked(key netip.AddrPort, endpoint *UdpEndpoint) bool {
	endpoint.mu.Lock()
	if endpoint.closed.Load() {
		endpoint.mu.Unlock()
		return false
	}
	if _, exists := p.pool.Load(key); !exists {
		limit := int64(p.sourceCapacity())
		for {
			used := p.sources.Load()
			if used >= limit {
				endpoint.mu.Unlock()
				return false
			}
			if p.sources.CompareAndSwap(used, used+1) {
				break
			}
		}
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
	return true
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
	return p.refreshSocket(key, endpoint, nil, now)
}

func (p *UdpEndpointPool) refreshSocket(key netip.AddrPort, endpoint *UdpEndpoint, child *udpSocket, now time.Time) bool {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	if endpoint.closed.Load() || child != nil && child.retired.Load() {
		return false
	}
	if child != nil {
		child.lastUsed = now
	}
	p.refreshTimerStateLocked(key, endpoint, now)
	return true
}

func (p *UdpEndpointPool) refreshTimerStateLocked(key netip.AddrPort, endpoint *UdpEndpoint, now time.Time) {
	endpoint.timerDeadline = now.Add(endpoint.NatTimeout)
	// Activity extends the deadline. An early expiry rearms the existing timer.
	if endpoint.deadlineTimer == nil {
		endpoint.deadlineTimer = time.AfterFunc(min(time.Until(endpoint.timerDeadline), udpChildIdleTimeout/2), func() {
			p.expire(key, endpoint)
		})
	}
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
	expired, cause := endpoint.expireChildrenLocked(now)
	if cause == nil && now.Before(deadline) {
		endpoint.deadlineTimer.Reset(min(deadline.Sub(now), udpChildIdleTimeout/2))
		endpoint.mu.Unlock()
		p.UdpEndpointKeyLocker.Unlock(key, l)
		for _, conn := range expired {
			closeInBackground(conn)
		}
		return
	}
	removed := p.removeLocked(key, endpoint)
	if removed {
		if endpoint.pending != nil {
			// Sniffing timed out: the buffered datagrams are never sent.
			dropExpired.Add(uint64(len(endpoint.pending.packets)))
		}
		endpoint.retireLocked()
	}
	endpoint.mu.Unlock()
	p.UdpEndpointKeyLocker.Unlock(key, l)
	for _, conn := range expired {
		closeInBackground(conn)
	}
	if removed {
		endpoint.closeTrafficAccounting()
		_ = endpoint.Close()
	}
}
