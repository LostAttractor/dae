/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

// DefaultAnyfromCacheTTL is the eviction interval when GetOrCreate is called with ttl <= 0.
// Pooled sockets always use a positive TTL so they are removed from the pool and closed
// without requiring callers to Close (e.g. sendPkt).
const DefaultAnyfromCacheTTL = 5 * time.Second

func normalizeAnyfromPoolTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return DefaultAnyfromCacheTTL
	}
	return ttl
}

type Anyfrom struct {
	conn           *net.UDPConn
	idleMu         sync.Mutex
	idleEvictTimer *time.Timer
	idleTTL        time.Duration
	idleDeadline   time.Time
	writeMu        sync.Mutex
	socketOnce     sync.Once
	socket         *netproxy.UDPSocket
	closed         atomic.Bool
	closeMu        sync.Mutex
}

// Activity advances the deadline; the eviction callback rearms itself if early.
func (a *Anyfrom) refreshIdleDeadline() bool {
	a.idleMu.Lock()
	defer a.idleMu.Unlock()
	if a.closed.Load() {
		return false
	}
	a.idleDeadline = time.Now().Add(a.idleTTL)
	return true
}

// Close can interrupt an in-flight write without waiting for its deadline.
func (a *Anyfrom) Close() error {
	a.closeMu.Lock()
	defer a.closeMu.Unlock()
	err := a.conn.Close()
	// A replacement must not reuse this slot until the descriptor is closed.
	a.closed.Store(true)
	return err
}

// Send the DNS cookie and mark per message without changing shared socket identity.
func (a *Anyfrom) writeDNSReply(data, oob []byte, addr netip.AddrPort, deadline time.Time) (int, error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	if err := a.conn.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	defer a.conn.SetWriteDeadline(time.Time{})
	n, _, err := a.conn.WriteMsgUDPAddrPort(data, oob, addr)
	return n, err
}

// AnyfromPool is a full-cone udp listener pool
type AnyfromPool struct {
	pool     map[netip.AddrPort]*Anyfrom
	creating map[netip.AddrPort]chan struct{}
	failed   map[netip.AddrPort]anyfromFailure
	mu       sync.RWMutex
	limit    int
	listen   func(netip.AddrPort) (*net.UDPConn, error)
}

// An address that cannot be bound, such as one a local listener holds, fails
// fast for anyfromRetryDelay instead of repeating socket setup per reply.
// Exhausted descriptors are global and retried at once.
type anyfromFailure struct {
	err   error
	until time.Time
}

const anyfromRetryDelay = time.Second

var DefaultAnyfromPool = NewAnyfromPool()

var dropReplySocketLimit = netproxy.NewDrop("", netproxy.DropDownload, "reply_socket_limit")

var anyfromSoMark atomic.Uint32

func SetAnyfromSoMark(mark uint32) {
	anyfromSoMark.Store(mark)
}

func NewAnyfromPool() *AnyfromPool {
	return &AnyfromPool{
		pool:     make(map[netip.AddrPort]*Anyfrom, 64),
		creating: make(map[netip.AddrPort]chan struct{}),
		failed:   make(map[netip.AddrPort]anyfromFailure),
		// Each reply address costs one descriptor, including in-flight creation.
		limit:  maxUDPSources,
		listen: listenAnyfrom,
	}
}

func (p *AnyfromPool) usage() (used, limit int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.pool) + len(p.creating), p.limit
}

// TryGet returns the live pooled socket bound to lAddr and refreshes its idle
// time, or nil, without waiting, if there is none or the pool is locked.
func (p *AnyfromPool) TryGet(lAddr netip.AddrPort) *Anyfrom {
	if !p.mu.TryRLock() {
		return nil
	}
	defer p.mu.RUnlock()
	if af := p.pool[lAddr]; af != nil && af.refreshIdleDeadline() {
		return af
	}
	return nil
}

// GetOrCreate returns a pooled UDP socket bound to lAddr. ttl is the idle time before eviction;
// if ttl <= 0, DefaultAnyfromCacheTTL is used so entries are always pooled and closed on idle.
func (p *AnyfromPool) GetOrCreate(lAddr netip.AddrPort, ttl time.Duration) (conn *Anyfrom, isNew bool, err error) {
	// Hits share the lock, so they never make TryGet on the push path fail.
	p.mu.RLock()
	if af := p.pool[lAddr]; af != nil && af.refreshIdleDeadline() {
		p.mu.RUnlock()
		return af, false, nil
	}
	p.mu.RUnlock()
	p.mu.Lock()
	for {
		if af := p.pool[lAddr]; af != nil {
			if af.refreshIdleDeadline() {
				p.mu.Unlock()
				return af, false, nil
			}
			delete(p.pool, lAddr)
			if af.idleEvictTimer != nil {
				af.idleEvictTimer.Stop()
			}
		}
		if ready := p.creating[lAddr]; ready != nil {
			p.mu.Unlock()
			<-ready
			p.mu.Lock()
			continue
		}
		break
	}
	if failure, ok := p.failed[lAddr]; ok {
		if time.Now().Before(failure.until) {
			p.mu.Unlock()
			return nil, true, failure.err
		}
		delete(p.failed, lAddr)
	}
	if len(p.pool)+len(p.creating) >= p.limit {
		p.mu.Unlock()
		dropReplySocketLimit.Add(1)
		return nil, true, netproxy.ErrPacketDropped
	}
	ready := make(chan struct{})
	p.creating[lAddr] = ready
	p.mu.Unlock()

	uConn, err := p.listen(lAddr)
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.creating, lAddr)
	defer close(ready)
	if err != nil {
		if !errors.Is(err, syscall.EADDRINUSE) && !errors.Is(err, syscall.EADDRNOTAVAIL) {
			return nil, true, err
		}
		now := time.Now()
		if len(p.failed) >= p.limit {
			maps.DeleteFunc(p.failed, func(_ netip.AddrPort, f anyfromFailure) bool { return !now.Before(f.until) })
		}
		if len(p.failed) < p.limit {
			p.failed[lAddr] = anyfromFailure{err, now.Add(anyfromRetryDelay)}
		}
		return nil, true, err
	}

	ttl = normalizeAnyfromPoolTTL(ttl)
	af := &Anyfrom{
		conn:         uConn,
		idleTTL:      ttl,
		idleDeadline: time.Now().Add(ttl),
	}
	af.idleEvictTimer = time.AfterFunc(ttl, func() { p.expire(lAddr, af) })
	p.pool[lAddr] = af
	return af, true, nil
}

func listenAnyfrom(lAddr netip.AddrPort) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network string, address string, c syscall.RawConn) error {
			if err := transparentControl(c); err != nil {
				return err
			}
			var socketErr error
			if err := c.Control(func(fd uintptr) { socketErr = enableDNSReplyMetadata(int(fd)) }); err != nil {
				return err
			}
			if socketErr != nil {
				return socketErr
			}
			if mark := anyfromSoMark.Load(); mark != 0 {
				return netproxy.SoMarkControl(c, int(mark))
			}
			return nil
		},
		KeepAlive: 0,
	}

	pc, err := GetDaeNetns().With(func() (net.PacketConn, error) {
		return lc.ListenPacket(context.Background(), "udp", lAddr.String())
	})
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

func (p *AnyfromPool) expire(addr netip.AddrPort, conn *Anyfrom) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pool[addr] != conn {
		return
	}
	conn.idleMu.Lock()
	defer conn.idleMu.Unlock()
	// Activity may have advanced the deadline while this callback was waiting.
	if remaining := time.Until(conn.idleDeadline); remaining > 0 {
		conn.idleEvictTimer.Reset(remaining)
		return
	}
	delete(p.pool, addr)
	_ = conn.Close()
}
