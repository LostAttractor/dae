/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
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
}

// Activity advances the deadline; the eviction callback rearms itself if early.
func (a *Anyfrom) refreshIdleDeadline() {
	a.idleMu.Lock()
	defer a.idleMu.Unlock()
	a.idleDeadline = time.Now().Add(a.idleTTL)
}

// Close can interrupt an in-flight write without waiting for its deadline.
func (a *Anyfrom) Close() error { return a.conn.Close() }

func (a *Anyfrom) WriteToUDPAddrPortWithDeadline(b []byte, addr netip.AddrPort, deadline time.Time) (n int, err error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	if err := a.conn.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	defer a.conn.SetWriteDeadline(time.Time{})

	defer a.refreshIdleDeadline()
	return a.conn.WriteToUDPAddrPort(b, addr)
}

// AnyfromPool is a full-cone udp listener pool
type AnyfromPool struct {
	pool map[netip.AddrPort]*Anyfrom
	mu   sync.Mutex
}

var DefaultAnyfromPool = NewAnyfromPool()

var anyfromSoMark atomic.Uint32

func SetAnyfromSoMark(mark uint32) {
	anyfromSoMark.Store(mark)
}

func NewAnyfromPool() *AnyfromPool {
	return &AnyfromPool{
		pool: make(map[netip.AddrPort]*Anyfrom, 64),
	}
}

// GetOrCreate returns a pooled UDP socket bound to lAddr. ttl is the idle time before eviction;
// if ttl <= 0, DefaultAnyfromCacheTTL is used so entries are always pooled and closed on idle.
func (p *AnyfromPool) GetOrCreate(lAddr netip.AddrPort, ttl time.Duration) (conn *Anyfrom, isNew bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	ttl = normalizeAnyfromPoolTTL(ttl)

	af, ok := p.pool[lAddr]
	if ok {
		af.refreshIdleDeadline()
		return af, false, nil
	}

	lc := net.ListenConfig{
		Control: func(network string, address string, c syscall.RawConn) error {
			if err := transparentControl(c); err != nil {
				return err
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
		return nil, true, err
	}

	uConn := pc.(*net.UDPConn)
	af = &Anyfrom{
		conn:         uConn,
		idleTTL:      ttl,
		idleDeadline: time.Now().Add(ttl),
	}
	af.idleEvictTimer = time.AfterFunc(ttl, func() { p.expire(lAddr, af) })
	p.pool[lAddr] = af

	return af, true, nil
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
