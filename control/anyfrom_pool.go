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

	"github.com/daeuniverse/dae/component/outbound/dialer"
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
	*net.UDPConn
	idleEvictTimer *time.Timer
	idleTTL        time.Duration
	writeMu        sync.Mutex
}

// refreshIdleDeadline extends the pool eviction timer by the connection's idle TTL.
func (a *Anyfrom) refreshIdleDeadline() {
	if a.idleEvictTimer != nil {
		a.idleEvictTimer.Reset(a.idleTTL)
	}
}

func (a *Anyfrom) ReadFrom(b []byte) (int, net.Addr, error) {
	defer a.refreshIdleDeadline()
	return a.UDPConn.ReadFrom(b)
}
func (a *Anyfrom) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	defer a.refreshIdleDeadline()
	return a.UDPConn.ReadFromUDP(b)
}
func (a *Anyfrom) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	defer a.refreshIdleDeadline()
	return a.UDPConn.ReadFromUDPAddrPort(b)
}
func (a *Anyfrom) ReadMsgUDP(b []byte, oob []byte) (n int, oobn int, flags int, addr *net.UDPAddr, err error) {
	defer a.refreshIdleDeadline()
	return a.UDPConn.ReadMsgUDP(b, oob)
}
func (a *Anyfrom) ReadMsgUDPAddrPort(b []byte, oob []byte) (n int, oobn int, flags int, addr netip.AddrPort, err error) {
	defer a.refreshIdleDeadline()
	return a.UDPConn.ReadMsgUDPAddrPort(b, oob)
}
func (a *Anyfrom) SyscallConn() (syscall.RawConn, error) {
	defer a.refreshIdleDeadline()
	return a.UDPConn.SyscallConn()
}
func (a *Anyfrom) WriteMsgUDP(b []byte, oob []byte, addr *net.UDPAddr) (n int, oobn int, err error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	defer a.refreshIdleDeadline()
	return a.UDPConn.WriteMsgUDP(b, oob, addr)
}
func (a *Anyfrom) WriteMsgUDPAddrPort(b []byte, oob []byte, addr netip.AddrPort) (n int, oobn int, err error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	defer a.refreshIdleDeadline()
	return a.UDPConn.WriteMsgUDPAddrPort(b, oob, addr)
}
func (a *Anyfrom) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	defer a.refreshIdleDeadline()
	return a.UDPConn.WriteTo(b, addr)
}
func (a *Anyfrom) WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	defer a.refreshIdleDeadline()
	return a.UDPConn.WriteToUDP(b, addr)
}
func (a *Anyfrom) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (n int, err error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	return a.writeToUDPAddrPort(b, addr)
}

func (a *Anyfrom) WriteToUDPAddrPortWithDeadline(b []byte, addr netip.AddrPort, deadline time.Time) (n int, err error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	if err := a.UDPConn.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	defer a.UDPConn.SetWriteDeadline(time.Time{})
	return a.writeToUDPAddrPort(b, addr)
}

func (a *Anyfrom) writeToUDPAddrPort(b []byte, addr netip.AddrPort) (n int, err error) {
	defer a.refreshIdleDeadline()
	return a.UDPConn.WriteToUDPAddrPort(b, addr)
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
			if err := dialer.TransparentControl(c); err != nil {
				return err
			}
			if mark := anyfromSoMark.Load(); mark != 0 {
				return dialer.SoMarkControl(c, int(mark))
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
		UDPConn: uConn,
		idleTTL: ttl,
	}
	af.idleEvictTimer = time.AfterFunc(ttl, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		_af := p.pool[lAddr]
		if _af == af {
			delete(p.pool, lAddr)
			af.Close()
		}
	})
	p.pool[lAddr] = af

	return af, true, nil
}
