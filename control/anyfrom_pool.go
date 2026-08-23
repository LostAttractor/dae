/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"golang.org/x/sys/unix"
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
	// GSO support is modified from quic-go with many thanks.
	gso         bool
	gotGSOError bool
}

func (a *Anyfrom) afterWrite(err error) {
	if !a.gotGSOError && isGSOError(err) {
		a.gotGSOError = true
	}
	a.refreshIdleDeadline()
}

// refreshIdleDeadline extends the pool eviction timer by the connection's idle TTL.
func (a *Anyfrom) refreshIdleDeadline() {
	if a.idleEvictTimer != nil {
		a.idleEvictTimer.Reset(a.idleTTL)
	}
}
func (a *Anyfrom) SupportGso(size int) bool {
	if size > math.MaxUint16 {
		return false
	}
	return a.gso && !a.gotGSOError
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
	defer func() { a.afterWrite(err) }()
	if a.SupportGso(len(b)) {
		return a.UDPConn.WriteMsgUDP(b, appendUDPSegmentSizeMsg(oob, uint16(len(b))), addr)
	}
	return a.UDPConn.WriteMsgUDP(b, oob, addr)
}
func (a *Anyfrom) WriteMsgUDPAddrPort(b []byte, oob []byte, addr netip.AddrPort) (n int, oobn int, err error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	defer func() { a.afterWrite(err) }()
	if a.SupportGso(len(b)) {
		return a.UDPConn.WriteMsgUDPAddrPort(b, appendUDPSegmentSizeMsg(oob, uint16(len(b))), addr)
	}
	return a.UDPConn.WriteMsgUDPAddrPort(b, oob, addr)
}
func (a *Anyfrom) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	defer func() { a.afterWrite(err) }()
	if a.SupportGso(len(b)) {
		n, _, err = a.UDPConn.WriteMsgUDP(b, appendUDPSegmentSizeMsg(nil, uint16(len(b))), addr.(*net.UDPAddr))
		return n, err
	}
	return a.UDPConn.WriteTo(b, addr)
}
func (a *Anyfrom) WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	defer func() { a.afterWrite(err) }()
	if a.SupportGso(len(b)) {
		n, _, err = a.UDPConn.WriteMsgUDP(b, appendUDPSegmentSizeMsg(nil, uint16(len(b))), addr)
		return n, err
	}
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
	defer func() { a.afterWrite(err) }()
	if a.SupportGso(len(b)) {
		n, _, err = a.UDPConn.WriteMsgUDPAddrPort(b, appendUDPSegmentSizeMsg(nil, uint16(len(b))), addr)
		return n, err
	}
	return a.UDPConn.WriteToUDPAddrPort(b, addr)
}

// isGSOSupported tests if the kernel supports GSO.
// Sending with GSO might still fail later on, if the interface doesn't support it (see isGSOError).
func isGSOSupported(uc *net.UDPConn) bool {
	// TODO: We disable GSO because we haven't thought through how to design to use larger packets (we assume the max size of packet is 1500).
	// See https://github.com/daeuniverse/dae/blob/cab1e4290967340923d7d5ca52b80f781711c18e/control/control_plane.go#L721C37-L721C37.
	var gsoDisabled = true
	if gsoDisabled {
		return false
	}
	conn, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	disabled, err := strconv.ParseBool(os.Getenv("DAE_DISABLE_GSO"))
	if err == nil && disabled {
		return false
	}
	var serr error
	if err := conn.Control(func(fd uintptr) {
		_, serr = unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
	}); err != nil {
		return false
	}
	return serr == nil
}
func isGSOError(err error) bool {
	var serr *os.SyscallError
	if errors.As(err, &serr) {
		// EIO is returned by udp_send_skb() if the device driver does not have tx checksums enabled,
		// which is a hard requirement of UDP_SEGMENT. See:
		// https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/tree/man7/udp.7?id=806eabd74910447f21005160e90957bde4db0183#n228
		// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/udp.c?h=v6.2&id=c9c3395d5e3dcc6daee66c6908354d47bf98cb0c#n942
		return serr.Err == unix.EIO || serr.Err == unix.EINVAL
	}
	return false
}
func appendUDPSegmentSizeMsg(b []byte, size uint16) []byte {
	startLen := len(b)
	const dataLen = 2 // payload is a uint16
	b = append(b, make([]byte, unix.CmsgSpace(dataLen))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[startLen]))
	h.Level = syscall.IPPROTO_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(dataLen))

	// UnixRights uses the private `data` method, but I *think* this achieves the same goal.
	offset := startLen + unix.CmsgSpace(0)
	*(*uint16)(unsafe.Pointer(&b[offset])) = size
	return b
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
		UDPConn:     uConn,
		idleTTL:     ttl,
		gotGSOError: false,
		gso:         isGSOSupported(uConn),
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
