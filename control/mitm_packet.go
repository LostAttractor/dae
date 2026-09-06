/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/daeuniverse/outbound/netproxy"
)

const (
	mitmPacketQueueSize = 64
	mitmPacketMaxSize   = 65535
)

var mitmPacketDrops udpPacketDrops

type mitmPacketPair struct {
	mu     sync.Mutex
	closed bool
	memory *membuffer.Budget
	lease  *netproxy.Lease
}

type mitmPacketConn struct {
	pair          *mitmPacketPair
	peer          *mitmPacketConn
	local         netip.AddrPort
	readDeadline  time.Time
	writeDeadline time.Time
	readChanged   chan struct{}
	packets       [mitmPacketQueueSize]udpPacket
	head          int
	count         int
}

// newMITMPacketPair bridges one transparent UDP flow to a QUIC server. The
// ingress side receives server responses with the original destination as their
// source; the server side receives client datagrams with the original client as
// their source. A full receive queue drops incoming datagrams, so a slow QUIC
// connection cannot block the transparent packet worker.
func newMITMPacketPair(client, destination netip.AddrPort) (ingress, server net.PacketConn) {
	pair := &mitmPacketPair{memory: udpPacketMemory, lease: netproxy.NewLease(netproxy.NewResourceRef())}
	a := &mitmPacketConn{pair: pair, local: client, readChanged: make(chan struct{})}
	b := &mitmPacketConn{pair: pair, local: destination, readChanged: make(chan struct{})}
	a.peer, b.peer = b, a
	return a, b
}

// Both bridge ends share the source lifetime's failure signal.
func (c *mitmPacketConn) DependencyLease() *netproxy.Lease { return c.pair.lease }

func (c *mitmPacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	for {
		c.pair.mu.Lock()
		if c.pair.closed {
			c.pair.mu.Unlock()
			return 0, nil, net.ErrClosed
		}
		deadline := c.readDeadline
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			c.pair.mu.Unlock()
			return 0, nil, os.ErrDeadlineExceeded
		}
		if c.count > 0 {
			packet := c.packets[c.head]
			c.packets[c.head] = udpPacket{}
			c.head = (c.head + 1) % mitmPacketQueueSize
			c.count--
			c.pair.mu.Unlock()
			n := copy(buf, packet.data)
			packet.release()
			return n, net.UDPAddrFromAddrPort(c.peer.local), nil
		}
		changed := c.readChanged
		c.pair.mu.Unlock()

		var timer *time.Timer
		var expired <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			expired = timer.C
		}
		select {
		case <-changed:
		case <-expired:
		}
		if timer != nil {
			timer.Stop()
		}
		// Recheck the deadline under the lock: a concurrent update may have
		// extended or cleared it while its previous timer was firing.
	}
}

func (c *mitmPacketConn) WriteTo(buf []byte, addr net.Addr) (int, error) {
	c.pair.mu.Lock()
	defer c.pair.mu.Unlock()
	if c.pair.closed {
		return 0, net.ErrClosed
	}
	if !c.writeDeadline.IsZero() && !time.Now().Before(c.writeDeadline) {
		return 0, os.ErrDeadlineExceeded
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil || !sameMITMPacketAddress(udpAddr.AddrPort(), c.peer.local) {
		return 0, &net.OpError{
			Op: "write", Net: "udp", Source: c.LocalAddr(), Addr: addr,
			Err: &net.AddrError{Err: "MITM packet connection only accepts its original peer", Addr: c.peer.local.String()},
		}
	}
	if len(buf) > mitmPacketMaxSize {
		return 0, &net.OpError{Op: "write", Net: "udp", Source: c.LocalAddr(), Addr: addr, Err: syscall.EMSGSIZE}
	}
	if c.peer.count == mitmPacketQueueSize {
		return len(buf), nil
	}
	index := (c.peer.head + c.peer.count) % mitmPacketQueueSize
	packet, ok := copyUDPPacket(buf, c.pair.memory)
	if !ok {
		mitmPacketDrops.report("packet_memory_limit")
		return len(buf), nil
	}
	c.peer.packets[index] = packet
	c.peer.count++
	if c.peer.count == 1 {
		c.peer.notifyReaders()
	}
	return len(buf), nil
}

func sameMITMPacketAddress(a, b netip.AddrPort) bool {
	return a.Port() == b.Port() && a.Addr().Unmap() == b.Addr().Unmap()
}

func (c *mitmPacketConn) Close() error {
	c.pair.mu.Lock()
	defer c.pair.mu.Unlock()
	if !c.pair.closed {
		c.pair.closed = true
		c.pair.lease.Invalidate(net.ErrClosed)
		close(c.readChanged)
		close(c.peer.readChanged)
		for i := range c.packets {
			c.packets[i].release()
			c.peer.packets[i].release()
		}
		c.count, c.peer.count = 0, 0
	}
	return nil
}

func (c *mitmPacketConn) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(c.local)
}

func (c *mitmPacketConn) SetDeadline(deadline time.Time) error {
	c.pair.mu.Lock()
	defer c.pair.mu.Unlock()
	if c.pair.closed {
		return net.ErrClosed
	}
	c.readDeadline, c.writeDeadline = deadline, deadline
	c.notifyReaders()
	return nil
}

func (c *mitmPacketConn) SetReadDeadline(deadline time.Time) error {
	c.pair.mu.Lock()
	defer c.pair.mu.Unlock()
	if c.pair.closed {
		return net.ErrClosed
	}
	c.readDeadline = deadline
	c.notifyReaders()
	return nil
}

func (c *mitmPacketConn) SetWriteDeadline(deadline time.Time) error {
	c.pair.mu.Lock()
	defer c.pair.mu.Unlock()
	if c.pair.closed {
		return net.ErrClosed
	}
	c.writeDeadline = deadline
	return nil
}

// notifyReaders requires the pair lock. Replacing the channel wakes all pending
// reads without making future reads spin on an already closed channel.
func (c *mitmPacketConn) notifyReaders() {
	close(c.readChanged)
	c.readChanged = make(chan struct{})
}
