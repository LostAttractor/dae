// SPDX-License-Identifier: AGPL-3.0-only

package netproxy

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

type trackedTestConn struct {
	net.Conn
	lease   *Lease
	half    atomic.Int32
	failure error
}

func (c *trackedTestConn) Close() error                          { return c.failure }
func (c *trackedTestConn) CloseWrite() error                     { c.half.Add(1); return nil }
func (c *trackedTestConn) DependencyLease() *Lease               { return c.lease }
func (c *trackedTestConn) SyscallConn() (syscall.RawConn, error) { return nil, c.failure }

type trackedTestPacket struct {
	net.PacketConn
	failure error
}

func (c *trackedTestPacket) Close() error                          { return c.failure }
func (c *trackedTestPacket) SyscallConn() (syscall.RawConn, error) { return nil, c.failure }

func TestTrackedConnectionPreservesOwnersAndCapabilities(t *testing.T) {
	failure := errors.New("socket close")
	raw := &trackedTestConn{Conn: new(net.TCPConn), lease: NewLease(NewResourceRef()), failure: failure}
	var a, b atomic.Int32
	conn := TrackConn(TrackConn(raw, func() { a.Add(1) }), func() { b.Add(1) })
	if DependencyOf(conn) != raw.lease || NativeTCPConn(conn) != nil {
		t.Fatal("tracking crossed a protocol adapter")
	}
	if _, err := conn.(syscall.Conn).SyscallConn(); !errors.Is(err, failure) {
		t.Fatal("raw socket access lost")
	}
	if err := CloseWrite(conn); err != nil || raw.half.Load() != 1 || a.Load()+b.Load() != 0 {
		t.Fatal("half-close released resource ownership")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if err := conn.Close(); !errors.Is(err, failure) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if a.Load() != 1 || b.Load() != 1 {
		t.Fatalf("references released %d/%d times", a.Load(), b.Load())
	}
	native := new(net.TCPConn)
	if NativeTCPConn(TrackConn(TrackConn(native, func() {}), func() {})) != native {
		t.Fatal("native socket hidden by tracking")
	}
}

func TestTrackedPacketReleasesEachOwnerOnce(t *testing.T) {
	failure := errors.New("packet close")
	var a, b atomic.Int32
	conn := TrackPacketConn(TrackPacketConn(&trackedTestPacket{failure: failure}, func() { a.Add(1) }), func() { b.Add(1) })
	if _, err := conn.(syscall.Conn).SyscallConn(); !errors.Is(err, failure) {
		t.Fatal("raw packet socket access lost")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if err := conn.Close(); !errors.Is(err, failure) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if a.Load() != 1 || b.Load() != 1 {
		t.Fatalf("packet references released %d/%d times", a.Load(), b.Load())
	}
}
