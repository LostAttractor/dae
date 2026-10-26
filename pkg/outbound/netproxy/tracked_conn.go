// SPDX-License-Identifier: AGPL-3.0-only

package netproxy

import (
	"net"
	"sync"
	"syscall"
)

// TrackConn transfers a connection and one ownership reference to a wrapper.
// Closing releases the reference once, including when the underlying Close
// fails. Nested tracking shares a single connection wrapper, preserving native
// socket access, half-close and dependency identity through every owner.
func TrackConn(conn net.Conn, release func()) net.Conn {
	switch c := conn.(type) {
	case *trackedSyscallConn:
		return TrackConn(c.Conn, joinRelease(c.release, release))
	case *trackedConn:
		return TrackConn(c.Conn, joinRelease(c.release, release))
	}
	tracked := &trackedConn{Conn: conn, release: sync.OnceFunc(release)}
	if raw, ok := conn.(syscall.Conn); ok {
		return &trackedSyscallConn{tracked, raw}
	}
	return tracked
}

// TrackPacketConn is TrackConn's packet-oriented counterpart.
func TrackPacketConn(conn net.PacketConn, release func()) net.PacketConn {
	switch c := conn.(type) {
	case *trackedSyscallPacketConn:
		return TrackPacketConn(c.PacketConn, joinRelease(c.release, release))
	case *trackedPacketConn:
		return TrackPacketConn(c.PacketConn, joinRelease(c.release, release))
	}
	tracked := &trackedPacketConn{PacketConn: conn, release: sync.OnceFunc(release)}
	if raw, ok := conn.(syscall.Conn); ok {
		return &trackedSyscallPacketConn{tracked, raw}
	}
	return tracked
}

func joinRelease(inner, outer func()) func() {
	return func() { defer outer(); inner() }
}

type trackedConn struct {
	net.Conn
	release func()
}

func (c *trackedConn) Close() error            { defer c.release(); return c.Conn.Close() }
func (c *trackedConn) CloseWrite() error       { return CloseWrite(c.Conn) }
func (c *trackedConn) WriteThrough() net.Conn  { return c.Conn }
func (c *trackedConn) DependencyLease() *Lease { return DependencyOf(c.Conn) }

type trackedPacketConn struct {
	net.PacketConn
	release func()
}

func (c *trackedPacketConn) Close() error            { defer c.release(); return c.PacketConn.Close() }
func (c *trackedPacketConn) DependencyLease() *Lease { return DependencyOf(c.PacketConn) }
func (c *trackedPacketConn) Unwrap() net.PacketConn  { return c.PacketConn }

type trackedSyscallConn struct {
	*trackedConn
	raw syscall.Conn
}

func (c *trackedSyscallConn) SyscallConn() (syscall.RawConn, error) { return c.raw.SyscallConn() }

type trackedSyscallPacketConn struct {
	*trackedPacketConn
	raw syscall.Conn
}

func (c *trackedSyscallPacketConn) SyscallConn() (syscall.RawConn, error) { return c.raw.SyscallConn() }

// NativeTCPConn unwraps ownership tracking only. Protocol adapters are never
// unwrapped, and callers still close the original tracked connection.
func NativeTCPConn(conn net.Conn) *net.TCPConn {
	switch c := conn.(type) {
	case *net.TCPConn:
		return c
	case *trackedSyscallConn:
		return NativeTCPConn(c.Conn)
	case *trackedConn:
		return NativeTCPConn(c.Conn)
	default:
		return nil
	}
}

// BuffersWriterOf returns conn's vectorised writer, looking through ownership
// tracking, or nil if conn has none.
func BuffersWriterOf(conn net.Conn) BuffersWriter {
	switch c := conn.(type) {
	case *trackedSyscallConn:
		return BuffersWriterOf(c.Conn)
	case *trackedConn:
		return BuffersWriterOf(c.Conn)
	case BuffersWriter:
		return c
	}
	return nil
}

// PassthroughReader is implemented by adapters whose reads may become a
// verbatim pass-through. ReadPassthrough returns the wrapped connection once
// every later read is served from it unchanged, and nil before then.
type PassthroughReader interface{ ReadPassthrough() net.Conn }

// ReadSocket returns the TCP socket whose receive queue holds conn's next
// bytes unchanged, or nil. Unlike NativeTCPConn it also looks through
// pass-through readers, so the socket only suits receive tuning.
func ReadSocket(conn net.Conn) *net.TCPConn {
	switch c := conn.(type) {
	case *net.TCPConn:
		return c
	case *trackedSyscallConn:
		return ReadSocket(c.Conn)
	case *trackedConn:
		return ReadSocket(c.Conn)
	case PassthroughReader:
		if inner := c.ReadPassthrough(); inner != nil {
			return ReadSocket(inner)
		}
	}
	return nil
}

// WriteThrough is implemented by adapters that write what they are given,
// framed or encrypted, to one connection: WriteThrough returns it. The
// NetConn method of a crypto/tls connection serves as well.
type WriteThrough interface{ WriteThrough() net.Conn }

// SendSocket returns the TCP socket whose send queue takes conn's writes,
// or nil. Like ReadSocket it looks through adapters, so the socket only
// suits send tuning and polling, never writing.
func SendSocket(conn net.Conn) *net.TCPConn {
	switch c := conn.(type) {
	case *net.TCPConn:
		return c
	case WriteThrough:
		return SendSocket(c.WriteThrough())
	case interface{ NetConn() net.Conn }:
		return SendSocket(c.NetConn())
	}
	return nil
}
