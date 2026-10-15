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
func (c *trackedConn) DependencyLease() *Lease { return DependencyOf(c.Conn) }

type trackedPacketConn struct {
	net.PacketConn
	release func()
}

func (c *trackedPacketConn) Close() error            { defer c.release(); return c.PacketConn.Close() }
func (c *trackedPacketConn) DependencyLease() *Lease { return DependencyOf(c.PacketConn) }

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
