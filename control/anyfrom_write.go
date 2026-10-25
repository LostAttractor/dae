// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

// trySend sends data to addr without waiting and without touching another
// writer's poller deadline. It returns syscall.EAGAIN if the send buffer is
// full, and errors.ErrUnsupported, having sent nothing, for an address only
// the net.UDPConn path can take or validate.
func (a *Anyfrom) trySend(data []byte, addr netip.AddrPort) error {
	if !addr.IsValid() {
		return errors.ErrUnsupported
	}
	a.socketOnce.Do(func() { a.socket = netproxy.NewUDPSocket(a.conn) })
	err := a.socket.Send(data, addr)
	if errno, ok := err.(syscall.Errno); ok && errno != syscall.EAGAIN {
		err = &net.OpError{Op: "write", Net: "udp", Source: a.conn.LocalAddr(), Addr: net.UDPAddrFromAddrPort(addr), Err: os.NewSyscallError("sendto", errno)}
	}
	return err
}

// WriteToUDPAddrPortWithDeadline sends without arming the socket deadline
// unless the socket is full: only then does it serialize and wait, until the
// deadline. Callers refresh the idle deadline before writing; that refresh
// also detects a closed socket.
func (a *Anyfrom) WriteToUDPAddrPortWithDeadline(b []byte, addr netip.AddrPort, deadline time.Time) (int, error) {
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	err := a.trySend(b, addr)
	switch {
	case err == nil:
		return len(b), nil
	case errors.Is(err, syscall.EAGAIN), errors.Is(err, errors.ErrUnsupported):
		return a.writeWithDeadline(b, addr, deadline)
	}
	return 0, err
}

// Only a would-block write needs a socket-wide deadline and serialization.
func (a *Anyfrom) writeWithDeadline(b []byte, addr netip.AddrPort, deadline time.Time) (n int, err error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	if err := a.conn.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	defer a.conn.SetWriteDeadline(time.Time{})
	return a.conn.WriteToUDPAddrPort(b, addr)
}
