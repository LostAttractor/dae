// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Most UDP writes complete immediately. Raw Control pins the descriptor across
// a nonblocking send without changing another writer's poller deadline. EAGAIN
// falls back to the serialized net.UDPConn path, which waits with this packet's
// deadline and remains interruptible by Close.
func (a *Anyfrom) tryWrite(data []byte, addr netip.AddrPort, deadline time.Time) (n int, err error, attempted bool) {
	if !addr.IsValid() || addr.Addr().Zone() != "" {
		return 0, nil, false
	}
	a.rawOnce.Do(func() {
		a.raw, a.rawErr = a.conn.SyscallConn()
		if a.rawErr != nil {
			return
		}
		var optionErr error
		controlErr := a.raw.Control(func(fd uintptr) {
			a.family, optionErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_DOMAIN)
		})
		a.rawErr = errors.Join(controlErr, optionErr)
	})
	if a.rawErr != nil || a.raw == nil {
		return 0, nil, false
	}

	request := anyfromWrites.Get().(*anyfromWrite)
	defer func() {
		request.data, request.destination, request.err = nil, nil, nil
		anyfromWrites.Put(request)
	}()
	switch a.family {
	case unix.AF_INET:
		if !addr.Addr().Is4In6() && !addr.Addr().Is4() {
			return 0, nil, false
		}
		request.v4.Port, request.v4.Addr = int(addr.Port()), addr.Addr().Unmap().As4()
		request.destination = &request.v4
	case unix.AF_INET6:
		request.v6.Port, request.v6.Addr = int(addr.Port()), addr.Addr().As16()
		request.destination = &request.v6
	default:
		return 0, nil, false
	}
	request.data, request.deadline = data, deadline
	err = a.raw.Control(request.send)
	sendErr := request.err

	if err != nil {
		return 0, err, true
	}
	if errors.Is(sendErr, unix.EAGAIN) {
		return 0, nil, false
	}
	if sendErr != nil {
		return 0, &net.OpError{Op: "write", Net: "udp", Source: a.conn.LocalAddr(), Addr: net.UDPAddrFromAddrPort(addr), Err: sendErr}, true
	}
	return len(data), nil, true
}

// Reuse callback state: RawConn.Control's interface otherwise makes the closure,
// result and sockaddr escape on every packet. No data is retained after return.
type anyfromWrite struct {
	data        []byte
	destination unix.Sockaddr
	v4          unix.SockaddrInet4
	v6          unix.SockaddrInet6
	deadline    time.Time
	err         error
	send        func(uintptr)
}

var anyfromWrites = sync.Pool{New: func() any {
	request := new(anyfromWrite)
	request.send = request.write
	return request
}}

func (w *anyfromWrite) write(fd uintptr) {
	for {
		if !w.deadline.IsZero() && !time.Now().Before(w.deadline) {
			w.err = os.ErrDeadlineExceeded
			return
		}
		w.err = unix.Sendto(int(fd), w.data, unix.MSG_DONTWAIT, w.destination)
		if !errors.Is(w.err, unix.EINTR) {
			return
		}
	}
}
