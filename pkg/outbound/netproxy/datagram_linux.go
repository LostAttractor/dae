package netproxy

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/sys/unix"
)

// NewUDPSocket returns conn's socket for sends that never wait, or nil if it
// has none.
func NewUDPSocket(conn *net.UDPConn) *UDPSocket {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil
	}
	s := &UDPSocket{conn: conn, raw: raw}
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		s.family, optErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_DOMAIN)
	}); err != nil || optErr != nil {
		return nil
	}
	return s
}

// Send sends b, one datagram, to `to`, or to the connected peer if `to` is
// the zero AddrPort, with MSG_DONTWAIT. It returns unix.EAGAIN, having dropped
// b, if the send buffer is full, another errno if the send failed, and
// errors.ErrUnsupported, having sent nothing, for a nil socket, a zoned
// address or one of another family.
func (s *UDPSocket) Send(b []byte, to netip.AddrPort) error {
	if s == nil {
		return errors.ErrUnsupported
	}
	request := datagramSends.Get().(*datagramSend)
	defer func() {
		request.data, request.to, request.err = nil, nil, nil
		datagramSends.Put(request)
	}()
	if to.IsValid() {
		addr := to.Addr()
		switch {
		case addr.Zone() != "":
			return errors.ErrUnsupported
		case s.family == unix.AF_INET && addr.Unmap().Is4():
			request.v4.Port, request.v4.Addr = int(to.Port()), addr.Unmap().As4()
			request.to = &request.v4
		case s.family == unix.AF_INET6:
			request.v6.Port, request.v6.Addr = int(to.Port()), addr.As16()
			request.to = &request.v6
		default:
			return errors.ErrUnsupported
		}
	}
	request.data = b
	// Control, unlike Write, neither serializes with nor arms the poller's
	// write deadline: the send cannot wait.
	if err := s.raw.Control(request.send); err != nil {
		return err
	}
	return request.err
}

// Reused callback state: RawConn.Control's interface otherwise makes the
// closure, its result and the address escape for every datagram.
type datagramSend struct {
	data []byte
	to   unix.Sockaddr
	v4   unix.SockaddrInet4
	v6   unix.SockaddrInet6
	err  error
	send func(uintptr)
}

var datagramSends = sync.Pool{New: func() any {
	request := new(datagramSend)
	request.send = request.write
	return request
}}

func (w *datagramSend) write(fd uintptr) {
	for {
		w.err = unix.Sendto(int(fd), w.data, unix.MSG_DONTWAIT, w.to)
		if w.err != unix.EINTR {
			return
		}
	}
}
