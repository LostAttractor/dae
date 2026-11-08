package netproxy

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"syscall"
)

// A kernel socket's send buffer was full: the link beneath it is congested.
var dropSocketFull = NewDrop("", DropUpload, "socket_full")

// TryWriteTo sends b to addr on conn as conn's NonBlockingWriter does, for a
// layer that sends its datagrams on conn. It returns errors.ErrUnsupported,
// having sent nothing, if conn can only wait.
func TryWriteTo(conn net.PacketConn, b []byte, addr net.Addr) (int, error) {
	if writer, ok := PacketConnAs[NonBlockingWriter](conn); ok {
		return writer.TryWriteTo(b, addr)
	}
	return 0, errors.ErrUnsupported
}

// CanTryWriteTo reports whether conn can try a send before a wrapping layer
// frames or encrypts it. Conditional writers implement CanTryWrite() bool to
// propagate their carrier's capability without exposing it through Unwrap.
// Address-specific restrictions may still make TryWriteTo return ErrUnsupported.
func CanTryWriteTo(conn net.PacketConn) bool {
	writer, ok := PacketConnAs[NonBlockingWriter](conn)
	if !ok {
		return false
	}
	if conditional, ok := writer.(interface{ CanTryWrite() bool }); ok {
		return conditional.CanTryWrite()
	}
	return true
}

// CanTryWrite is CanTryWriteTo for the connected carriers TryWrite supports.
func CanTryWrite(conn net.Conn) bool {
	switch c := conn.(type) {
	case *BindPacketConn:
		return CanTryWriteTo(c.PacketConn)
	case *trackedSyscallConn:
		return CanTryWrite(c.Conn)
	case *trackedConn:
		return CanTryWrite(c.Conn)
	case *net.UDPConn:
		return runtime.GOOS == "linux"
	}
	return false
}

// TryWrite is TryWriteTo for a connection to one peer: a BindPacketConn, or a
// connected kernel UDP socket, which drops b if its send buffer is full.
func TryWrite(conn net.Conn, b []byte) (int, error) {
	switch c := conn.(type) {
	case *BindPacketConn:
		return TryWriteTo(c.PacketConn, b, c.Address)
	case *trackedSyscallConn:
		return TryWrite(c.Conn, b)
	case *trackedConn:
		return TryWrite(c.Conn, b)
	case *net.UDPConn:
		raw, err := c.SyscallConn()
		if err != nil {
			return 0, err
		}
		return (&UDPSocket{conn: c, raw: raw}).TryWriteTo(b, nil)
	}
	return 0, errors.ErrUnsupported
}

// WriteDatagram writes b to conn's peer as a NonBlockingWriter's WriteTo
// does: a datagram TryWrite drops is reported as written. It waits only for a
// conn TryWrite cannot use.
func WriteDatagram(conn net.Conn, b []byte) (int, error) {
	n, err := TryWrite(conn, b)
	return finishDatagramWrite(conn, b, n, err)
}

// DatagramWriter borrows a connected carrier, caching its raw socket once
// instead of allocating a SyscallConn wrapper for every encrypted datagram.
// It never owns or closes conn, and never bypasses protocol wrappers.
type DatagramWriter struct {
	conn   net.Conn
	socket *UDPSocket
}

func NewDatagramWriter(conn net.Conn) DatagramWriter {
	w := DatagramWriter{conn: conn}
	for current := conn; ; {
		switch c := current.(type) {
		case *trackedSyscallConn:
			current = c.Conn
		case *trackedConn:
			current = c.Conn
		case *net.UDPConn:
			w.socket = NewUDPSocket(c)
			return w
		default:
			return w
		}
	}
}

// TryWrite has the same drop and fallback semantics as TryWrite on the carrier.
func (w *DatagramWriter) TryWrite(b []byte) (int, error) {
	if w.socket != nil {
		return w.socket.TryWriteTo(b, nil)
	}
	return TryWrite(w.conn, b)
}

// Write reports dropped datagrams as written, as WriteDatagram does.
func (w *DatagramWriter) Write(b []byte) (int, error) {
	n, err := w.TryWrite(b)
	return finishDatagramWrite(w.conn, b, n, err)
}

func finishDatagramWrite(conn net.Conn, b []byte, n int, err error) (int, error) {
	switch {
	case errors.Is(err, errors.ErrUnsupported):
		return conn.Write(b)
	case errors.Is(err, ErrPacketDropped):
		return len(b), nil
	}
	return n, err
}

// UDPSocket sends on a kernel UDP socket without waiting.
type UDPSocket struct {
	conn   *net.UDPConn
	raw    syscall.RawConn
	family int // of addressed sends
}

// TryWriteTo sends b to addr, a *net.UDPAddr, or to the connected peer if addr
// is nil, as a NonBlockingWriter does: a full send buffer drops b.
func (s *UDPSocket) TryWriteTo(b []byte, addr net.Addr) (int, error) {
	var to netip.AddrPort
	if addr != nil {
		udp, ok := addr.(*net.UDPAddr)
		if !ok {
			return 0, errors.ErrUnsupported
		}
		if udp == nil {
			return 0, &net.AddrError{Err: "missing UDP address", Addr: "<nil>"}
		}
		if udp.Port < 0 || udp.Port > 65535 {
			return 0, &net.AddrError{Err: "invalid UDP port", Addr: strconv.Itoa(udp.Port)}
		}
		to = udp.AddrPort()
		if len(udp.IP) == 0 {
			if s == nil {
				return 0, errors.ErrUnsupported
			}
			ip := netip.IPv6Unspecified()
			if s.conn.LocalAddr().(*net.UDPAddr).IP.To4() != nil {
				ip = netip.IPv4Unspecified()
			}
			to = netip.AddrPortFrom(ip, uint16(udp.Port))
		} else if !to.IsValid() {
			return 0, &net.AddrError{Err: "invalid UDP IP", Addr: udp.IP.String()}
		}
	}
	err := s.Send(b, to)
	switch {
	case err == nil:
		return len(b), nil
	case errors.Is(err, syscall.EAGAIN):
		dropSocketFull.Add(1)
		return 0, ErrPacketDropped
	case errors.Is(err, errors.ErrUnsupported):
		return 0, err
	}
	if errno, ok := err.(syscall.Errno); ok {
		err = os.NewSyscallError("sendto", errno)
	}
	if addr == nil {
		addr = s.conn.RemoteAddr()
	}
	return 0, &net.OpError{Op: "write", Net: "udp", Source: s.conn.LocalAddr(), Addr: addr, Err: err}
}
