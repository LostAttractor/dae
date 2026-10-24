package netproxy

import (
	"errors"
	"net"
)

var UnsupportedTunnelTypeError = net.UnknownNetworkError("unsupported tunnel type")

// CloseWriter sends a write-side EOF while preserving reads. Implementations
// that cannot half-close return errors.ErrUnsupported directly; wrapped or
// joined errors report a failed close operation.
type CloseWriter interface {
	CloseWrite() error
}

// CloseWrite preserves reads when supported. ErrUnsupported means the caller
// must decide how long to drain the reverse direction.
func CloseWrite(conn net.Conn) error {
	if writer, ok := conn.(CloseWriter); ok {
		return writer.CloseWrite()
	}
	return errors.ErrUnsupported
}

// BuffersWriter writes the concatenation of its buffers as a single Write
// would, framing them together where the protocol frames writes. It does not
// modify the buffers.
type BuffersWriter interface {
	WriteBuffers(v [][]byte) (int, error)
}

// ErrPacketDropped reports a datagram that NonBlockingWriter.TryWriteTo
// dropped because its queue was full. It is returned unwrapped.
var ErrPacketDropped = errors.New("datagram dropped: transport queue full")

// NonBlockingWriter is a packet connection whose writes never wait: TryWriteTo
// queues the datagram or drops it with ErrPacketDropped, for callers that
// account for drops, and WriteTo drops it without an error, as a congested
// link would. Write deadlines have nothing to bound.
type NonBlockingWriter interface {
	TryWriteTo(b []byte, addr net.Addr) (int, error)
}

// PacketConnAs finds T in conn or in the connections it wraps, following
// Unwrap() net.PacketConn. Wrappers that unwrap preserve how writes block and
// how datagrams are received, or implement T themselves.
func PacketConnAs[T any](conn net.PacketConn) (T, bool) {
	for conn != nil {
		if t, ok := conn.(T); ok {
			return t, true
		}
		wrapper, ok := conn.(interface{ Unwrap() net.PacketConn })
		if !ok {
			break
		}
		conn = wrapper.Unwrap()
	}
	var zero T
	return zero, false
}

type CloseWriteConn struct {
	net.Conn
	CloseWriter
}

type BindPacketConn struct {
	net.PacketConn
	Address net.Addr
}

func (c *BindPacketConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.Address)
}

func (c *BindPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *BindPacketConn) RemoteAddr() net.Addr {
	return c.Address
}

func (c *CloseWriteConn) DependencyLease() *Lease { return DependencyOf(c.Conn) }
func (c *BindPacketConn) DependencyLease() *Lease { return DependencyOf(c.PacketConn) }
