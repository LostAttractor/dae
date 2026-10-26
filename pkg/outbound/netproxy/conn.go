package netproxy

import (
	"errors"
	"net"
	"net/netip"
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
// dropped because its queue or its socket's send buffer was full. It is
// returned unwrapped.
var ErrPacketDropped = errors.New("datagram dropped: transport queue full")

// NonBlockingWriter is a packet connection whose writes never wait: TryWriteTo
// queues or sends the datagram or drops it with ErrPacketDropped, for callers
// that account for sent datagrams, and WriteTo drops it without an error, as
// a congested link would. A queued datagram may still be dropped later, to
// make room or because it waited too long, without telling the caller. The
// transport counts every drop in a Drop; callers do not, also not those
// reported by ErrPacketDropped. Write deadlines have nothing to bound.
// A layer over a connection that can only wait returns errors.ErrUnsupported
// from TryWriteTo, unwrapped and having sent nothing, and its WriteTo waits;
// callers then use WriteTo. Such layers implement CanTryWrite() bool so outer
// layers can check the carrier before framing, encrypting or consuming send state.
type NonBlockingWriter interface {
	TryWriteTo(b []byte, addr net.Addr) (int, error)
}

// PacketPusher is implemented by packet connections that can push received
// datagrams instead of returning them from ReadFrom.
type PacketPusher interface {
	// SetPacketHandler hands every datagram received from now on to
	// onPacket, in order and never concurrently, on the transport's receive
	// goroutine, which onPacket must not block; payload is valid only during
	// the call, and from is the IP address it came from. onPacket must not
	// call methods of the connection. onClose then reports once why delivery
	// ended, with the error ReadFrom would return (also for a datagram from a
	// name), and is not followed by onPacket. It may run on any goroutine,
	// including one that closes the connection, so it must not block either;
	// it may close the connection. Set the handler before the first write. It
	// reports false, leaving ReadFrom, if the connection cannot push.
	SetPacketHandler(onPacket func(payload []byte, from netip.AddrPort), onClose func(error)) bool
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
