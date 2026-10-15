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
