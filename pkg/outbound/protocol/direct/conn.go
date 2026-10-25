package direct

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type PacketConn struct {
	*net.UDPConn
	dialer *directDialer
	socket *netproxy.UDPSocket
}

// TryWriteTo never waits: a full send buffer drops the datagram. A name
// target needs resolving, which may wait: it returns errors.ErrUnsupported.
func (c *PacketConn) TryWriteTo(p []byte, addr net.Addr) (int, error) {
	if _, ok := addr.(*netproxy.ProxyAddr); ok {
		return 0, errors.ErrUnsupported
	}
	if err := c.checkFamily(addr); err != nil {
		return 0, err
	}
	return c.socket.TryWriteTo(p, addr)
}

// WriteTo waits only to resolve a name target; a full send buffer drops the
// datagram, which is reported as written.
func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if _, ok := addr.(*netproxy.ProxyAddr); ok {
		ctx, cancel := netproxy.NewDialTimeoutContextFrom(context.Background())
		defer cancel()
		addr, err = c.dialer.ResolveUDPAddr(ctx, addr.String())
		if err != nil {
			return
		}
	}
	if err := c.checkFamily(addr); err != nil {
		return 0, err
	}
	n, err = c.socket.TryWriteTo(p, addr)
	switch {
	case errors.Is(err, errors.ErrUnsupported):
		return c.UDPConn.WriteTo(p, addr)
	case errors.Is(err, netproxy.ErrPacketDropped):
		return len(p), nil
	}
	return n, err
}

func (c *PacketConn) checkFamily(addr net.Addr) error {
	if udp, ok := addr.(*net.UDPAddr); ok && udp != nil {
		family := c.dialer.ipVersion
		if family == "4" && udp.IP.To4() == nil || family == "6" && udp.IP.To4() != nil {
			return fmt.Errorf("address %s conflicts with entry IPv%s", addr, family)
		}
	}
	return nil
}

// CanTryWrite reports whether the platform supports nonblocking socket sends.
func (c *PacketConn) CanTryWrite() bool { return c.socket != nil }
