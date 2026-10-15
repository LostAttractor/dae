package direct

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type PacketConn struct {
	*net.UDPConn
	dialer *directDialer
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if _, ok := addr.(*netproxy.ProxyAddr); ok {
		ctx, cancel := netproxy.NewDialTimeoutContextFrom(context.Background())
		defer cancel()
		addr, err = c.dialer.ResolveUDPAddr(ctx, addr.String())
		if err != nil {
			return
		}
	}
	if udp, ok := addr.(*net.UDPAddr); ok {
		family := c.dialer.ipVersion
		if family == "4" && udp.IP.To4() == nil || family == "6" && udp.IP.To4() != nil {
			return 0, fmt.Errorf("address %s conflicts with entry IPv%s", addr, family)
		}
	}
	return c.UDPConn.WriteTo(p, addr)
}
