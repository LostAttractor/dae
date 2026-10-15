package trojanc

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

func init() { protocol.Register("trojanc", NewDialer) }

type Dialer struct {
	ParentDialer netproxy.Dialer
	proxyAddress string
	password     string
}

func NewDialer(parent netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	return &Dialer{ParentDialer: parent, proxyAddress: header.ProxyAddress, password: header.Password}, nil
}

func (d *Dialer) dial(ctx context.Context, address string, command byte) (net.Conn, error) {
	target, err := socks5.AddressFromString(address)
	if err != nil {
		return nil, err
	}
	carrier, err := d.ParentDialer.DialContext(ctx, "tcp", d.proxyAddress)
	if err != nil {
		return nil, err
	}
	conn := newConn(carrier, target, command, d.password)
	if err := protocol.Handshake(ctx, conn, func() error { _, err := conn.Write(nil); return err }); err != nil {
		return nil, err
	}
	return conn, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp":
		return d.dial(ctx, address, commandConnect)
	case "udp":
		conn, err := d.ListenPacket(ctx, address)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{PacketConn: conn, Address: netproxy.NewAddr("udp", address)}, nil
	default:
		return nil, fmt.Errorf("%w: %s", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	conn, err := d.dial(ctx, address, commandUDP)
	if err != nil {
		return nil, err
	}
	return &PacketConn{Conn: conn}, nil
}
