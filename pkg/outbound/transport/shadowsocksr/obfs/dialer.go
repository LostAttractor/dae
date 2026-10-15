package obfs

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type Dialer struct {
	ParentDialer netproxy.Dialer
	param        ObfsParam
	constructor  constructor
}

type ObfsParam struct {
	ObfsHost  string
	ObfsPort  uint16
	Obfs      string
	ObfsParam string
}

func NewDialer(parent netproxy.Dialer, param *ObfsParam) (*Dialer, error) {
	factory, ok := constructors[param.Obfs]
	if !ok {
		return nil, fmt.Errorf("unsupported SSR obfuscation %q", param.Obfs)
	}
	return &Dialer{ParentDialer: parent, param: *param, constructor: factory}, nil
}

func (d *Dialer) ObfsOverhead() int { return d.constructor.Overhead }

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network == "udp" {
		return d.ParentDialer.DialContext(ctx, network, address)
	}
	if network != "tcp" {
		return nil, fmt.Errorf("%w: SSR obfuscation+%s", netproxy.UnsupportedTunnelTypeError, network)
	}
	conn, err := d.ParentDialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	codec := d.constructor.New()
	codec.SetServerInfo(&ServerInfo{Host: d.param.ObfsHost, Port: d.param.ObfsPort, Param: d.param.ObfsParam})
	return &Conn{Conn: conn, codec: codec, addrLen: 30}, nil
}

func (d *Dialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return d.ParentDialer.ListenPacket(ctx, address)
}
