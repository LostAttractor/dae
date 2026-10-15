package vless

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/vless/vision"
)

const XRV = "xtls-rprx-vision"

func init() { protocol.Register("vless", NewDialer) }

type Dialer struct {
	ParentDialer  netproxy.Dialer
	address, flow string
	key           []byte
}

func NewDialer(parent netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	key, err := Password2Key(header.Password)
	if err != nil {
		return nil, err
	}
	flow := ""
	if header.Feature1 != nil {
		var ok bool
		flow, ok = header.Feature1.(string)
		if !ok {
			return nil, fmt.Errorf("invalid VLESS flow type")
		}
	}
	if flow != "" && flow != XRV {
		return nil, fmt.Errorf("unsupported VLESS flow: %s", flow)
	}
	return &Dialer{ParentDialer: parent, address: header.ProxyAddress, flow: flow, key: key}, nil
}
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp":
		return d.open(ctx, network, address)
	case "udp":
		c, err := d.openPacket(ctx, address)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{PacketConn: c, Address: netproxy.NewAddr("udp", address)}, nil
	default:
		return nil, fmt.Errorf("%w: %s", netproxy.UnsupportedTunnelTypeError, network)
	}
}
func (d *Dialer) open(ctx context.Context, network, address string) (net.Conn, error) {
	target, err := socks5.AddressFromString(address)
	if err != nil {
		return nil, err
	}
	if len(target.Hostname) > 255 {
		return nil, fmt.Errorf("VLESS hostname exceeds 255 bytes")
	}
	header := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(header)
	header.WriteByte(0)
	header.Write(d.key)
	if d.flow != "" {
		header.WriteByte(byte(2 + len(d.flow)))
		header.WriteByte(10)
		header.WriteByte(byte(len(d.flow)))
		header.WriteString(d.flow)
	} else {
		header.WriteByte(0)
	}
	command := byte(1)
	if network == "udp" {
		command = 2
		if d.flow == XRV {
			command = 3
		}
	}
	header.WriteByte(command)
	if command != 3 {
		header.WriteByte(byte(target.Port >> 8))
		header.WriteByte(byte(target.Port))
		switch target.Type {
		case socks5.AddressTypeIPv4:
			header.WriteByte(1)
			header.Write(target.IP.AsSlice())
		case socks5.AddressTypeIPv6:
			header.WriteByte(3)
			header.Write(target.IP.AsSlice())
		case socks5.AddressTypeDomain:
			header.WriteByte(2)
			header.WriteByte(byte(len(target.Hostname)))
			header.WriteString(target.Hostname)
		}
	}
	parent, err := d.ParentDialer.DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, err
	}
	netproxy.CaptureDependency(ctx, parent)
	conn := &Conn{Conn: parent}
	var result net.Conn = conn
	err = protocol.Handshake(ctx, parent, func() error {
		if d.flow == XRV {
			var err error
			result, err = vision.NewConn(conn, d.key)
			if err != nil {
				return err
			}
		}
		_, err := conn.Write(header.Bytes())
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
func (d *Dialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	if d.flow == XRV {
		return d.openPacket(ctx, address)
	}
	return protocol.NewPacketAssociation(ctx, address, d.openPacket)
}

func (d *Dialer) openPacket(ctx context.Context, address string) (net.PacketConn, error) {
	conn, err := d.open(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	target := netproxy.NewAddr("udp", address)
	if d.flow == XRV {
		return vision.NewPacketConn(conn.(*vision.Conn), target), nil
	}
	return newPacketConn(conn, target), nil
}
