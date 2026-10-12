package proto

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
	"github.com/daeuniverse/outbound/protocol/shadowsocks_stream"
)

type Dialer struct {
	parent   *shadowsocks_stream.Dialer
	name     string
	param    string
	overhead int
}

func NewDialer(parent netproxy.Dialer, name, param string, overhead int) (*Dialer, error) {
	stream, ok := parent.(*shadowsocks_stream.Dialer)
	if !ok {
		return nil, fmt.Errorf("SSR requires a stream cipher dialer, got %T", parent)
	}
	if NewProtocol(name) == nil {
		return nil, fmt.Errorf("unsupported SSR protocol %q", name)
	}
	switch name {
	case "auth_chain_a", "auth_chain_b", "auth_aes128_md5", "auth_aes128_sha1":
		if _, _, err := parseUserParam(param); err != nil {
			return nil, err
		}
	}
	return &Dialer{parent: stream, name: name, param: param, overhead: overhead}, nil
}

func (d *Dialer) newProtocol(cipher *ciphers.StreamCipher, addrLen int) (IProtocol, error) {
	iv, err := cipher.InitEncrypt()
	if err != nil {
		return nil, err
	}
	codec := NewProtocol(d.name)
	if err := codec.InitWithServerInfo(&ServerInfo{Param: d.param, TcpMss: 1460, IV: iv, Key: cipher.Key(), AddrLen: addrLen, Overhead: codec.GetOverhead() + d.overhead}); err != nil {
		return nil, err
	}
	return codec, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp":
		addr, err := socks.ParseAddr(address)
		if err != nil {
			return nil, err
		}
		conn, err := d.parent.DialTCPTransport(ctx)
		if err != nil {
			return nil, err
		}
		codec, err := d.newProtocol(conn.Cipher(), len(addr))
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		c := &Conn{Conn: conn, codec: codec}
		if err := protocol.Handshake(ctx, c, func() error {
			if _, err := c.Write(addr); err != nil {
				return err
			}
			if obfs, ok := conn.Conn.(interface{ Handshake() error }); ok {
				return obfs.Handshake()
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return c, nil
	case "udp":
		if _, err := socks.ParseAddr(address); err != nil {
			return nil, err
		}
		conn, err := d.ListenPacket(ctx, address)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{PacketConn: conn, Address: netproxy.NewAddr("udp", address)}, nil
	default:
		return nil, fmt.Errorf("%w: SSR+%s", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, _ string) (net.PacketConn, error) {
	conn, err := d.parent.DialUDPTransport(ctx)
	if err != nil {
		return nil, err
	}
	codec, err := d.newProtocol(conn.Cipher(), 0)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &PacketConn{Conn: conn, codec: codec}, nil
}
