package shadowsocks_stream

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

func init() { protocol.Register("shadowsocks_stream", NewDialer) }

type Dialer struct {
	ParentDialer netproxy.Dialer
	address      string
	cipher       *ciphers.StreamCipher
}

func NewDialer(parent netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	cipher, err := ciphers.NewStreamCipher(header.Cipher, header.Password)
	if err != nil {
		return nil, err
	}
	return &Dialer{ParentDialer: parent, address: header.ProxyAddress, cipher: cipher}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp":
		header := pool.GetBytesBuffer()
		defer pool.PutBytesBuffer(header)
		if err := socks5.WriteAddr(address, header); err != nil {
			return nil, err
		}
		conn, err := d.DialTCPTransport(ctx)
		if err != nil {
			return nil, err
		}
		if err := protocol.Handshake(ctx, conn, func() error { _, err := conn.Write(header.Bytes()); return err }); err != nil {
			return nil, err
		}
		return conn, nil
	case "udp":
		if _, err := socks5.AddressFromString(address); err != nil {
			return nil, err
		}
		conn, err := d.ListenPacket(ctx, address)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{PacketConn: conn, Address: netproxy.NewAddr("udp", address)}, nil
	default:
		return nil, fmt.Errorf("%w: %s", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, _ string) (net.PacketConn, error) {
	conn, err := d.DialUDPTransport(ctx)
	if err != nil {
		return nil, err
	}
	return &packetConn{UdpConn: conn}, nil
}

// The transport methods expose encryption without a destination header to SSR.
func (d *Dialer) DialTCPTransport(ctx context.Context) (*TcpConn, error) {
	cipher := d.cipher.Clone()
	conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	netproxy.CaptureDependency(ctx, conn)
	return NewTCPConn(conn, cipher), nil
}

func (d *Dialer) DialUDPTransport(ctx context.Context) (*UdpConn, error) {
	cipher := d.cipher.Clone()
	conn, err := d.ParentDialer.DialContext(ctx, "udp", d.address)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	netproxy.CaptureDependency(ctx, conn)
	return NewUDPConn(conn, cipher), nil
}
