package shadowsocks

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/common"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

func init() {
	protocol.Register("shadowsocks", NewDialer)
}

type Dialer struct {
	ParentDialer netproxy.Dialer
	proxyAddress string
	conf         *ciphers.CipherConf
	key          []byte
	sg           SaltGenerator
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	conf := ciphers.AeadCiphersConf[header.Cipher]
	if conf == nil {
		return nil, fmt.Errorf("unsupported shadowsocks cipher: %s", header.Cipher)
	}
	key := common.EVPBytesToKey(header.Password, conf.KeyLen)
	sg := RandomSaltGenerator(conf.SaltLen)
	return &Dialer{
		ParentDialer: nextDialer,
		proxyAddress: header.ProxyAddress,
		conf:         conf,
		key:          key,
		sg:           sg,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp":
		addrInfo, err := socks5.AddressFromString(addr)
		if err != nil {
			return nil, err
		}
		// Shadowsocks transfer TCP traffic via TCP tunnel.
		conn, err := d.ParentDialer.DialContext(ctx, network, d.proxyAddress)
		if err != nil {
			return nil, err
		}
		client := NewTCPConn(conn, d.conf, d.key, d.sg, addrInfo)
		if err = protocol.Handshake(ctx, client, func() error { _, err := client.Write(nil); return err }); err != nil {
			return nil, err
		}
		return client, nil

	case "udp":
		conn, err := d.ListenPacket(ctx, d.proxyAddress)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{
			PacketConn: conn,
			Address:    netproxy.NewAddr("udp", addr),
		}, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

// DialTCPTransport exposes AEAD encryption without a destination header. The
// caller supplies the enclosing protocol's handshake as the first plaintext.
func (d *Dialer) DialTCPTransport(ctx context.Context) (net.Conn, error) {
	conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.proxyAddress)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	netproxy.CaptureDependency(ctx, conn)
	return NewTCPConn(conn, d.conf, d.key, d.sg, nil), nil
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	// Shadowsocks transfer UDP traffic via UDP tunnel.
	conn, err := d.ParentDialer.DialContext(ctx, "udp", d.proxyAddress)
	if err != nil {
		return nil, err
	}
	return NewUdpConn(conn, d.conf, d.key, d.sg), nil
}
