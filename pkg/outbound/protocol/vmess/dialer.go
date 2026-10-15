package vmess

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/daeuniverse/dae/pkg/outbound/common"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
	"github.com/google/uuid"
)

func init() { protocol.Register("vmess", NewDialer) }

type Dialer struct {
	ParentDialer netproxy.Dialer
	address      string
	cipher       Cipher
	key          [16]byte
	packetAddr   bool
}

func NewDialer(parent netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	cipher := Cipher(header.Cipher)
	if cipher == "" || cipher == "auto" {
		cipher = CipherAES128GCM
	}
	if _, ok := NewCipherMapper[cipher]; !ok {
		return nil, fmt.Errorf("unsupported VMess cipher: %s", cipher)
	}
	password := header.Password
	if len(password) < 32 || len(password) > 36 {
		password = common.StringToUUID5(password)
	}
	id, err := uuid.Parse(password)
	if err != nil {
		return nil, err
	}
	return &Dialer{ParentDialer: parent, address: header.ProxyAddress, cipher: cipher, key: commandKey(id), packetAddr: header.Flags&protocol.Flags_VMess_UsePacketAddr != 0}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp":
		conn, err := d.open(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return conn, nil
	case "udp":
		// Packet-address has an IP-only wire format. Resolve a bound domain
		// once during dialing, while its caller's context owns cancellation.
		if d.packetAddr {
			target, err := socks5.AddressFromString(address)
			if err != nil {
				return nil, err
			}
			if target.Type == socks5.AddressTypeDomain {
				ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", target.Hostname)
				if err != nil {
					return nil, err
				}
				if len(ips) == 0 {
					return nil, fmt.Errorf("VMess UDP destination has no IP addresses")
				}
				address = netip.AddrPortFrom(ips[0].Unmap(), target.Port).String()
			}
		}
		conn, err := d.openPacket(ctx, address)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{PacketConn: conn, Address: netproxy.NewAddr("udp", address)}, nil
	default:
		return nil, fmt.Errorf("%w: %s", netproxy.UnsupportedTunnelTypeError, network)
	}
}
func (d *Dialer) open(ctx context.Context, network, address string) (*Conn, error) {
	target, err := socks5.AddressFromString(address)
	if err != nil {
		return nil, err
	}
	if len(target.Hostname) > 255 {
		return nil, fmt.Errorf("VMess hostname exceeds 255 bytes")
	}
	if network == "udp" && d.packetAddr {
		target = &socks5.AddressInfo{Type: socks5.AddressTypeDomain, Hostname: SeqPacketMagicAddress, Port: target.Port}
	}
	parent, err := d.ParentDialer.DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, err
	}
	netproxy.CaptureDependency(ctx, parent)
	var conn *Conn
	err = protocol.Handshake(ctx, parent, func() error {
		var err error
		conn, err = newConn(parent, request{address: target, network: network, cipher: d.cipher}, d.key[:])
		return err
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// ListenPacket creates a packet association. In packet-address mode each
// WriteTo destination must be an IP; it never starts an implicit DNS lookup.
func (d *Dialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	if d.packetAddr {
		return d.openPacket(ctx, address)
	}
	return protocol.NewPacketAssociation(ctx, address, d.openPacket)
}

func (d *Dialer) openPacket(ctx context.Context, address string) (net.PacketConn, error) {
	conn, err := d.open(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	return &PacketConn{Conn: conn, target: netproxy.NewAddr("udp", address), packetAddr: d.packetAddr}, nil
}
