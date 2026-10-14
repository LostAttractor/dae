package tuic

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
	"github.com/google/uuid"
)

func init() {
	protocol.RegisterLayer("tuic", func(parent netproxy.Dialer, header protocol.Header) (netproxy.Layer, error) {
		dialer, err := NewDialer(parent, header)
		if err != nil {
			return netproxy.Layer{}, err
		}
		return netproxy.Layer{Data: dialer, Sessions: []netproxy.Session{dialer}, Resources: []io.Closer{dialer}}, nil
	})
}

type Dialer struct {
	clientRing *clientRing

	proxyAddress string
	nextDialer   netproxy.Dialer
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (*Dialer, error) {
	id, err := uuid.Parse(header.User)
	if err != nil {
		return nil, fmt.Errorf("parse UUID: %w", err)
	}
	// ensure server's incoming stream can handle correctly, increase to 1.1x
	maxDatagramFrameSize := 1400
	udpRelayMode := common.NATIVE
	if header.Flags&protocol.Flags_Tuic_UdpRelayModeQuic > 0 {
		udpRelayMode = common.QUIC
	}
	return &Dialer{
		clientRing: newClientRing(func(capabilityCallback func(n int64)) *clientImpl {
			return &clientImpl{
				ClientOption: &ClientOption{
					TlsConfig: header.TlsConfig,
					QuicConfig: &quic.Config{
						InitialStreamReceiveWindow:     common.InitialStreamReceiveWindow,
						MaxStreamReceiveWindow:         common.MaxStreamReceiveWindow,
						InitialConnectionReceiveWindow: common.InitialConnectionReceiveWindow,
						MaxConnectionReceiveWindow:     common.MaxConnectionReceiveWindow,
						KeepAlivePeriod:                3 * time.Second,
						DisablePathMTUDiscovery:        false,
						EnableDatagrams:                true,
						HandshakeIdleTimeout:           8 * time.Second,
						CapabilityCallback:             capabilityCallback,
					},
					Uuid:                  id,
					Password:              header.Password,
					UdpRelayMode:          udpRelayMode,
					CongestionController:  header.Feature1.(string),
					ReduceRtt:             false,
					CWND:                  10,
					MaxUdpRelayPacketSize: maxDatagramFrameSize,
				},
				udp: true,
			}
		}, 10),
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
	}, nil
}

func (d *Dialer) Close() error { return d.clientRing.Close() }

func (d *Dialer) Snapshot() netproxy.StateEvent { return d.clientRing.Snapshot() }
func (d *Dialer) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return d.clientRing.WatchState(ctx)
}
func (d *Dialer) Connect(ctx context.Context) error {
	proxyAddr, err := netproxy.ResolveUDPAddr(ctx, d.nextDialer, d.proxyAddress)
	if err != nil {
		return err
	}
	return d.clientRing.Connect(ctx, d.nextDialer, d.dialFuncFactory("udp", proxyAddr))
}

func (d *Dialer) dialFuncFactory(_ string, rAddr net.Addr) common.DialFunc {
	return func(ctx context.Context, dialer netproxy.Dialer) (*quic.Transport, net.Addr, error) {
		conn, err := dialer.ListenPacket(ctx, d.proxyAddress)
		if err != nil {
			return nil, nil, err
		}
		netproxy.CaptureDependency(ctx, conn)
		return &quic.Transport{Conn: conn}, rAddr, nil
	}
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network == "udp" {
		packet, err := d.ListenPacket(ctx, address)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{PacketConn: packet, Address: netproxy.NewAddr("udp", address)}, nil
	}
	if network != "tcp" {
		return nil, fmt.Errorf("%w: %s", netproxy.UnsupportedTunnelTypeError, network)
	}
	if err := netproxy.RequireConnected(d); err != nil {
		return nil, err
	}
	metadata, err := protocol.ParseMetadata(address)
	if err != nil {
		return nil, err
	}
	return d.clientRing.DialContext(ctx, &metadata)
}

func (d *Dialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	if err := netproxy.RequireConnected(d); err != nil {
		return nil, err
	}
	metadata, err := protocol.ParseMetadata(address)
	if err != nil {
		return nil, err
	}
	return d.clientRing.ListenPacket(ctx, &metadata)
}
