package juicity

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
	"github.com/google/uuid"
)

func init() {
	protocol.RegisterLayer("juicity", func(parent netproxy.Dialer, header protocol.Header) (netproxy.Layer, error) {
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
	maxOpenIncomingStreams := int64(100)
	quicMaxOpenIncomingStreams := int64(maxOpenIncomingStreams)
	quicMaxOpenIncomingStreams = quicMaxOpenIncomingStreams + int64(math.Ceil(float64(quicMaxOpenIncomingStreams)/10.0))
	reservedStreamsCapability := maxOpenIncomingStreams / 5
	if reservedStreamsCapability < 1 {
		reservedStreamsCapability = 1
	}
	if reservedStreamsCapability > 5 {
		reservedStreamsCapability = 5
	}
	return &Dialer{
		clientRing: newClientRing(func(capabilityCallback func(streamType quic.StreamType, n int64)) *clientImpl {
			ctx, cancel := context.WithCancel(context.Background())
			return &clientImpl{
				ClientOption: &ClientOption{
					TlsConfig: header.TlsConfig,
					QuicConfig: &quic.Config{
						InitialStreamReceiveWindow:     common.InitialStreamReceiveWindow,
						MaxStreamReceiveWindow:         common.MaxStreamReceiveWindow,
						InitialConnectionReceiveWindow: common.InitialConnectionReceiveWindow,
						MaxConnectionReceiveWindow:     common.MaxConnectionReceiveWindow,
						KeepAlivePeriod:                5 * time.Second,
						DisablePathMTUDiscovery:        false,
						EnableDatagrams:                false,
						HandshakeIdleTimeout:           8 * time.Second,
						CapabilityCallback:             capabilityCallback,
					},
					Uuid:                 id,
					Password:             header.Password,
					CongestionController: header.Feature1.(string),
					CWND:                 10,
					Ctx:                  ctx,
					Cancel:               cancel,
					UnderlayAuth:         make(chan *UnderlayAuth, 64),
				},
			}
		}, reservedStreamsCapability),
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
	conn, err := d.clientRing.DialContext(ctx, &Metadata{Metadata: metadata, Network: "tcp"})
	if err != nil {
		return nil, err
	}
	if err = protocol.Handshake(ctx, conn, func() error { _, err := conn.Write(nil); return err }); err != nil {
		return nil, err
	}
	return conn, nil
}

func (d *Dialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	if err := netproxy.RequireConnected(d); err != nil {
		return nil, err
	}
	metadata, err := protocol.ParseMetadata(address)
	if err != nil {
		return nil, err
	}
	m := &Metadata{Metadata: metadata, Network: "udp"}
	if metadata.Port != 0 {
		conn, err := d.clientRing.DialContext(ctx, m)
		if err != nil {
			return nil, err
		}
		if err = protocol.Handshake(ctx, conn, func() error { _, err := conn.Write(nil); return err }); err != nil {
			return nil, err
		}
		return &PacketConn{Conn: conn}, nil
	}
	auth, err := d.clientRing.DialAuth(ctx, m)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			auth.lease.Invalidate(net.ErrClosed)
		}
	}()
	proxyAddr, err := netproxy.ResolveUDPAddr(ctx, d.nextDialer, d.proxyAddress)
	if err != nil {
		return nil, err
	}
	conn, err := d.nextDialer.ListenPacket(ctx, d.proxyAddress)
	if err != nil {
		return nil, err
	}
	packet := &TransportPacketConn{PacketConn: conn, proxyAddr: proxyAddr, target: netproxy.NewAddr("udp", address), key: &shadowsocks.Key{CipherConf: CipherConf, MasterKey: auth.Psk}, firstIv: auth.IV, authLease: auth.lease, lease: netproxy.NewLease(auth.lease.Resource(), auth.lease, netproxy.DependencyOf(conn)), done: make(chan struct{})}
	if !packet.lease.Valid() {
		_ = packet.Close()
		return nil, packet.lease.Cause()
	}
	go func() {
		select {
		case <-packet.lease.Done():
			_ = packet.Close()
		case <-packet.done:
		}
	}()
	transferred = true
	return packet, nil
}
