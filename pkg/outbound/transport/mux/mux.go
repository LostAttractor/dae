package mux

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

// Mux is a base Mux struct
type Mux struct {
	ParentDialer   netproxy.Dialer
	Addr           string
	PassthroughUdp bool
}

func (s *Mux) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp":
		c, err := s.ParentDialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("[Mux]: dial to %s: %w", s.Addr, err)
		}
		return NewConn(c, MuxOption{
			ID:   [2]byte{0, 0},
			Port: 0,
			Host: "127.0.0.1",
			Type: "",
		}), err
	case "udp":
		if s.PassthroughUdp {
			return s.ParentDialer.DialContext(ctx, network, addr)
		}
		// TODO: mux+udp
		return nil, fmt.Errorf("%w: mux+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (s *Mux) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	if s.PassthroughUdp {
		return s.ParentDialer.ListenPacket(ctx, addr)
	}
	return nil, fmt.Errorf("%w: mux+udp", netproxy.UnsupportedTunnelTypeError)
}
