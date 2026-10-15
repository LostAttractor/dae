package simpleobfs

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type ObfsType int

const (
	HTTP ObfsType = iota
	TLS
)

func NewObfsType(obfsType string) (ObfsType, error) {
	switch obfsType {
	case "http":
		return HTTP, nil
	case "tls":
		return TLS, nil
	default:
		return 0, fmt.Errorf("unsupported obfs type %v", obfsType)
	}
}

// SimpleObfs is a base http-obfs struct
type SimpleObfs struct {
	ParentDialer netproxy.Dialer
	ObfsType     ObfsType
	Addr         string
	Path         string
	Host         string
}

func (s *SimpleObfs) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp":
		_, port, err := net.SplitHostPort(s.Addr)
		if err != nil {
			return nil, err
		}
		if s.ObfsType != HTTP && s.ObfsType != TLS {
			return nil, fmt.Errorf("unsupported obfs type: %v", s.ObfsType)
		}
		rc, err := s.ParentDialer.DialContext(ctx, network, s.Addr)
		if err != nil {
			return nil, fmt.Errorf("[simpleobfs]: dial to %s: %w", s.Addr, err)
		}

		switch s.ObfsType {
		case HTTP:
			c = NewHTTPObfs(rc, s.Host, port, s.Path)
		case TLS:
			c = NewTLSObfs(rc, s.Host)
		}
		return c, err
	case "udp":
		return s.ParentDialer.DialContext(ctx, network, s.Addr)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (s *SimpleObfs) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	return s.ParentDialer.ListenPacket(ctx, addr)
}
