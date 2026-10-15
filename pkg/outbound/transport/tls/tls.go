package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	utls "github.com/refraction-networking/utls"
)

// Tls is a base Tls struct
type Tls struct {
	ParentDialer        netproxy.Dialer
	addr                string
	tlsImplentation     string
	utlsImitate         string
	passthroughUdp      bool
	fragmentation       bool
	fragmentMinLength   int64
	fragmentMaxLength   int64
	fragmentMinInterval int64
	fragmentMaxInterval int64

	tlsConfig *tls.Config
}

type TLSConfig struct {
	Host           string
	Sni            string
	Alpn           string
	PassthroughUdp bool

	AllowInsecure bool
}

// NewTls returns a Tls infra.
func (s *TLSConfig) Build(option *dialer.ExtraOption, upstream dialer.Upstream) (netproxy.Layer, error) {
	t := &Tls{
		ParentDialer:    upstream,
		addr:            s.Host,
		tlsImplentation: option.TlsImplementation,
		utlsImitate:     option.UtlsImitate,
		passthroughUdp:  s.PassthroughUdp,
	}
	if s.Sni == "" {
		host, _, err := net.SplitHostPort(s.Host)
		if err != nil {
			return netproxy.Layer{}, err
		}
		s.Sni = host
	}
	t.tlsConfig = &tls.Config{
		ServerName:         s.Sni,
		InsecureSkipVerify: s.AllowInsecure || option.AllowInsecure,
	}
	if len(s.Alpn) > 0 {
		t.tlsConfig.NextProtos = strings.Split(s.Alpn, ",")
	}

	if option.TlsFragment {
		t.fragmentation = true
		minLen, maxLen, err := parseRange(option.TlsFragmentLength)
		if err != nil {
			return netproxy.Layer{}, err
		}
		t.fragmentMinLength = minLen
		t.fragmentMaxLength = maxLen
		minInterval, maxInterval, err := parseRange(option.TlsFragmentInterval)
		if err != nil {
			return netproxy.Layer{}, err
		}
		t.fragmentMinInterval = minInterval
		t.fragmentMaxInterval = maxInterval
	}

	return netproxy.Layer{Data: t}, nil
}

func (s *Tls) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp":
		rc, err := s.ParentDialer.DialContext(ctx, network, s.addr)
		if err != nil {
			return nil, fmt.Errorf("[Tls]: dial to %s: %w", s.addr, err)
		}
		netproxy.CaptureDependency(ctx, rc)
		keep := false
		defer func() {
			if !keep {
				_ = rc.Close()
			}
		}()

		if s.fragmentation {
			rc = NewFragmentConn(rc, s.fragmentMinLength, s.fragmentMaxLength, s.fragmentMinInterval, s.fragmentMaxInterval)
		}

		var tlsConn interface {
			net.Conn
			HandshakeContext(context.Context) error
		}

		switch s.tlsImplentation {
		case "tls":
			tlsConn = &leasedTLSConn{Conn: tls.Client(rc, s.tlsConfig), lease: netproxy.DependencyOf(rc)}

		case "utls":
			clientHelloID, err := nameToUtlsClientHelloID(s.utlsImitate)
			if err != nil {
				return nil, err
			}

			tlsConn = &leasedUTLSConn{UConn: utls.UClient(rc, uTLSConfigFromTLSConfig(s.tlsConfig), *clientHelloID), lease: netproxy.DependencyOf(rc)}

		default:
			return nil, fmt.Errorf("unknown tls implementation: %v", s.tlsImplentation)
		}

		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, netproxy.WrapFailure(err, netproxy.Failure{Phase: netproxy.OpHandshake})
		}
		keep = true
		return tlsConn, err
	case "udp":
		if s.passthroughUdp {
			return s.ParentDialer.DialContext(ctx, network, addr)
		}
		return nil, fmt.Errorf("%w: tls+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (s *Tls) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	if s.passthroughUdp {
		return s.ParentDialer.ListenPacket(ctx, addr)
	}
	return nil, fmt.Errorf("%w: tls+udp", netproxy.UnsupportedTunnelTypeError)
}
