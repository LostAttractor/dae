package http

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"strings"

	"fmt"
	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	tls2 "github.com/daeuniverse/dae/pkg/outbound/transport/tls"
)

// HttpProxy is an HTTP/HTTPS proxy.
type HttpProxy struct {
	ParentDialer netproxy.Dialer
	https        bool
	transport    bool
	Addr         string
	Host         string
	Path         string
	HaveAuth     bool
	Username     string
	Password     string
	pool         *h2ConnsPool
}

func BuildHTTPProxy(u *url.URL, option *dialer.ExtraOption, parentDialer netproxy.Dialer) (netproxy.Layer, error) {
	query := u.Query()
	layer := netproxy.Layer{Data: parentDialer}
	https := u.Scheme == "https"
	if https {
		alpn := query.Get("alpn")
		if alpn == "" {
			alpn = "h2,http/1.1"
		}
		allowInsecure, _ := strconv.ParseBool(query.Get("allowInsecure"))
		if !allowInsecure {
			allowInsecure, _ = strconv.ParseBool(query.Get("allow_insecure"))
		}
		if !allowInsecure {
			allowInsecure, _ = strconv.ParseBool(query.Get("allowinsecure"))
		}
		if !allowInsecure {
			allowInsecure, _ = strconv.ParseBool(query.Get("skipVerify"))
		}
		tlsConfig := tls2.TLSConfig{
			Host:          u.Host,
			Alpn:          alpn,
			Sni:           query.Get("sni"),
			AllowInsecure: allowInsecure,
		}
		if err := layer.AppendResult(tlsConfig.Build(option, dialer.NewUpstream(layer.Data))); err != nil {
			return netproxy.Layer{}, err
		}
	}
	path := u.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	transport, _ := strconv.ParseBool(query.Get("transport"))
	s := &HttpProxy{
		ParentDialer: layer.Data,
		https:        https,
		transport:    transport,
		Addr:         u.Host,
		Path:         path,
		Host:         query.Get("host"),
	}
	if u.User != nil {
		s.HaveAuth = true
		s.Username = u.User.Username()
		s.Password, _ = u.User.Password()
	}
	s.pool = newH2ConnsPool(s.ParentDialer, s.Addr)
	layer.Data = s
	layer.Resources = append(layer.Resources, s)
	if https {
		layer.Sessions = append(layer.Sessions, s.pool)
	}
	return layer, nil
}

func (s *HttpProxy) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.pool.mu.Lock()
	if s.pool.ctx.Err() != nil {
		s.pool.mu.Unlock()
		return nil, net.ErrClosed
	}
	s.pool.operations.Add(1)
	s.pool.mu.Unlock()
	defer s.pool.operations.Done()
	operation, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.pool.ctx, cancel)
	defer func() { stop(); cancel() }()
	ctx = operation

	if network != "tcp" {
		return nil, fmt.Errorf("%w: HTTP %s", netproxy.UnsupportedTunnelTypeError, network)
	}
	if s.https {
		if err := netproxy.RequireConnected(s.pool); err != nil {
			return nil, err
		}
		raw, h2, err := s.pool.getConn(ctx, true)
		if err != nil {
			return nil, err
		}
		if h2 != nil {
			return s.connectHTTP2(ctx, raw, h2, addr)
		}
		return s.connectHTTP1(ctx, raw, addr)
	}
	raw, err := s.ParentDialer.DialContext(ctx, network, s.Addr)
	if err != nil {
		return nil, err
	}
	netproxy.CaptureDependency(ctx, raw)
	return s.connectHTTP1(ctx, raw, addr)
}

func (s *HttpProxy) ListenPacket(ctx context.Context, network string) (net.PacketConn, error) {
	return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
}

func (s *HttpProxy) Close() error {
	return s.pool.Close()
}
