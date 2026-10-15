package meek

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type Dialer struct {
	url       string
	transport *http.Transport
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	workers   sync.WaitGroup
	closeOnce sync.Once
}

type Config struct {
	URL string
	// Nil uses the HTTPS endpoint's hostname and the default HTTP/2 ALPN.
	TLSConfig *tls.Config
}

func NewDialer(parent netproxy.Dialer, config Config) (*Dialer, error) {
	if config.URL == "" {
		return nil, fmt.Errorf("NewMeek: url is empty")
	}
	u, err := url.Parse(config.URL)
	if err != nil {
		return nil, fmt.Errorf("NewMeek: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("NewMeek: unimplemented backdrop")
	}

	tlsConfig := new(tls.Config)
	if config.TLSConfig != nil {
		tlsConfig = config.TLSConfig.Clone()
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = u.Hostname()
	}
	if len(tlsConfig.NextProtos) == 0 {
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	}
	m := &Dialer{url: config.URL}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.transport = &http.Transport{
		ForceAttemptHTTP2: true,
		DialContext:       parent.DialContext,
		TLSClientConfig:   tlsConfig,
	}

	return m, nil
}

func (m *Dialer) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch network {
	case "tcp":
		session := newClientSession(m.ctx, m.transport, m.url, &m.workers)
		if err := ctx.Err(); err != nil {
			_ = session.Close()
			return nil, err
		}
		return session, nil
	case "udp":
		return nil, fmt.Errorf("%w: meek+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (m *Dialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, fmt.Errorf("%w: meek+udp", netproxy.UnsupportedTunnelTypeError)
}

func (m *Dialer) Close() error {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.cancel()
		m.mu.Unlock()
		m.workers.Wait()
		m.transport.CloseIdleConnections()
	})
	return nil
}
