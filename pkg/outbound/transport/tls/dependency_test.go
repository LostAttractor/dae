package tls

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type dependencyDialer struct {
	lease *netproxy.Lease
	dial  func(context.Context, string, string) (net.Conn, error)
}

type dependencyConn struct {
	net.Conn
	lease *netproxy.Lease
}

func (c *dependencyConn) DependencyLease() *netproxy.Lease { return c.lease }
func (d *dependencyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := d.dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &dependencyConn{Conn: c, lease: d.lease}, nil
}
func (d *dependencyDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, netproxy.UnsupportedTunnelTypeError
}

func TestTLSRetainsTunnelDependencyAndALPN(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	for _, impl := range []string{"tls", "utls"} {
		t.Run(impl, func(t *testing.T) {
			lease := netproxy.NewLease(netproxy.NewResourceRef())
			parent := &dependencyDialer{lease: lease, dial: (&net.Dialer{}).DialContext}
			cfg := &TLSConfig{Host: server.Listener.Addr().String(), AllowInsecure: true, Alpn: "h2,http/1.1"}
			layer, err := cfg.Build(&dialer.ExtraOption{TlsImplementation: impl, UtlsImitate: "firefox", TlsFragment: true, TlsFragmentLength: "20-40", TlsFragmentInterval: "0-0"}, dialer.NewUpstream(parent))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := layer.Data.DialContext(ctx, "tcp", "unused:443")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if got := netproxy.DependencyOf(conn); got != lease {
				t.Fatalf("dependency = %p, want %p", got, lease)
			}
			if _, ok := conn.(netproxy.CloseWriter); !ok {
				t.Fatal("TLS wrapper lost CloseWrite")
			}
			if got := conn.(interface{ NegotiatedProtocol() string }).NegotiatedProtocol(); got != "h2" {
				t.Fatalf("ALPN = %q", got)
			}
			child := netproxy.NewLease(netproxy.NewResourceRef(), netproxy.DependencyOf(conn))
			lease.Invalidate(errors.New("parent stream reset"))
			if child.Valid() {
				t.Fatal("TLS wrapper hid invalidated parent")
			}
		})
	}
}

func TestTLSHandshakeCancellationClosesUnderlay(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	parent := &dependencyDialer{dial: func(context.Context, string, string) (net.Conn, error) { return local, nil }}
	layer, err := (&TLSConfig{Host: "test:443"}).Build(&dialer.ExtraOption{TlsImplementation: "tls"}, dialer.NewUpstream(parent))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = layer.Data.DialContext(ctx, "tcp", "unused:443")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("handshake error = %v", err)
	}
	if err := local.SetDeadline(time.Now()); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("failed handshake did not close underlay: %v", err)
	}
}
