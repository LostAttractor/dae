package http

import (
	"bufio"
	"context"
	"errors"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"io"
	"net"
	stdhttp "net/http"
	"sync"
	"testing"
	"time"
)

type blockingWriteConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

type blockingDialer struct {
	started chan struct{}
	release chan struct{}
	peer    net.Conn
}

func (d *blockingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	close(d.started)
	<-d.release
	conn, peer := net.Pipe()
	d.peer = peer
	return conn, nil
}

func (d *blockingDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected listen")
}

func (c *blockingWriteConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

func TestH2PoolCloseClosesCachedConnections(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	pool := newH2ConnsPool(nil, "")
	pool.conns = append(pool.conns, &h2Conn{raw: client})
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pool.getConn(context.Background(), false); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("GetConn after Close error = %v, want net.ErrClosed", err)
	}
	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Fatal("cached connection remained open")
	}
}

func TestH2PoolCloseWaitsForAdmittedDial(t *testing.T) {
	dialer := &blockingDialer{started: make(chan struct{}), release: make(chan struct{})}
	pool := newH2ConnsPool(dialer, "proxy.example:443")
	result := make(chan error, 1)
	go func() {
		_, _, err := pool.getConn(context.Background(), false)
		result <- err
	}()
	<-dialer.started
	closed := make(chan error, 1)
	go func() { closed <- pool.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned before admitted dial: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(dialer.release)
	defer func() {
		if dialer.peer != nil {
			_ = dialer.peer.Close()
		}
	}()
	if err := <-result; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("GetConn error = %v, want net.ErrClosed", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

type http1Parent struct{ conn net.Conn }

func (p http1Parent) DialContext(context.Context, string, string) (net.Conn, error) {
	return p.conn, nil
}
func (p http1Parent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected packet")
}
func http1Proxy(parent netproxy.Dialer) *HttpProxy {
	return &HttpProxy{ParentDialer: parent, Addr: "proxy.test:80", pool: newH2ConnsPool(parent, "proxy.test:80")}
}

func TestHTTP1EagerConnectBuffersTunnelAndKeepsPayload(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "http", true: "https"}[secure], func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			lease := netproxy.NewLease(netproxy.NewResourceRef())
			parent := http1Parent{&negotiatedTestConn{Conn: client, lease: lease, proto: "http/1.1"}}
			proxy := http1Proxy(parent)
			if secure {
				proxy.https = true
				// The TLS preflight selected HTTP/1, which uses a fresh carrier per dial.
				proxy.pool.http1 = true
				proxy.pool.publishLocked(nil, "")
			}
			defer proxy.Close()
			payload := "GET /application HTTP/1.1\r\nHost: target.test\r\n\r\n"
			result := make(chan error, 1)
			go func() {
				request, err := stdhttp.ReadRequest(bufio.NewReader(server))
				if err != nil {
					result <- err
					return
				}
				if request.Method != "CONNECT" || request.Host != "target.test:80" {
					result <- errors.New("not an eager CONNECT")
					return
				}
				if _, err := io.WriteString(server, "HTTP/1.1 200 OK\r\n\r\nserver-first"); err != nil {
					result <- err
					return
				}
				got := make([]byte, len(payload))
				_, err = io.ReadFull(server, got)
				if err == nil && string(got) != payload {
					err = errors.New("application request rewritten")
				}
				result <- err
			}()
			conn, err := proxy.DialContext(context.Background(), "tcp", "target.test:80")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, ok := conn.(netproxy.CloseWriter); ok {
				t.Fatal("HTTP/1 advertised unsupported half-close")
			}
			if netproxy.DependencyOf(conn) != lease {
				t.Fatal("missing eager lease")
			}
			got := make([]byte, len("server-first"))
			if _, err := io.ReadFull(conn, got); err != nil || string(got) != "server-first" {
				t.Fatalf("buffered data %q %v", got, err)
			}
			if _, err := io.WriteString(conn, payload); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}

		})
	}
}

func TestHTTP1CancelClosesHandshake(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	carrier := &blockingWriteConn{Conn: client, started: make(chan struct{})}
	proxy := http1Proxy(http1Parent{carrier})
	defer proxy.Close()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := proxy.DialContext(ctx, "tcp", "target.test:443"); result <- err }()
	<-carrier.started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled handshake blocked")
	}
	if _, err := server.Write([]byte("late")); err == nil {
		t.Fatal("canceled handshake retained carrier")
	}
}
func TestHTTP1CancellationCleansLateDial(t *testing.T) {
	parent := &blockingDialer{started: make(chan struct{}), release: make(chan struct{})}
	proxy := http1Proxy(parent)
	defer proxy.Close()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := proxy.DialContext(ctx, "tcp", "target.test:443"); result <- err }()
	<-parent.started
	cancel()
	close(parent.release)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	defer parent.peer.Close()
	if _, err := parent.peer.Write([]byte("late")); err == nil {
		t.Fatal("late carrier retained")
	}
}

func TestHTTP1ProxyCloseWaitsForLateHandshakeCleanup(t *testing.T) {
	parent := &blockingDialer{started: make(chan struct{}), release: make(chan struct{})}
	proxy := http1Proxy(parent)
	result := make(chan error, 1)
	go func() { _, err := proxy.DialContext(context.Background(), "tcp", "target.test:443"); result <- err }()
	<-parent.started
	closed := make(chan error, 1)
	go func() { closed <- proxy.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("owner Close skipped pending handshake: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	close(parent.release)
	if err := <-result; err == nil {
		t.Fatal("closed owner published late connection")
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	defer parent.peer.Close()
	if _, err := parent.peer.Write([]byte("late")); err == nil {
		t.Fatal("late connection was not cleaned up")
	}
}
func TestHTTP1RejectedConnectClosesCarrier(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	proxy := http1Proxy(http1Parent{client})
	defer proxy.Close()
	done := make(chan error, 1)
	go func() {
		_, err := stdhttp.ReadRequest(bufio.NewReader(server))
		if err == nil {
			_, err = io.WriteString(server, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
		}
		done <- err
	}()
	_, err := proxy.DialContext(context.Background(), "tcp", "target.test:443")
	fact := netproxy.ClassifyFailure(err)
	if fact.Reason != netproxy.ReasonAuth || fact.Code != "407" || fact.Phase != netproxy.OpHandshake {
		t.Fatalf("rejection: %+v", fact)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Fatal("rejected connection remained open")
	}
}
