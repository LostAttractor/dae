package httpupgrade

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type parentDialer struct {
	lease   *netproxy.Lease
	address string
}
type leasedTCP struct {
	*net.TCPConn
	lease *netproxy.Lease
}

func (c *leasedTCP) DependencyLease() *netproxy.Lease { return c.lease }
func (d *parentDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.address = address
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &leasedTCP{TCPConn: conn.(*net.TCPConn), lease: d.lease}, nil
}
func (*parentDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, netproxy.UnsupportedTunnelTypeError
}

func TestUpgradeRetainsBufferedPayloadDependencyAndHalfClose(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var tlsConfig *tls.Config
			if scheme == "https" {
				certServer := httptest.NewTLSServer(nil)
				certServer.Close()
				listener = tls.NewListener(listener, certServer.TLS)
				tlsConfig = &tls.Config{ServerName: "tls.example", InsecureSkipVerify: true}
			}
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				reader := bufio.NewReader(conn)
				req, err := http.ReadRequest(reader)
				if err != nil {
					done <- err
					return
				}
				if req.URL.RequestURI() != "/tunnel?x=1" || req.Host != "edge.example" {
					done <- errors.New("invalid upgrade request")
					return
				}
				if secure, ok := conn.(*tls.Conn); ok {
					state := secure.ConnectionState()
					if state.ServerName != "tls.example" || state.NegotiatedProtocol != "http/1.1" {
						done <- errors.New("invalid upgrade TLS configuration")
						return
					}
				}
				if _, err = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\nwelcome"); err != nil {
					done <- err
					return
				}
				body, err := io.ReadAll(reader)
				if err != nil {
					done <- err
					return
				}
				if string(body) != "request" {
					done <- errors.New("payload changed")
					return
				}
				_, err = io.WriteString(conn, "reply")
				done <- err
			}()
			parent := &parentDialer{lease: netproxy.NewLease(netproxy.NewResourceRef())}
			d, err := NewDialer(parent, Config{Address: listener.Addr().String(), Path: "/tunnel?x=1", Host: "edge.example", TLSConfig: tlsConfig})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := d.DialContext(ctx, "tcp", "business.example:443")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if parent.address != listener.Addr().String() || netproxy.DependencyOf(conn) != parent.lease {
				t.Fatal("lost proxy address or lease")
			}
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			var welcome [7]byte
			if _, err = io.ReadFull(conn, welcome[:]); err != nil || string(welcome[:]) != "welcome" {
				t.Fatalf("buffered upgrade payload lost: %q %v", welcome, err)
			}
			_, _ = conn.Write([]byte("request"))
			if err = conn.(netproxy.CloseWriter).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			response, err := io.ReadAll(conn)
			if err != nil || string(response) != "reply" {
				t.Fatalf("reverse half-close: %q %v", response, err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUpgradeCanceledHandshakeClosesConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, err = io.Copy(io.Discard, conn)
		done <- err
	}()
	d, err := NewDialer(&parentDialer{}, Config{Address: listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err = d.DialContext(ctx, "tcp", "unused"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled upgrade: %v", err)
	}
	if err = <-done; err != nil {
		t.Fatalf("underlay not closed: %v", err)
	}
}
