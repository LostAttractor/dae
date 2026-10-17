// SPDX-License-Identifier: AGPL-3.0-only

package dnsrouter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/plugin"
	policy "github.com/daeuniverse/dae/plugins/dns-router/policy"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	dns "github.com/miekg/dns"
)

var exchangeTLS *tls.Config

func TestMain(m *testing.M) {
	server := httptest.NewTLSServer(nil)
	exchangeTLS = server.TLS.Clone()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	_ = os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",x509usefallbackroots=1")
	x509.SetFallbackRoots(roots)
	server.Close()
	os.Exit(m.Run())
}

// Exercise the public router entry, not the old forwarder's private reuse state.
// All encrypted transports authenticate the fixture certificate normally.
func TestExchangeWireTransports(t *testing.T) {
	for _, scheme := range []policy.UpstreamScheme{"udp", "tcp", "tls", "https", "quic", "h3"} {
		t.Run(string(scheme), func(t *testing.T) {
			requests := make(chan *dns.Msg, 4)
			answer := func(query *dns.Msg) *dns.Msg {
				requests <- query.Copy()
				response := new(dns.Msg).SetReply(query)
				rr, _ := dns.NewRR(query.Question[0].Name + " 60 IN A 192.0.2.17")
				response.Answer = []dns.RR{rr}
				return response
			}
			address := exchangeServer(t, scheme, answer)
			upstream := &policy.Upstream{Scheme: scheme, Hostname: "example.com", Port: address.Port(), Path: "/dns-query",
				Ip46: &netutils.Ip46{Ip4: address.Addr()}}
			var closes atomic.Int32
			for i := range 2 {
				request := safetyRequest(dns.TypeA)
				message := request.MessageCopy()
				message.Id = uint16(400 + i)
				request.DNSPacket = plugin.DNSMessage(message)
				request.DialContext = func(ctx context.Context, network, target, hostname string) (net.Conn, error) {
					if target != address.String() || hostname != "example.com" {
						t.Errorf("lost routed target/hostname: %s %s", target, hostname)
					}
					conn, err := (&net.Dialer{}).DialContext(ctx, network, target)
					if err != nil {
						return nil, err
					}
					return &exchangeCountConn{Conn: conn, closed: &closes}, nil
				}
				request.ListenPacket = func(ctx context.Context, target, hostname string) (net.PacketConn, error) {
					if target != address.String() || hostname != "example.com" {
						t.Errorf("lost packet target/hostname")
					}
					conn, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", "127.0.0.1:0")
					if err != nil {
						return nil, err
					}
					return &exchangeCountPacket{PacketConn: conn, closed: &closes}, nil
				}
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				response, err := exchangeForTest(ctx, request, upstream)
				cancel()
				if err != nil {
					t.Fatal(err)
				}
				if response.MessageCopy().Id != request.MessageCopy().Id || len(response.MessageCopy().Answer) != 1 || request.MessageCopy().Response {
					t.Fatalf("response identity/ownership changed: %+v", response)
				}
				query := <-requests
				if (scheme == "quic" || scheme == "https" || scheme == "h3") && query.Id != 0 {
					t.Fatal("encrypted multiplexed DNS ID must be zero")
				}
			}
			deadline := time.After(time.Second)
			for closes.Load() != 2 {
				select {
				case <-deadline:
					t.Fatalf("exchange sockets not released: %d", closes.Load())
				case <-time.After(time.Millisecond):
				}
			}
		})
	}
}

func TestExchangeHTTPConfiguredEndpoint(t *testing.T) {
	for _, scheme := range []policy.UpstreamScheme{"https", "h3"} {
		for _, path := range []string{"", "/tenant%2Fhome/dns-query"} {
			t.Run(string(scheme)+path, func(t *testing.T) {
				wantPath := path
				if wantPath == "" {
					wantPath = "/dns-query"
				}
				address := exchangeHTTPServer(t, scheme, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					values := r.URL.Query()
					if r.URL.EscapedPath() != wantPath || values.Get("profile") != "home+mobile" || !slices.Equal(values["tag"], []string{"one", "two"}) {
						t.Errorf("configured endpoint changed: %s", r.URL)
					}
					wire, err := base64.RawURLEncoding.DecodeString(values.Get("dns"))
					query := new(dns.Msg)
					if err != nil || query.Unpack(wire) != nil || query.Id != 0 || len(values["dns"]) != 1 {
						t.Error("invalid DoH query")
						http.Error(w, "invalid query", http.StatusBadRequest)
						return
					}
					wire, _ = new(dns.Msg).SetReply(query).Pack()
					w.Header().Set("Content-Type", "application/dns-message")
					_, _ = w.Write(wire)
				}))
				raw, err := url.Parse(string(scheme) + "://" + address.String() + path + "?profile=home%2Bmobile&tag=one&tag=two&dns=stale")
				if err != nil {
					t.Fatal(err)
				}
				original := raw.String()
				upstream, err := policy.NewUpstream(t.Context(), raw)
				if err != nil {
					t.Fatal(err)
				}
				request := safetyRequest(dns.TypeA)
				request.DialContext = func(ctx context.Context, network, target, hostname string) (net.Conn, error) {
					if target != address.String() || hostname != address.Addr().String() {
						t.Errorf("routed endpoint changed: %s %s", target, hostname)
					}
					return (&net.Dialer{}).DialContext(ctx, network, target)
				}
				request.ListenPacket = func(ctx context.Context, target, hostname string) (net.PacketConn, error) {
					if target != address.String() || hostname != address.Addr().String() {
						t.Errorf("routed packet endpoint changed: %s %s", target, hostname)
					}
					return (&net.ListenConfig{}).ListenPacket(ctx, "udp", "127.0.0.1:0")
				}
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				defer cancel()
				response, err := exchangeForTest(ctx, request, upstream)
				if err != nil {
					t.Fatal(err)
				}
				if response.MessageCopy().Id != request.MessageCopy().Id || !response.MessageCopy().Response || raw.String() != original {
					t.Fatal("exchange changed query identity or configured URL")
				}
			})
		}
	}
}

type exchangeCountConn struct {
	net.Conn
	once   sync.Once
	closed *atomic.Int32
}

func (c *exchangeCountConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.closed.Add(1) })
	return err
}

type exchangeCountPacket struct {
	net.PacketConn
	once   sync.Once
	closed *atomic.Int32
}

func (c *exchangeCountPacket) Close() error {
	err := c.PacketConn.Close()
	c.once.Do(func() { c.closed.Add(1) })
	return err
}

func exchangeServer(t *testing.T, scheme policy.UpstreamScheme, answer func(*dns.Msg) *dns.Msg) netip.AddrPort {
	t.Helper()
	stream := func(conn net.Conn) {
		defer conn.Close()
		dc := &dns.Conn{Conn: conn}
		q, err := dc.ReadMsg()
		if err == nil {
			_ = dc.WriteMsg(answer(q))
		}
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Host, "example.com:") {
			t.Error("unexpected HTTP authority")
		}
		if r.URL.Path != "/dns-query" {
			t.Error("lost endpoint path")
		}
		wire, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		q := new(dns.Msg)
		if err != nil || q.Unpack(wire) != nil {
			t.Error("invalid DoH query")
			return
		}
		wire, _ = answer(q).Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	})
	switch scheme {
	case "udp":
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) { _ = w.WriteMsg(answer(q)) })}
		go server.ActivateAndServe()
		t.Cleanup(func() { _ = server.Shutdown(); _ = conn.Close() })
		return conn.LocalAddr().(*net.UDPAddr).AddrPort()
	case "tcp", "tls":
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			for {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				if scheme == "tls" {
					c = tls.Server(c, exchangeTLS)
				}
				go stream(c)
			}
		}()
		return listener.Addr().(*net.TCPAddr).AddrPort()
	case "https", "h3":
		return exchangeHTTPServer(t, scheme, handler)
	default:
		config := exchangeTLS.Clone()
		config.NextProtos = []string{"doq"}
		listener, err := quic.ListenAddr("127.0.0.1:0", config, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			for {
				conn, err := listener.Accept(t.Context())
				if err != nil {
					return
				}
				go func() {
					stream, err := conn.AcceptStream(t.Context())
					if err != nil {
						return
					}
					var prefix [2]byte
					if _, err := io.ReadFull(stream, prefix[:]); err != nil {
						return
					}
					wire := make([]byte, binary.BigEndian.Uint16(prefix[:]))
					if _, err := io.ReadFull(stream, wire); err != nil {
						return
					}
					q := new(dns.Msg)
					if q.Unpack(wire) != nil {
						return
					}
					wire, _ = answer(q).Pack()
					binary.BigEndian.PutUint16(prefix[:], uint16(len(wire)))
					_, _ = stream.Write(append(prefix[:], wire...))
					_ = stream.Close()
					<-conn.Context().Done()
				}()
			}
		}()
		return listener.Addr().(*net.UDPAddr).AddrPort()
	}
}

func exchangeHTTPServer(t *testing.T, scheme policy.UpstreamScheme, handler http.Handler) netip.AddrPort {
	t.Helper()
	if scheme == "https" {
		server := httptest.NewUnstartedServer(handler)
		server.TLS, server.EnableHTTP2 = exchangeTLS.Clone(), true
		server.StartTLS()
		t.Cleanup(server.Close)
		return server.Listener.Addr().(*net.TCPAddr).AddrPort()
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{Handler: handler, TLSConfig: exchangeTLS.Clone()}
	go server.Serve(conn)
	t.Cleanup(func() { _ = server.Close(); _ = conn.Close() })
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestExchangeTCPCorrelationRetryAndEOF(t *testing.T) {
	for _, retry := range []bool{false, true} {
		request := safetyRequest(dns.TypeA)
		calls := 0
		request.DialContext = func(context.Context, string, string, string) (net.Conn, error) {
			calls++
			c, p := net.Pipe()
			go func(first bool) {
				defer p.Close()
				dc := &dns.Conn{Conn: p}
				q, err := dc.ReadMsg()
				if err != nil || first {
					return
				}
				wrong := new(dns.Msg).SetReply(q)
				wrong.Question[0].Name = "wrong.example."
				_ = dc.WriteMsg(wrong)
				response := new(dns.Msg).SetReply(q)
				response.Rcode = dns.RcodeRefused
				response.Question = nil
				_ = dc.WriteMsg(response)
			}(retry && calls == 1)
			return c, nil
		}
		upstream := &policy.Upstream{Scheme: "tcp", Hostname: "192.0.2.53", Port: 53, Ip46: &netutils.Ip46{Ip4: netip.MustParseAddr("192.0.2.53")}}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		response, err := exchangeForTest(ctx, request, upstream)
		cancel()
		if err != nil || response.MessageCopy().Rcode != dns.RcodeRefused || response.MessageCopy().Id != request.MessageCopy().Id {
			t.Fatalf("response lost: %+v %v", response, err)
		}
		want := 1
		if retry {
			want = 2
		}
		if calls != want {
			t.Fatalf("dial count %d, want %d", calls, want)
		}
	}
}

func TestExchangeCancellationDoesNotWaitForClose(t *testing.T) {
	for _, scheme := range []policy.UpstreamScheme{"udp", "tcp", "tls", "https", "quic", "h3"} {
		t.Run(string(scheme), func(t *testing.T) {
			request := safetyRequest(dns.TypeA)
			c, p := net.Pipe()
			defer p.Close()
			release := make(chan struct{})
			defer close(release)
			request.DialContext = func(context.Context, string, string, string) (net.Conn, error) {
				return &exchangeBlockingClose{Conn: c, release: release}, nil
			}
			upstream := &policy.Upstream{Scheme: scheme, Hostname: "example.com", Port: 53, Ip46: &netutils.Ip46{Ip4: netip.MustParseAddr("192.0.2.53")}}
			if scheme == "quic" || scheme == "h3" {
				blackhole, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer blackhole.Close()
				address := blackhole.LocalAddr().(*net.UDPAddr).AddrPort()
				upstream.Port, upstream.Ip4 = address.Port(), address.Addr()
				request.ListenPacket = func(ctx context.Context, _, _ string) (net.PacketConn, error) {
					packet, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", "127.0.0.1:0")
					if err != nil {
						return nil, err
					}
					return &exchangeBlockingPacketClose{PacketConn: packet, release: release}, nil
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := exchangeForTest(ctx, request, upstream); done <- err }()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation waited for transport Close")
			}
			if request.MessageCopy().Response {
				t.Fatal("canceled exchange mutated query")
			}
		})
	}
}

type exchangeBlockingClose struct {
	net.Conn
	release <-chan struct{}
}

func (c *exchangeBlockingClose) Close() error { <-c.release; return c.Conn.Close() }

type exchangeBlockingPacketClose struct {
	net.PacketConn
	release <-chan struct{}
}

func (c *exchangeBlockingPacketClose) Close() error { <-c.release; return c.PacketConn.Close() }

func exchangeForTest(ctx context.Context, request *plugin.DNSExchange, upstream *policy.Upstream) (*plugin.DNSResponse, error) {
	return exchange(ctx, request, upstream, nil, "", "")
}
