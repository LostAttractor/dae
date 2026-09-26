// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
)

func http3TestAuthority(t *testing.T) (*mitmca.Authority, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	if err := mitmca.Generate(cert, key, "HTTP/3 MITM test", time.Hour); err != nil {
		t.Fatal(err)
	}
	authority, err := mitmca.Load(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := mitmca.ReadCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return authority, roots
}

func http3TestPacketConn(t *testing.T) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func http3TestUpstream(t *testing.T, cfg *tls.Config, handler http.Handler) net.Addr {
	t.Helper()
	conn := http3TestPacketConn(t)
	server := &http3.Server{TLSConfig: cfg, Handler: handler, QUICConfig: &quic.Config{Allow0RTT: false}}
	done := make(chan error, 1)
	go func() { done <- server.Serve(conn) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("upstream HTTP/3 server did not stop")
		}
	})
	return conn.LocalAddr()
}

func http3TestClient(t *testing.T, host *Host, roots *x509.CertPool, name string, upstream net.Addr) (*http.Client, <-chan error, *atomic.Int32) {
	t.Helper()
	intercepted, clientPackets := http3TestPacketConn(t), http3TestPacketConn(t)
	flow := plugin.Flow{Host: name, Port: 443}
	flow.Source = netip.MustParseAddrPort(clientPackets.LocalAddr().String())
	flow.Destination = netip.MustParseAddrPort(intercepted.LocalAddr().String())
	var tcpDials atomic.Int32
	served := make(chan error, 1)
	go func() {
		served <- host.ServePacketConn(intercepted, flow,
			testUpstream(func(context.Context, string, string) (net.Conn, error) {
				tcpDials.Add(1)
				return nil, errors.New("unexpected TCP dial")
			}),
			testPacketUpstream(func(_ context.Context, address string) (net.PacketConn, net.Addr, error) {
				if upstream == nil {
					return nil, nil, errors.New("no upstream in local-response fixture")
				}
				if address != net.JoinHostPort(name, "443") {
					return nil, nil, fmt.Errorf("unexpected upstream address: %s", address)
				}
				conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
				return conn, upstream, err
			}))
	}()
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots},
		Dial: func(ctx context.Context, _ string, cfg *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			return quic.Dial(ctx, clientPackets, intercepted.LocalAddr(), cfg, quicConfig)
		},
	}
	t.Cleanup(func() { _ = transport.Close() })
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}, served, &tcpDials
}

func TestHTTP3MITMPluginsAndTrailers(t *testing.T) {
	authority, roots := http3TestAuthority(t)
	var connections sync.Map
	var calls atomic.Int32
	upstream := http3TestUpstream(t, authority.TLSConfig("example.com"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 3 || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.TLS.NegotiatedProtocol != "h3" {
			t.Errorf("upstream was not HTTP/3 over verified TLS: %s %+v", r.Proto, r.TLS)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "modified request" || r.Header.Get("X-Plugin") != "request" {
			t.Errorf("upstream received unmodified request: %q, %v, %v", body, r.Header, err)
		}
		calls.Add(1)
		w.Header().Set("Trailer", "Grpc-Status")
		w.Header().Set("Alt-Svc", `h3=":8443"`)
		_, _ = w.Write([]byte("upstream"))
		w.Header().Set("Grpc-Status", "0")
	}))
	p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("example.com")}}}, wrap: func(flow plugin.Flow, next plugin.Handler) plugin.Handler {
		if !flow.Source.IsValid() || !flow.Destination.IsValid() {
			t.Errorf("missing original flow addresses: %+v", flow)
		}
		return func(e *plugin.Exchange) (*http.Response, error) {
			connection, request := plugin.IDs(e.Request.Context())
			if connection == "" || request == "" {
				t.Error("HTTP/3 plugin request has no IDs")
			}
			connections.Store(connection, true)
			if e.Request.URL.Path == "/local" {
				return response("local"), nil
			}
			if err := e.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Errorf("HTTP/3 body read deadline unsupported: %v", err)
			}
			view, err := membuffer.Copy([]byte("modified request"), bodyMemory)
			if err != nil {
				return nil, err
			}
			plugin.SetRequestBody(e.Request, view)
			view.Close()
			e.Request.Header.Set("X-Plugin", "request")
			r, err := next(e)
			if err != nil {
				return nil, err
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				_ = r.Body.Close()
				return nil, err
			}
			view, err = membuffer.Copy(append(body, []byte(" modified response")...), bodyMemory)
			if err != nil {
				_ = r.Body.Close()
				return nil, err
			}
			plugin.SetResponseBody(r, view)
			view.Close()
			return r, nil
		}
	}}
	host := testHost(t, Options{Authority: authority, UpstreamTLSConfig: &tls.Config{RootCAs: roots}}, Instance{Plugin: p})
	client, served, tcpDials := http3TestClient(t, host, roots, "example.com", upstream)
	var requests sync.WaitGroup
	for range 4 {
		requests.Go(func() {
			resp, err := client.Post("https://example.com/test", "application/grpc", strings.NewReader("original"))
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil || resp.ProtoMajor != 3 || resp.StatusCode != 200 || string(body) != "upstream modified response" || resp.Trailer.Get("Grpc-Status") != "0" || resp.Header.Get("Alt-Svc") != "" {
				t.Errorf("unexpected HTTP/3 response: %s %d %q trailer=%v headers=%v error=%v", resp.Proto, resp.StatusCode, body, resp.Trailer, resp.Header, err)
			}
		})
	}
	requests.Wait()
	for _, path := range []string{"/local", "/wrong-port"} {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com"+path, nil)
		if path == "/wrong-port" {
			req.Host = "other.example.com:8443"
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if path == "/local" && string(body) != "local" || path == "/wrong-port" && resp.StatusCode != 421 {
			t.Fatalf("%s: status=%d body=%q", path, resp.StatusCode, body)
		}
	}
	connectionCount := 0
	connections.Range(func(_, _ any) bool { connectionCount++; return true })
	if calls.Load() != 4 || tcpDials.Load() != 0 || connectionCount != 1 {
		t.Fatalf("upstream calls=%d TCP dials=%d downstream connections=%d", calls.Load(), tcpDials.Load(), connectionCount)
	}
	_ = client.Transport.(*http3.Transport).Close()
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP/3 association did not exit when host closed")
	}
}

func TestHTTP3MITMRejectsUntrustedUpstreamWithoutTCPFallback(t *testing.T) {
	authority, roots := http3TestAuthority(t)
	upstreamAuthority, _ := http3TestAuthority(t)
	upstream := http3TestUpstream(t, upstreamAuthority.TLSConfig("example.com"), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("request reached untrusted upstream")
	}))
	host := testHost(t, Options{Authority: authority, UpstreamTLSConfig: &tls.Config{RootCAs: roots}})
	client, _, tcpDials := http3TestClient(t, host, roots, "example.com", upstream)
	resp, err := client.Get("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || tcpDials.Load() != 0 {
		t.Fatalf("status=%d TCP dials=%d", resp.StatusCode, tcpDials.Load())
	}
}

func TestHTTP3MITMTLSIdentity(t *testing.T) {
	for _, name := range []string{"example.com", "127.0.0.1"} {
		t.Run(name, func(t *testing.T) {
			authority, roots := http3TestAuthority(t)
			p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope(name)}}}, wrap: func(plugin.Flow, plugin.Handler) plugin.Handler {
				return func(*plugin.Exchange) (*http.Response, error) { return response("local"), nil }
			}}
			host := testHost(t, Options{Authority: authority}, Instance{Plugin: p})
			client, _, _ := http3TestClient(t, host, roots, name, nil)
			if name == "example.com" {
				client.Transport.(*http3.Transport).TLSClientConfig.ServerName = "different.example.com"
			}
			resp, err := client.Get("https://" + name + "/")
			if name == "example.com" {
				if err == nil {
					_ = resp.Body.Close()
					t.Fatal("HTTP/3 accepted SNI different from intercepted destination")
				}
				return
			}
			if err != nil {
				t.Fatalf("IP target without SNI failed verified TLS: %v", err)
			}
			_ = resp.Body.Close()
			if resp.TLS == nil || resp.TLS.ServerName != "" || resp.StatusCode != 200 {
				t.Fatalf("IP response: status=%d TLS=%+v", resp.StatusCode, resp.TLS)
			}
		})
	}
}

func TestHTTP3UpstreamHeaderTimeout(t *testing.T) {
	for _, delayedHeaders := range []bool{true, false} {
		t.Run(fmt.Sprintf("delayed_headers=%t", delayedHeaders), func(t *testing.T) {
			authority, roots := http3TestAuthority(t)
			upstream := http3TestUpstream(t, authority.TLSConfig("example.com"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if delayedHeaders {
					select {
					case <-r.Context().Done():
					case <-time.After(300 * time.Millisecond):
					}
					return
				}
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				time.Sleep(150 * time.Millisecond)
				_, _ = w.Write([]byte("streamed body"))
			}))
			host := testHost(t, Options{UpstreamTLSConfig: &tls.Config{RootCAs: roots}})
			transport := host.http3Transport(func(context.Context, string) (net.PacketConn, net.Addr, error) {
				conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
				return conn, upstream, err
			})
			transport.headerTimeout = 75 * time.Millisecond
			defer transport.Close()
			req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
			resp, err := transport.RoundTrip(req)
			if delayedHeaders {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("missing header timeout: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil || string(body) != "streamed body" {
				t.Fatalf("header timeout leaked into body: %q, %v", body, err)
			}
		})
	}
}

func TestHTTP3HeaderTimeoutExcludesUpload(t *testing.T) {
	for _, earlyResponse := range []bool{false, true} {
		t.Run(fmt.Sprintf("early_response=%t", earlyResponse), func(t *testing.T) {
			authority, roots := http3TestAuthority(t)
			started, finished := make(chan struct{}), make(chan struct{})
			defer close(finished)
			upstream := http3TestUpstream(t, authority.TLSConfig("example.com"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if earlyResponse {
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
				}
				close(started)
				_, _ = io.Copy(w, r.Body)
			}))
			host := testHost(t, Options{UpstreamTLSConfig: &tls.Config{RootCAs: roots}})
			transport := host.http3Transport(func(context.Context, string) (net.PacketConn, net.Addr, error) {
				conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
				return conn, upstream, err
			})
			transport.headerTimeout = 50 * time.Millisecond
			defer transport.Close()
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			written := make(chan error, 1)
			go func() {
				select {
				case <-started:
				case <-finished:
					return
				}
				time.Sleep(3 * transport.headerTimeout)
				_, err := io.WriteString(writer, "slow upload")
				_ = writer.Close()
				written <- err
			}()
			request, _ := http.NewRequest(http.MethodPost, "https://example.com/", reader)
			response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != "slow upload" {
				t.Fatalf("upload consumed header budget: body=%q err=%v", body, err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Embedding UDPConn deliberately exposes OOB/syscall interfaces. Real outbound
// wrappers can do this while relying on WriteTo to resolve or frame addresses.
type http3DomainPacketConn struct {
	*net.UDPConn
	peer, destination net.Addr
	writes            atomic.Int32
}

func (c *http3DomainPacketConn) WriteTo(body []byte, address net.Addr) (int, error) {
	c.writes.Add(1)
	if address.String() == c.peer.String() {
		address = c.destination
	}
	return c.UDPConn.WriteTo(body, address)
}

func TestHTTP3UpstreamPreservesPacketDialerSemantics(t *testing.T) {
	authority, roots := http3TestAuthority(t)
	upstream := http3TestUpstream(t, authority.TLSConfig("example.com"), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("via selected packet dialer"))
	}))
	peer := netproxy.NewAddr("udp", "example.com:443")
	packets := &http3DomainPacketConn{UDPConn: http3TestPacketConn(t).(*net.UDPConn), peer: peer, destination: upstream}
	host := testHost(t, Options{UpstreamTLSConfig: &tls.Config{RootCAs: roots}})
	transport := host.http3Transport(func(context.Context, string) (net.PacketConn, net.Addr, error) {
		return packets, peer, nil
	})
	defer transport.Close()
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	resp, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "via selected packet dialer" || packets.writes.Load() == 0 {
		t.Fatalf("outbound WriteTo bypassed: body=%q writes=%d error=%v", body, packets.writes.Load(), err)
	}
}

func TestHTTP3MITMMultipleConnectionsOnOneAssociation(t *testing.T) {
	authority, roots := http3TestAuthority(t)
	var wraps atomic.Int32
	p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("example.com")}}}, wrap: func(plugin.Flow, plugin.Handler) plugin.Handler {
		local := wraps.Add(1)
		return func(e *plugin.Exchange) (*http.Response, error) {
			connection, _ := plugin.IDs(e.Request.Context())
			return response(fmt.Sprintf("%d/%s", local, connection)), nil
		}
	}}
	host := testHost(t, Options{Authority: authority}, Instance{Plugin: p})
	intercepted, clientPackets := http3TestPacketConn(t), http3TestPacketConn(t)
	flow := plugin.Flow{
		Host: "example.com", Port: 443,
		Source:      netip.MustParseAddrPort(clientPackets.LocalAddr().String()),
		Destination: netip.MustParseAddrPort(intercepted.LocalAddr().String()),
	}
	served := make(chan error, 1)
	go func() {
		served <- host.ServePacketConn(intercepted, flow, testUpstream(nil), testPacketUpstream(func(context.Context, string) (net.PacketConn, net.Addr, error) {
			return nil, nil, errors.New("unexpected upstream")
		}))
	}()
	// One UDP socket multiplexes distinct QUIC connections and their CIDs.
	wire := &quic.Transport{Conn: clientPackets}
	defer wire.Close()
	newClient := func() *http.Client {
		transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
			return wire.Dial(ctx, intercepted.LocalAddr(), tlsConfig, config)
		}}
		t.Cleanup(func() { _ = transport.Close() })
		return &http.Client{Transport: transport, Timeout: 3 * time.Second}
	}
	clients := []*http.Client{newClient(), newClient()}
	bodies := make([]string, 3)
	var requests sync.WaitGroup
	request := func(client *http.Client, index int) {
		defer requests.Done()
		resp, err := client.Get("https://example.com/")
		if err != nil {
			t.Error(err)
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Error(err)
		}
		bodies[index] = string(body)
	}
	for i, client := range clients {
		requests.Add(1)
		go request(client, i)
	}
	requests.Wait()
	_ = clients[0].Transport.(*http3.Transport).Close()
	// Reconnecting immediately on the same tuple must reach a fresh chain.
	clients = append(clients, newClient())
	requests.Add(1)
	request(clients[2], 2)
	if wraps.Load() != 3 || bodies[0] == "" || bodies[1] == "" || bodies[2] == "" || bodies[0] == bodies[1] || bodies[0] == bodies[2] || bodies[1] == bodies[2] {
		t.Fatalf("connections shared middleware or IDs: wraps=%d bodies=%v", wraps.Load(), bodies)
	}
	for _, client := range clients {
		_ = client.Transport.(*http3.Transport).Close()
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("association with multiple connections did not drain")
	}
}
