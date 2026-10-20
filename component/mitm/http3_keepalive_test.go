// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
)

func TestHTTP3ClientKeepAlive(t *testing.T) {
	t.Parallel()
	for _, route := range []string{"direct", "mitm"} {
		t.Run(route, func(t *testing.T) {
			t.Parallel()
			authority, roots := http3TestAuthority(t)
			packets := http3TestPacketConn(t)
			server := &http3.Server{TLSConfig: authority.TLSConfig("example.com"), QUICConfig: &quic.Config{MaxIdleTimeout: 5 * time.Second}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-time.After(6 * time.Second):
					io.WriteString(w, "delayed response")
				case <-r.Context().Done():
				}
			})}
			done := make(chan error, 1)
			go func() { done <- server.Serve(packets) }()
			t.Cleanup(func() { server.Close(); <-done })
			host := testHost(t, Options{Authority: authority, UpstreamTLSConfig: &tls.Config{RootCAs: roots}})
			var client *http.Client
			if route == "mitm" {
				client, _, _ = http3TestClient(t, host, roots, "example.com", packets.LocalAddr())
				client.Timeout = 12 * time.Second
				client.Transport.(*http3.Transport).QUICConfig = &quic.Config{MaxIdleTimeout: 10 * time.Second, KeepAlivePeriod: 250 * time.Millisecond}
			} else {
				transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, QUICConfig: &quic.Config{MaxIdleTimeout: 10 * time.Second, KeepAlivePeriod: 250 * time.Millisecond}, Dial: func(ctx context.Context, _ string, cfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
					return quic.Dial(ctx, http3TestPacketConn(t), packets.LocalAddr(), cfg, qcfg)
				}}
				t.Cleanup(func() { transport.Close() })
				client = &http.Client{Transport: transport, Timeout: 12 * time.Second}
			}
			started := time.Now()
			response, err := client.Get("https://example.com/wait")
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			t.Logf("status=%d body=%q elapsed=%v read=%v", response.StatusCode, body, time.Since(started), readErr)
			if response.StatusCode != http.StatusOK || readErr != nil || string(body) != "delayed response" {
				t.Fatalf("slow response failed: status=%d body=%q read=%v", response.StatusCode, body, readErr)
			}
		})
	}
}

func TestHTTP3IdleConnectionLifetime(t *testing.T) {
	authority, roots := http3TestAuthority(t)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	peer := http3TestUpstream(t, authority.TLSConfig("example.com"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			w.WriteHeader(200)
			_ = http.NewResponseController(w).Flush()
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		_, _ = io.WriteString(w, "tail")
	}))
	host := testHost(t, Options{Authority: authority, UpstreamTLSConfig: &tls.Config{RootCAs: roots}})
	transport := host.http3Transport(func(context.Context, string) (net.PacketConn, net.Addr, error) {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		return conn, peer, err
	})
	defer transport.Close()
	transport.IdleConnTimeout = 100 * time.Millisecond
	transport.QUICConfig.KeepAlivePeriod = 50 * time.Millisecond
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	slow, err := client.Get("https://example.com/slow")
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Body.Close()
	fast, err := client.Get("https://example.com/fast")
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, fast.Body)
	fast.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	transport.mu.Lock()
	if len(transport.connections) != 1 {
		t.Errorf("pooled connections=%d, want 1", len(transport.connections))
	}
	var connection *quic.Conn
	for conn := range transport.connections {
		connection = conn
	}
	transport.mu.Unlock()
	if connection == nil {
		t.Fatal("missing active connection")
	}
	select {
	case <-connection.Context().Done():
		t.Fatal("response headers were mistaken for end of request")
	case <-time.After(250 * time.Millisecond):
	}
	unblock()
	body, err := io.ReadAll(slow.Body)
	slow.Body.Close()
	if err != nil || string(body) != "tail" {
		t.Fatalf("slow response=%q err=%v", body, err)
	}
	select {
	case <-connection.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("keepalive retained unused connection")
	}
	// A transport cache entry can outlive QUIC idle closure. Its next request
	// must reconnect without turning that stale entry into an HTTP failure.
	next, err := client.Get("https://example.com/fast")
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(next.Body)
	next.Body.Close()
	if err != nil || string(body) != "tail" {
		t.Fatalf("next response=%q err=%v", body, err)
	}
}

func TestHTTP3RejectedConnectionsBecomeIdle(t *testing.T) {
	authority, roots := http3TestAuthority(t)
	peer, attempts := retryTestHTTP3Peer(t, authority.TLSConfig("example.com"), http3.ErrCodeRequestRejected, "payload")
	host := testHost(t, Options{Authority: authority, UpstreamTLSConfig: &tls.Config{RootCAs: roots}})
	transport := host.http3Transport(func(context.Context, string) (net.PacketConn, net.Addr, error) {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		return conn, peer, err
	})
	defer transport.Close()
	transport.IdleConnTimeout = 100 * time.Millisecond
	transport.QUICConfig.KeepAlivePeriod = 50 * time.Millisecond
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Post("https://example.com/rpc", "application/grpc", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 204 || attempts.Load() != 2 {
		t.Fatalf("status=%d attempts=%d read=%v", response.StatusCode, attempts.Load(), err)
	}
	// Rejection evicts the first connection from the HTTP/3 transport cache.
	// Both that connection and the cached retry must release their UDP sockets.
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		transport.mu.Lock()
		remaining := len(transport.connections)
		transport.mu.Unlock()
		if remaining == 0 {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("idle UDP connections retained: %d", remaining)
		case <-time.After(10 * time.Millisecond):
		}
	}
}
