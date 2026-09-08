// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
)

func TestHTTP3UpstreamCloseAfterStreamReset(t *testing.T) {
	authority, roots := http3TestAuthority(t)
	peer := http3TestUpstream(t, authority.TLSConfig("example.com"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/reset" {
			panic(http.ErrAbortHandler) // Reset this stream with H3_INTERNAL_ERROR, keeping QUIC alive.
		}
		_, _ = io.WriteString(w, "ok")
	}))
	host := testHost(t, Options{UpstreamTLSConfig: &tls.Config{RootCAs: roots}})
	transport := host.http3Transport(func(ctx context.Context, _ string) (net.PacketConn, net.Addr, error) {
		conn, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
		return conn, peer, err
	})
	connections := make(chan *quic.Conn, 2)
	dial := transport.Dial
	transport.Dial = func(ctx context.Context, address string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
		conn, err := dial(ctx, address, tlsConfig, config)
		if err == nil {
			connections <- conn
		}
		return conn, err
	}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	_, err := client.Get("https://example.com/reset")
	var h3err *http3.Error
	if !errors.As(err, &h3err) || h3err.ErrorCode != http3.ErrCodeInternalError {
		t.Fatalf("expected a stream reset, got %v", err)
	}
	evicted := <-connections
	t.Cleanup(func() { _ = evicted.CloseWithError(0, "test cleanup"); _ = transport.Close() })
	resp, err := client.Get("https://example.com/ok")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	var pooled *quic.Conn
	select {
	case pooled = <-connections:
	case <-time.After(time.Second):
		t.Fatal("the stream reset did not evict the first connection")
	}
	if evicted.Context().Err() != nil {
		t.Fatal("stream reset unexpectedly closed the QUIC connection")
	}
	closed := make(chan error, 1)
	go func() { closed <- transport.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		_ = evicted.CloseWithError(0, "test cleanup")
		<-closed
		t.Fatal("transport cleanup waited for the evicted connection's idle timeout")
	}
	for _, conn := range []*quic.Conn{evicted, pooled} {
		if conn.Context().Err() == nil {
			t.Error("transport cleanup left an owned QUIC connection open")
		}
	}
}

func TestHTTP3UpstreamCloseDuringDial(t *testing.T) {
	packets := http3TestPacketConn(t)
	started := make(chan struct{})
	host := testHost(t, Options{})
	transport := host.http3Transport(func(ctx context.Context, _ string) (net.PacketConn, net.Addr, error) {
		close(started)
		<-ctx.Done()
		// Model an outbound that has just opened its socket as Close cancels
		// the dial. The late resource must still be released before Close returns.
		return packets, packets.LocalAddr(), nil
	})
	t.Cleanup(func() { _ = transport.Close() })
	requestDone := make(chan error, 1)
	go func() {
		_, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get("https://example.com/")
		requestDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("upstream dial did not start")
	}
	closed := make(chan error, 2)
	for range 2 {
		go func() { closed <- transport.Close() }()
	}
	for range 2 {
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("Close did not cancel the pending dial")
		}
	}
	if _, err := packets.WriteTo([]byte("closed"), packets.LocalAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Close returned before releasing the pending dial's socket: %v", err)
	}
	if err := <-requestDone; err == nil {
		t.Fatal("request succeeded after transport closed during dial")
	}
}
