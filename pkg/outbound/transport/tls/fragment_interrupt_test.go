package tls_test

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	transporttls "github.com/daeuniverse/dae/pkg/outbound/transport/tls"
	"github.com/daeuniverse/dae/pkg/outbound/transport/ws"
)

func TestFragmentWaitInterrupted(t *testing.T) {
	for _, action := range []string{"close", "write deadline", "deadline"} {
		t.Run(action, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				config, err := transporttls.ParseFragmentConfig("1-1", "3600000-3600000")
				if err != nil {
					t.Fatal(err)
				}
				local, peer := net.Pipe()
				defer peer.Close()
				conn := config.Wrap(local)
				defer conn.Close()
				done := make(chan error, 1)
				go func() {
					_, err := conn.Write([]byte{22, 3, 3, 0, 3, 1, 2, 3})
					done <- err
				}()
				var first [6]byte
				if _, err := io.ReadFull(peer, first[:]); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				start := time.Now()
				switch action {
				case "close":
					err = conn.Close()
				case "write deadline":
					err = conn.SetWriteDeadline(start.Add(time.Millisecond))
				case "deadline":
					err = conn.SetDeadline(start.Add(time.Millisecond))
				}
				if err != nil {
					t.Fatal(err)
				}
				err = <-done
				if action == "close" {
					if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
						t.Fatalf("close did not interrupt write: %v", err)
					}
				} else if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("deadline did not interrupt write: %v", err)
				}
				if elapsed := time.Since(start); elapsed > time.Second {
					t.Fatalf("interruption waited for the fragment interval: %v", elapsed)
				}
			})
		})
	}
}

type fragmentDialer struct{ conn net.Conn }

func (d fragmentDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}
func (fragmentDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, netproxy.UnsupportedTunnelTypeError
}

func TestFragmentHandshakeCancellation(t *testing.T) {
	for _, implementation := range []string{"tls", "utls", "wss"} {
		t.Run(implementation, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				local, peer := net.Pipe()
				defer peer.Close()
				var builder dialer.Builder = &transporttls.TLSConfig{Host: "example.test:443"}
				if implementation == "wss" {
					builder = &ws.WsConfig{Scheme: "wss", Host: "example.test:443"}
				}
				layer, err := builder.Build(&dialer.ExtraOption{
					TlsImplementation: implementation, UtlsImitate: "firefox",
					TlsFragment: true, TlsFragmentLength: "1-1", TlsFragmentInterval: "3600000-3600000",
				}, dialer.NewUpstream(fragmentDialer{local}))
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				go func() {
					_, err := layer.Data.DialContext(ctx, "tcp", "unused:443")
					done <- err
				}()
				var first [6]byte
				if _, err := io.ReadFull(peer, first[:]); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				start := time.Now()
				cancel()
				if err := <-done; !errors.Is(err, context.Canceled) {
					t.Fatalf("handshake cancellation = %v", err)
				}
				if elapsed := time.Since(start); elapsed > time.Second {
					t.Fatalf("cancellation waited for the fragment interval: %v", elapsed)
				}
			})
		})
	}
}
