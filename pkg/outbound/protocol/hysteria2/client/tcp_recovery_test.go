package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/internal/utils"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/quicvarint"
)

func TestRecoveryFastOpenTargetFailurePreservesQUICSession(t *testing.T) {
	for _, reject := range []bool{true, false} {
		t.Run(map[bool]string{true: "target rejection", false: "truncated response"}[reject], func(t *testing.T) {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, priv)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}, NextProtos: []string{"hysteria-test"}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			serverErr := make(chan error, 1)
			go func() {
				conn, err := listener.Accept(ctx)
				if err != nil {
					serverErr <- err
					return
				}
				stream, err := conn.AcceptStream(ctx)
				if err != nil {
					serverErr <- err
					return
				}
				if _, err := io.ReadFull(stream, make([]byte, 1)); err != nil {
					serverErr <- err
					return
				}
				if reject {
					if err := writeTargetRejection(stream, "target connection refused"); err != nil {
						serverErr <- err
						return
					}
				}
				serverErr <- stream.Close()
			}()
			conn, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"hysteria-test"}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.CloseWithError(0, "")
			stream, err := conn.OpenStream()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stream.Write([]byte{0}); err != nil {
				t.Fatal(err)
			}
			parent := netproxy.NewLease(netproxy.NewResourceRef())
			sibling := parent.NewStream()
			fatal := false
			client := &tcpConn{Orig: &utils.QStream{Stream: stream, Lease: parent.NewStream(), Fail: func(error) { fatal = true }}}
			_, err = client.Read(make([]byte, 1))
			failure := netproxy.ClassifyFailure(err)
			if failure.Scope != netproxy.ScopeStream || fatal || !parent.Valid() || !sibling.Valid() || conn.Context().Err() != nil {
				t.Fatalf("request rejection killed shared session: failure=%+v fatal=%v", failure, fatal)
			}
			if reject {
				var target *TargetDialError
				if !errors.As(err, &target) || failure.Origin != netproxy.OriginTarget {
					t.Fatalf("lost target rejection: %v", err)
				}
			} else if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("truncated reply became normal EOF: %v", err)
			}
			if _, again := client.Read(make([]byte, 1)); again != err {
				t.Fatalf("terminal response error changed: %v => %v", err, again)
			}
			if client.DependencyLease().AbortCause() == nil {
				t.Fatal("failed response did not authorize resetting the TCP client")
			}
			if n, again := client.Write([]byte("must not be sent")); n != 0 || again != err {
				t.Fatalf("write after failed response = %d, %v; want original error %v", n, again, err)
			}
			cause := client.DependencyLease().AbortCause()
			_ = client.Close()
			if client.DependencyLease().AbortCause() != cause {
				t.Fatal("cleanup replaced the response failure")
			}
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRecoveryOpenStreamFatalInvalidatesAndCleansSession(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}, NextProtos: []string{"recovery-test"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan *quic.Conn, 1)
	go func() {
		server, err := listener.Accept(ctx)
		if err == nil {
			accepted <- server
		}
	}()
	conn, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"recovery-test"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	server := <-accepted
	defer server.CloseWithError(0, "")
	resource := &clientResource{conn: conn}
	closed := make(chan struct{})
	c := &Client{}
	c.lifecycle = netproxy.NewSingleSession(netproxy.SingleSessionConfig[*clientResource]{
		Layer:     netproxy.LayerQUIC,
		Establish: func(context.Context) (*clientResource, error) { return resource, nil },
		Close:     func(r *clientResource) error { defer close(closed); return r.close() },
	})
	defer c.Close()
	if err := c.lifecycle.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	handle, err := c.lifecycle.CurrentHandle()
	if err != nil {
		t.Fatal(err)
	}
	_ = server.CloseWithError(42, "remote connection failure")
	select {
	case <-conn.Context().Done():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	_, err = c.openStream(ctx, resource)
	if f := netproxy.ClassifyFailure(err); f.Scope != netproxy.ScopeSharedResource || f.Resource != handle.Ref() || f.Code != "42" {
		t.Fatalf("fatal open error=%+v", f)
	}
	if handle.Lease().Valid() || c.Snapshot().State == netproxy.SessionConnected {
		t.Fatal("failed stream admission did not synchronously gate session")
	}
	if !errors.Is(handle.Lease().AbortCause(), err) {
		t.Fatalf("fatal stream admission did not issue abort: %v", handle.Lease().AbortCause())
	}
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal("fatal open gated lease but did not clean resource")
	}
}

// The peer fixture deliberately lives in tests; the production codec is client-only.
func writeTargetRejection(w io.Writer, msg string) error {
	frame := quicvarint.Append([]byte{1}, uint64(len(msg)))
	frame = append(frame, msg...)
	frame = append(frame, 0) // no padding
	_, err := w.Write(frame)
	return err
}
