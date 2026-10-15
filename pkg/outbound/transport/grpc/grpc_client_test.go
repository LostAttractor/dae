package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	grpcapi "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"
)

type blockingDialer struct {
	once    sync.Once
	started chan struct{}
}

func (d *blockingDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	d.once.Do(func() { close(d.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}
func (d *blockingDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected ListenPacket")
}

func TestCloseCancelsConnect(t *testing.T) {
	parent := &blockingDialer{started: make(chan struct{})}
	dialer := &Dialer{
		ParentDialer: parent,
		Address:      "proxy.example:443",
	}
	result := make(chan error, 1)
	go func() { result <- dialer.Connect(context.Background()) }()
	select {
	case <-parent.started:
	case <-time.After(time.Second):
		t.Fatal("Connect did not reach the parent dialer")
	}
	if err := dialer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("Connect succeeded after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel Connect")
	}
	if state := dialer.Snapshot().State; state != netproxy.SessionClosed {
		t.Fatalf("state = %s, want closed", state)
	}
}

func TestShutdownChannelReturnsRecoveryToDaemon(t *testing.T) {
	listener, server := carrierPeer(t, "ready")
	defer server.Stop()
	d := &Dialer{ParentDialer: leasedCarrierParent{listener: listener}, Address: "passthrough:///peer"}
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := d.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	handle, err := d.session().CurrentHandle()
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Resource().Close(); err != nil {
		t.Fatal(err)
	}
	for ctx.Err() == nil {
		if state := d.Snapshot(); !state.Accepting && state.RecoveryExecutor == netproxy.RecoveryDaemon {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("terminal channel still claims library recovery: %+v", d.Snapshot())
}

func TestInitialTLSFailurePreservesCertificateError(t *testing.T) {
	certificate := httptest.NewTLSServer(nil)
	certificate.Close()
	listener := bufconn.Listen(1 << 20)
	defer listener.Close()
	server := grpcapi.NewServer(grpcapi.Creds(credentials.NewTLS(&tls.Config{Certificates: certificate.TLS.Certificates})))
	defer server.Stop()
	go server.Serve(listener)
	d := &Dialer{
		ParentDialer: peerDialer{listener}, Address: "passthrough:///peer",
		TLSConfig: &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "example.com"},
	}
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	err := d.Connect(ctx)
	for _, cause := range []error{err, d.Snapshot().Cause} {
		var certificateError x509.UnknownAuthorityError
		if !errors.As(cause, &certificateError) || !errors.Is(cause, context.DeadlineExceeded) {
			t.Fatalf("lost TLS diagnosis: %v", cause)
		}
	}
	// A later establishment must not carry the failed attempt's diagnosis.
	d.TLSConfig.RootCAs.AddCert(certificate.Certificate())
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := d.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if state := d.Snapshot(); !state.Accepting || state.Cause != nil {
		t.Fatalf("stale establishment error: %+v", state)
	}
}
