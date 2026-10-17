package juicity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/quic-go"
)

type loopbackPacketParent struct{}

func (loopbackPacketParent) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}
func (loopbackPacketParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

func recoveryTLS(t *testing.T) *tls.Config {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}, NextProtos: []string{"juicity-test"}, MinVersion: tls.VersionTLS13}
}

func TestRecoveryStreamResetDoesNotKillSharedQUICConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	listener, err := quic.ListenAddr("127.0.0.1:0", recoveryTLS(t), &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *quic.Conn, 2)
	go func() {
		for {
			c, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			select {
			case accepted <- c:
			case <-ctx.Done():
				return
			}
		}
	}()
	d, err := NewDialer(loopbackPacketParent{}, protocol.Header{ProxyAddress: listener.Addr().String(), User: "00000000-0000-0000-0000-000000000000", Password: "test", Feature1: "bbr", TlsConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"juicity-test"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	var server *quic.Conn
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var old *clientImpl
	if err := d.clientRing.Allocate(ctx, false, func(_ context.Context, client *clientImpl) error {
		old = client
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	open := func() (net.Conn, *quic.Stream) {
		t.Helper()
		client, err := d.DialContext(ctx, "tcp", "example.test:443")
		if err != nil {
			t.Fatal(err)
		}
		remote, err := server.AcceptStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = remote.SetDeadline(time.Now().Add(5 * time.Second))
		header := make([]byte, 1)
		if _, err := io.ReadFull(remote, header); err != nil {
			t.Fatal(err)
		}
		if _, err := readMetadata(remote); err != nil {
			t.Fatal(err)
		}
		_ = client.SetDeadline(time.Now().Add(5 * time.Second))
		return client, remote
	}
	first, remoteFirst := open()
	defer first.Close()
	second, remoteSecond := open()
	defer second.Close()
	remoteFirst.CancelWrite(23)
	_, err = first.Read(make([]byte, 1))
	if failure := netproxy.ClassifyFailure(err); failure.Scope != netproxy.ScopeStream || failure.Resource != old.resource {
		t.Fatalf("stream error lost attribution: %+v", failure)
	}
	if d.Snapshot().State != netproxy.SessionConnected {
		t.Fatalf("stream reset disconnected pool: %+v", d.Snapshot())
	}
	if netproxy.DependencyOf(first).AbortCause() != nil || old.lease.AbortCause() != nil {
		t.Fatal("single stream reset issued resource abort")
	}
	if _, err := remoteSecond.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(second, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("sibling read=%q err=%v", buf, err)
	}
	graceful, remoteGraceful := open()
	defer graceful.Close()
	if _, err := graceful.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := graceful.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if request, err := io.ReadAll(remoteGraceful); err != nil || string(request) != "request" {
		t.Fatalf("FIN request=%q err=%v", request, err)
	}
	if _, err := remoteGraceful.Write([]byte("response after FIN")); err != nil {
		t.Fatal(err)
	}
	if err := remoteGraceful.Close(); err != nil {
		t.Fatal(err)
	}
	if response, err := io.ReadAll(graceful); err != nil || string(response) != "response after FIN" {
		t.Fatalf("response=%q err=%v", response, err)
	}
	if !old.lease.Valid() {
		t.Fatal("stream FIN invalidated shared connection")
	}
	underlay, err := d.ListenPacket(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer underlay.Close()
	if dependency := netproxy.DependencyOf(underlay); dependency == nil || !dependency.Valid() {
		t.Fatal("raw UDP hid its authenticated dependency")
	}
	underlayDone := make(chan error, 1)
	go func() { _, _, err := underlay.ReadFrom(make([]byte, 1)); underlayDone <- err }()
	_ = server.CloseWithError(0x321, "connection failed")
	_, err = second.Read(buf)
	var appErr *quic.ApplicationError
	if failure := netproxy.ClassifyFailure(err); failure.Scope != netproxy.ScopeSharedResource || !errors.As(err, &appErr) {
		t.Fatalf("connection error=%+v", failure)
	}
	for _, lease := range []*netproxy.Lease{old.lease, netproxy.DependencyOf(second)} {
		if !errors.As(lease.AbortCause(), &appErr) || appErr.ErrorCode != 0x321 {
			t.Fatalf("connection failure lost abort signal: %v", lease.AbortCause())
		}
	}
	select {
	case err := <-underlayDone:
		if f := netproxy.ClassifyFailure(err); f.Scope != netproxy.ScopeSharedResource || f.Resource != old.resource {
			t.Fatalf("underlay terminal=%+v", f)
		}
	case <-ctx.Done():
		t.Fatal("raw UDP read outlived its authenticated session")
	}
	if d.Snapshot().State != netproxy.SessionDisconnected {
		t.Fatalf("failed connection still usable: %+v", d.Snapshot())
	}
	if err := d.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	before := d.Snapshot()
	old.failConnection(errors.New("late error from previous resource"))
	if after := d.Snapshot(); after.State != netproxy.SessionConnected || after.Seq != before.Seq {
		t.Fatalf("old resource invalidated replacement: %+v", after)
	}
}
