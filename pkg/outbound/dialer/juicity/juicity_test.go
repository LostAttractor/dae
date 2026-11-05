package juicity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	_ "github.com/daeuniverse/dae/pkg/outbound/protocol/juicity"
	"github.com/daeuniverse/quic-go"
)

type loopback struct{}

func (loopback) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, net.ErrClosed
}
func (loopback) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

// Reconnects of one node resume its TLS session, and never with 0-RTT even
// though the server accepts it.
func TestReconnectResumesTLSSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}, NextProtos: []string{"h3"}}, &quic.Config{Allow0RTT: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	node := &Juicity{Server: "127.0.0.1", Port: listener.Addr().(*net.UDPAddr).Port, User: "00000000-0000-0000-0000-000000000000", Password: "test", Sni: "localhost", AllowInsecure: true, CongestionControl: "bbr"}
	layer, err := node.Build(&dialer.ExtraOption{}, dialer.NewUpstream(loopback{}))
	if err != nil {
		t.Fatal(err)
	}
	defer layer.Close()
	for i := range 2 {
		if err := layer.Sessions[0].Connect(ctx); err != nil {
			t.Fatal(err)
		}
		server, err := listener.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if state := server.ConnectionState(); state.TLS.DidResume != (i == 1) || state.Used0RTT {
			t.Fatalf("connection %d: resumed=%v 0-RTT=%v", i, state.TLS.DidResume, state.Used0RTT)
		}
		// The reply follows the session ticket, so the client holds it after the read.
		conn, err := layer.Data.DialContext(ctx, "tcp", "1.2.3.4:443")
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		remote, err := server.AcceptStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(remote, make([]byte, 12)); err != nil {
			t.Fatal(err)
		}
		if _, err := remote.Write([]byte("pong")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(conn, make([]byte, 4)); err != nil {
			t.Fatal(err)
		}
		_ = server.CloseWithError(0, "")
		// The failed read takes the pool offline, so the next Connect dials.
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatal("read survived the closed connection")
		}
		_ = conn.Close()
	}
}
