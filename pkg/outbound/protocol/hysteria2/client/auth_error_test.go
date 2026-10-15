package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/internal/protocol"
	"github.com/daeuniverse/quic-go/http3"
)

type authTestDialer struct{}

func (authTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected TCP dial")
}
func (authTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

func TestRecoveryAuthResponsePreservesStatusAndEvidence(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	type authCase struct {
		status           int
		rx               string
		invalidBandwidth bool
	}
	tests := []authCase{{status: 401}, {status: 403}, {status: 404}, {status: 500}, {status: protocol.StatusAuthOK}}
	for _, rx := range []string{"auto", "0", "125000000", "18446744073709551615"} {
		tests = append(tests, authCase{protocol.StatusAuthOK, rx, false})
	}
	for _, rx := range []string{"-1", "18446744073709551616", "invalid"} {
		tests = append(tests, authCase{protocol.StatusAuthOK, rx, true})
	}
	for _, tc := range tests {
		status := tc.status
		t.Run(strconv.Itoa(status)+"/"+tc.rx, func(t *testing.T) {
			packet, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}}, EnableDatagrams: true, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(protocol.CommonHeaderCCRX, tc.rx)
				w.WriteHeader(status)
			})}
			done := make(chan struct{})
			go func() { defer close(done); _ = server.Serve(packet) }()
			defer func() { _ = server.Close(); <-done }()
			client, err := NewClient(&Config{Addr: packet.LocalAddr(), NextDialer: authTestDialer{}, TLSConfig: tls.Config{InsecureSkipVerify: true}, BandwidthConfig: BandwidthConfig{MaxTx: 125_000_000, MaxRx: 250_000_000}})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			err = client.Connect(ctx)
			if status == protocol.StatusAuthOK && !tc.invalidBandwidth {
				if err != nil || !client.Snapshot().Accepting {
					t.Fatalf("successful auth not ready: %v", err)
				}
				return
			}
			f := netproxy.ClassifyFailure(err)
			reason := netproxy.ReasonRejected
			code := strconv.Itoa(status)
			if status == 401 || status == 403 {
				reason = netproxy.ReasonAuth
			}
			if tc.invalidBandwidth {
				reason, code = netproxy.ReasonProtocol, ""
			}
			if f.Layer != netproxy.LayerH3 || f.Phase != netproxy.OpHandshake || f.Scope != netproxy.ScopeOperation || f.Origin != netproxy.OriginPeer || f.Reason != reason || f.Code != code {
				t.Fatalf("wrong authentication evidence: %+v", f)
			}
			snapshot := client.Snapshot()
			if snapshot.Accepting || snapshot.State == netproxy.SessionConnected || !errors.Is(snapshot.Cause, err) {
				t.Fatalf("authentication failure published ready/lost cause: %+v", snapshot)
			}
		})
	}
}
