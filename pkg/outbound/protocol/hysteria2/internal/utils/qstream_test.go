package utils

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/daeuniverse/quic-go"
)

// Close after CloseWrite keeps the upload: a peer that starts reading late
// still gets every byte and the FIN, not a reset.
func TestQStreamCloseAfterCloseWriteKeepsData(t *testing.T) {
	const size = 256 << 10
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}, NextProtos: []string{"qstream-test"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	received := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			received <- err
			return
		}
		defer conn.CloseWithError(0, "")
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			received <- err
			return
		}
		time.Sleep(300 * time.Millisecond)
		data, err := io.ReadAll(stream)
		if err == nil && len(data) != size {
			err = fmt.Errorf("peer read %d of %d bytes", len(data), size)
		}
		received <- err
	}()
	conn, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"qstream-test"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	s := &QStream{Stream: stream}
	if _, err := s.Write(make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	if err := s.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if err := <-received; err != nil {
		t.Fatal(err)
	}
}
