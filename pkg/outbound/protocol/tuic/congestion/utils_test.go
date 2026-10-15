package congestion

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/quic-go"
)

// Dropping complete UDP datagrams tests QUIC's actual ACK/loss callbacks and
// retransmissions; it doesn't rely on root privileges or host qdisc changes.
type droppingPacketConn struct {
	net.PacketConn
	every uint64
	sent  atomic.Uint64
}

func (c *droppingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.every != 0 && c.sent.Add(1)%c.every == 0 {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

func TestBBRv3QUICTransfer(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}},
		NextProtos:   []string{"bbr3-test"},
	}
	for _, dropEvery := range []uint64{0, 17} {
		t.Run(fmt.Sprintf("drop_every_%d", dropEvery), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			serverUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer serverUDP.Close()
			listener, err := quic.Listen(&droppingPacketConn{PacketConn: serverUDP, every: dropEvery}, tlsConfig, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			serverDone := make(chan error, 1)
			go func() {
				server, err := listener.Accept(ctx)
				if err != nil {
					serverDone <- err
					return
				}
				defer server.CloseWithError(0, "")
				UseBBR(server)
				stream, err := server.AcceptStream(ctx)
				if err != nil {
					serverDone <- err
					return
				}
				deadline, _ := ctx.Deadline()
				stream.SetDeadline(deadline)
				_, err = io.Copy(stream, stream)
				if err == nil {
					err = stream.Close()
				}
				serverDone <- err
				// Let the echo and FIN be acknowledged before closing the connection.
				<-ctx.Done()
			}()
			clientUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer clientUDP.Close()
			client, err := quic.Dial(ctx, &droppingPacketConn{PacketConn: clientUDP, every: dropEvery}, serverUDP.LocalAddr(),
				&tls.Config{InsecureSkipVerify: true, NextProtos: tlsConfig.NextProtos}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseWithError(0, "")
			UseBBR(client)
			stream, err := client.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			deadline, _ := ctx.Deadline()
			stream.SetDeadline(deadline)
			payload := bytes.Repeat([]byte("BBRv3 QUIC delivery\n"), 100_000)
			writeDone := make(chan error, 1)
			go func() {
				_, err := stream.Write(payload)
				if err == nil {
					err = stream.Close()
				}
				writeDone <- err
			}()
			response, err := io.ReadAll(stream)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(response, payload) {
				t.Fatalf("echo mismatch: received %d / %d bytes", len(response), len(payload))
			}
			if err := <-writeDone; err != nil {
				t.Fatal(err)
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}
