// SPDX-License-Identifier: AGPL-3.0-only

package testutil

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/daeuniverse/quic-go"
)

// QUICPair is a loopback connection whose client socket can stop sending after
// the handshake. No frames or acknowledgements are injected into the transport.
type QUICPair struct {
	Client, Server *quic.Conn
	socket         *heldPacketConn
}

func (p *QUICPair) HoldWrites()    { p.socket.hold.Store(true) }
func (p *QUICPair) ReleaseWrites() { p.socket.release() }

type heldPacketConn struct {
	net.PacketConn
	hold   atomic.Bool
	resume chan struct{}
	once   sync.Once
}

func (c *heldPacketConn) release() { c.once.Do(func() { close(c.resume) }) }
func (c *heldPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.hold.Load() {
		<-c.resume
	}
	return c.PacketConn.WriteTo(b, addr)
}
func (c *heldPacketConn) Close() error {
	c.release()
	return c.PacketConn.Close()
}

func NewQUICPair(t *testing.T) *QUICPair {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	const alpn = "dae-queue-test"
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}, NextProtos: []string{alpn}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	held := &heldPacketConn{PacketConn: socket, resume: make(chan struct{})}
	t.Cleanup(func() { _ = held.Close() })
	transport := &quic.Transport{Conn: held}
	t.Cleanup(func() { held.release(); _ = transport.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := transport.Dial(ctx, listener.Addr(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{alpn}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { held.release(); _ = client.CloseWithError(0, "") })
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { held.release(); _ = server.CloseWithError(0, "") })
	return &QUICPair{Client: client, Server: server, socket: held}
}

// WhileStalled bounds an admission check while the underlying socket cannot send.
func (p *QUICPair) WhileStalled(t *testing.T, check func() error) error {
	t.Helper()
	p.HoldWrites()
	done := make(chan error, 1)
	go func() { done <- check() }()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		p.ReleaseWrites()
		t.Fatal("QUIC datagram admission waited for carrier progress")
		return nil
	}
}
