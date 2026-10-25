package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/internal/protocol"
	"github.com/daeuniverse/quic-go"
)

type failingPacketDialer struct{ err error }

func (d failingPacketDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, d.err
}

func (d failingPacketDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, d.err
}

func TestEstablishFailureDoesNotPanic(t *testing.T) {
	wantErr := errors.New("packet setup failed")
	c := &Client{config: &Config{
		Addr:       &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443},
		NextDialer: failingPacketDialer{err: wantErr},
	}}
	if _, err := c.establish(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("establish error = %v, want %v", err, wantErr)
	}
}

func TestListenPacketClassifiesDisabledUDP(t *testing.T) {
	resource := new(clientResource)
	c := &Client{}
	c.lifecycle = netproxy.NewSingleSession(netproxy.SingleSessionConfig[*clientResource]{
		Establish: func(context.Context) (*clientResource, error) { return resource, nil },
	})
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err := c.ListenPacket(context.Background(), "")
	if !errors.Is(err, netproxy.UnsupportedTunnelTypeError) {
		t.Fatalf("ListenPacket error = %v, want UnsupportedTunnelTypeError", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

// Close waits until the peer has finished every bidirectional stream, which
// returns its credit.
func TestCloseWaitsForStreamCredit(t *testing.T) {
	addr := serveH3(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(protocol.StatusAuthOK) })
	client, err := NewClient(&Config{Addr: addr, NextDialer: authTestDialer{}, TLSConfig: tls.Config{InsecureSkipVerify: true}})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	resource, err := client.currentResource()
	if err != nil {
		t.Fatal(err)
	}
	if _, highest := resource.credit.Credit(quic.StreamTypeBidi); highest <= 0 {
		t.Fatalf("no bidirectional credit reported: %d", highest)
	}
	stream, err := resource.conn.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { defer close(closed); _ = client.Close() }()
	select {
	case <-closed:
		t.Fatal("Close returned while a stream was open")
	case <-time.After(200 * time.Millisecond):
	}
	_ = stream.Close()
	stream.CancelRead(0)
	select {
	case <-closed:
	case <-time.After(netproxy.CloseLinger / 2):
		t.Fatal("Close kept waiting after the stream was finished")
	}
}
