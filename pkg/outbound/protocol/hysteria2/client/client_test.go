package client

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
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
