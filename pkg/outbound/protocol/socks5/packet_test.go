package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type incomingDatagram struct {
	from net.Addr
	data []byte
}

type queuedPacketConn struct {
	net.PacketConn
	packets   []incomingDatagram
	writtenTo net.Addr
}

func (c *queuedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(c.packets) == 0 {
		return 0, nil, io.EOF
	}
	packet := c.packets[0]
	c.packets = c.packets[1:]
	return copy(p, packet.data), packet.from, nil
}

func (c *queuedPacketConn) Close() error { return nil }

func (c *queuedPacketConn) WriteTo(p []byte, to net.Addr) (int, error) {
	c.writtenTo = to
	return len(p), nil
}

func TestUDPRelayResolutionIsPinnedAndFailureClosesControl(t *testing.T) {
	resolveFailure := errors.New("relay resolution failed")
	for _, cause := range []error{nil, resolveFailure} {
		name := "success"
		if cause != nil {
			name = "resolution failure"
		}
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(3 * time.Second))
			bound := []byte{5, 0, 0, 3, 13}
			bound = append(bound, "relay.example"...)
			bound = append(bound, 0x12, 0x34)
			done := make(chan error, 1)
			go func() {
				done <- runPeer(server, []wireStep{
					{[]byte{5, 1, 0}, []byte{5, 0}},
					{[]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}, bound},
				})
			}()
			resolved := 0
			listened := false
			packet := new(queuedPacketConn)
			d, err := NewSocks5("socks5://proxy.example:1080", testParent{
				conn: client,
				resolve: func(_ context.Context, address string) (*net.UDPAddr, error) {
					resolved++
					if address != "relay.example:4660" {
						t.Errorf("resolve address = %s", address)
					}
					if cause != nil {
						return nil, cause
					}
					return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4660}, nil
				},
				listen: func(_ context.Context, address string) (net.PacketConn, error) {
					listened = true
					if address != "192.0.2.1:4660" {
						t.Errorf("listen address = %s", address)
					}
					return packet, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			conn, err := d.ListenPacket(t.Context(), "target.example:53")
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if cause != nil {
				if conn != nil || !errors.Is(err, cause) || listened {
					t.Fatalf("resolution failure: conn=%v err=%v listened=%v", conn, err, listened)
				}
				if _, err := server.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
					t.Fatalf("control connection leaked: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			for range 2 {
				if _, err := conn.WriteTo([]byte("query"), netproxy.NewAddr("udp", "target.example:53")); err != nil {
					t.Fatal(err)
				}
				if packet.writtenTo.String() != "192.0.2.1:4660" {
					t.Fatalf("write address = %s", packet.writtenTo)
				}
			}
			if resolved != 1 {
				t.Fatalf("resolved relay %d times", resolved)
			}
		})
	}
}

func TestUDPDiscardsForeignSendersBeforeDecoding(t *testing.T) {
	for _, relay := range []string{"192.0.2.1:1080", "[2001:db8::1]:1080"} {
		t.Run(relay, func(t *testing.T) {
			server := netproxy.NewAddr("udp", relay).(*net.UDPAddr)
			wire := append([]byte{0, 0, 0, 1, 8, 8, 8, 8, 0, 53}, []byte("reply")...)
			packet := &queuedPacketConn{packets: []incomingDatagram{
				{netproxy.NewAddr("udp", "192.0.2.2:1080"), wire},
				{&net.UDPAddr{IP: server.IP, Port: 1081}, wire},
				{netproxy.NewAddr("udp", "192.0.2.2:1080"), []byte{255}},
				{nil, wire},
				{netproxy.NewProxyAddr("udp", "untrusted.example:1080"), wire},
				{server, wire},
				{netproxy.NewProxyAddr("udp", relay), wire},
			}}
			control, peer := net.Pipe()
			defer peer.Close()
			conn := NewPktConn(packet, control, server)
			defer conn.Close()
			for range 2 {
				buf := make([]byte, 64)
				n, from, err := conn.ReadFrom(buf)
				if err != nil || string(buf[:n]) != "reply" || from.String() != "8.8.8.8:53" {
					t.Fatalf("ReadFrom = %d, %v, %v, payload=%q", n, from, err, buf[:n])
				}
			}
			if len(packet.packets) != 0 {
				t.Fatalf("accepted foreign packets: %d packets remain", len(packet.packets))
			}
		})
	}
}
