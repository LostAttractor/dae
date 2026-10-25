package protocol_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks_2022"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks_stream"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
	"github.com/daeuniverse/dae/pkg/outbound/transport/shadowsocksr/proto"
)

// waitingSocket stands for a socket beneath a UDP layer that can only wait.
type waitingSocket struct {
	net.PacketConn
	sent [][]byte
}

func (s *waitingSocket) WriteTo(b []byte, _ net.Addr) (int, error) {
	s.sent = append(s.sent, bytes.Clone(b))
	return len(b), nil
}
func (*waitingSocket) Close() error { return nil }

// droppingSocket never waits: it drops while drop is set, as a socket with a
// full send buffer does.
type droppingSocket struct {
	waitingSocket
	drop bool
}

func (s *droppingSocket) TryWriteTo(b []byte, addr net.Addr) (int, error) {
	if s.drop {
		return 0, netproxy.ErrPacketDropped
	}
	return s.waitingSocket.WriteTo(b, addr)
}

func (s *droppingSocket) WriteTo(b []byte, addr net.Addr) (int, error) {
	if _, err := s.TryWriteTo(b, addr); err != nil {
		return len(b), nil
	}
	return len(b), nil
}

// socketDialer hands every layer the same socket, connected to a proxy or not.
type socketDialer struct{ socket net.PacketConn }

func (d socketDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	return &netproxy.BindPacketConn{PacketConn: d.socket, Address: netproxy.NewAddr("udp", address)}, nil
}

func (d socketDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return d.socket, nil
}

// Every layer that sends datagrams on a UDP socket of its own writes without
// waiting: it frames or encrypts the datagram itself, never handing a lookup
// the socket beneath, and a datagram the socket drops is lost, not an error,
// to WriteTo. Over a socket that can only wait, TryWriteTo sends nothing.
func TestUDPLayersWriteWithoutWaiting(t *testing.T) {
	const proxy = "192.0.2.1:8388"
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))
	header := func(cipher, password string) protocol.Header {
		return protocol.Header{ProxyAddress: proxy, Cipher: cipher, Password: password}
	}
	listen := func(newDialer func(netproxy.Dialer, protocol.Header) (netproxy.Dialer, error), h protocol.Header) func(*testing.T, net.PacketConn) net.PacketConn {
		return func(t *testing.T, socket net.PacketConn) net.PacketConn {
			d, err := newDialer(socketDialer{socket}, h)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := d.ListenPacket(t.Context(), "")
			if err != nil {
				t.Fatal(err)
			}
			return conn
		}
	}
	layers := map[string]func(*testing.T, net.PacketConn) net.PacketConn{
		"shadowsocks":        listen(shadowsocks.NewDialer, header("aes-128-gcm", "secret")),
		"shadowsocks_2022":   listen(shadowsocks_2022.NewDialer, header("2022-blake3-aes-128-gcm", key)),
		"shadowsocks_stream": listen(shadowsocks_stream.NewDialer, header("aes-128-cfb", "secret")),
		"ssr": listen(func(parent netproxy.Dialer, h protocol.Header) (netproxy.Dialer, error) {
			stream, err := shadowsocks_stream.NewDialer(parent, h)
			if err != nil {
				return nil, err
			}
			return proto.NewDialer(stream, "origin", "", 0)
		}, header("aes-128-cfb", "secret")),
		"socks5": func(t *testing.T, socket net.PacketConn) net.PacketConn {
			control, peer := net.Pipe()
			t.Cleanup(func() { _ = peer.Close() })
			conn := socks5.NewPktConn(socket, control, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(proxy)))
			t.Cleanup(func() { _ = conn.Close() })
			return conn
		},
	}
	payload := []byte("a datagram that must not appear in clear")
	to := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443}
	for name, layer := range layers {
		t.Run(name, func(t *testing.T) {
			socket := new(droppingSocket)
			conn := layer(t, socket)
			writer, ok := netproxy.PacketConnAs[netproxy.NonBlockingWriter](conn)
			if !ok || writer != conn.(netproxy.NonBlockingWriter) {
				t.Fatalf("lookup found %T, want the layer itself", writer)
			}
			if n, err := writer.TryWriteTo(payload, to); n != len(payload) || err != nil || len(socket.sent) != 1 {
				t.Fatalf("TryWriteTo = %d, %v with %d datagrams sent", n, err, len(socket.sent))
			}
			if name != "socks5" && bytes.Contains(socket.sent[0], payload) || bytes.Equal(socket.sent[0], payload) {
				t.Fatalf("the socket was given %q", socket.sent[0])
			}
			socket.drop = true
			if _, err := writer.TryWriteTo(payload, to); err != netproxy.ErrPacketDropped {
				t.Fatalf("TryWriteTo over a full socket = %v", err)
			}
			if n, err := conn.WriteTo(payload, to); n != len(payload) || err != nil {
				t.Fatalf("WriteTo over a full socket = %d, %v", n, err)
			}

			waiting := new(waitingSocket)
			conn = layer(t, waiting)
			if netproxy.CanTryWriteTo(conn) {
				t.Fatal("waiting carrier reported nonblocking capability")
			}
			// Even address framing must not run before the capability check.
			if _, err := conn.(netproxy.NonBlockingWriter).TryWriteTo(payload, nil); err != errors.ErrUnsupported {
				t.Fatalf("framed before checking the carrier: %v", err)
			}
			if _, err := conn.(netproxy.NonBlockingWriter).TryWriteTo(payload, to); err != errors.ErrUnsupported || len(waiting.sent) != 0 {
				t.Fatalf("TryWriteTo over a waiting socket = %v with %d datagrams sent", err, len(waiting.sent))
			}
			if n, err := conn.WriteTo(payload, to); n != len(payload) || err != nil || len(waiting.sent) != 1 {
				t.Fatalf("WriteTo over a waiting socket = %d, %v with %d datagrams sent", n, err, len(waiting.sent))
			}
		})
	}
}
