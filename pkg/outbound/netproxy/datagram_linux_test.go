package netproxy

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TryWrite sends on a connected kernel socket, also through ownership
// tracking, and on the packet connection a BindPacketConn writes to; a
// connection it cannot send on without waiting is left to Write.
func TestTryWriteConnectedUDPSocket(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if n, err := TryWrite(TrackConn(client, func() {}), []byte("datagram")); n != 8 || err != nil {
		t.Fatalf("TryWrite = %d, %v", n, err)
	}
	buf := make([]byte, 16)
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	if n, _, err := server.ReadFrom(buf); err != nil || string(buf[:n]) != "datagram" {
		t.Fatalf("received %q, %v", buf[:n], err)
	}

}

// An unconnected socket sends to addresses of its family, IPv4 also on a
// dual-stack socket; it leaves zoned and foreign ones to WriteTo.
func TestUDPSocketSendsToItsFamily(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	to := server.LocalAddr().(*net.UDPAddr)
	for _, network := range []string{"udp", "udp4"} {
		conn, err := net.ListenUDP(network, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		socket := NewUDPSocket(conn)
		if n, err := socket.TryWriteTo([]byte(network), to); n != len(network) || err != nil {
			t.Fatalf("%s: TryWriteTo = %d, %v", network, n, err)
		}
		buf := make([]byte, 16)
		_ = server.SetReadDeadline(time.Now().Add(time.Second))
		if n, _, err := server.ReadFrom(buf); err != nil || string(buf[:n]) != network {
			t.Fatalf("%s: received %q, %v", network, buf[:n], err)
		}
		zoned := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[fe80::1%lo]:9"))
		if _, err := socket.TryWriteTo(nil, zoned); err != errors.ErrUnsupported {
			t.Fatalf("%s: TryWriteTo a zoned address = %v", network, err)
		}
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := NewUDPSocket(conn).TryWriteTo(nil, &net.UDPAddr{IP: net.IPv6loopback, Port: 9}); err != errors.ErrUnsupported {
		t.Fatalf("IPv4 socket: TryWriteTo an IPv6 address = %v", err)
	}
}

func TestUDPSocketEmptyIPMatchesNativeUDP(t *testing.T) {
	for _, network := range []string{"udp", "udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			receiver, err := net.ListenUDP(network, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			conn, err := net.ListenUDP(network, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			to := &net.UDPAddr{Port: receiver.LocalAddr().(*net.UDPAddr).Port}
			for _, ip := range []net.IP{nil, {}} {
				to.IP = ip
				for _, write := range []func([]byte, net.Addr) (int, error){conn.WriteTo, NewUDPSocket(conn).TryWriteTo} {
					if n, err := write([]byte("probe"), to); n != 5 || err != nil {
						t.Fatalf("write to empty IP = %d, %v", n, err)
					}
					_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
					var b [16]byte
					if n, _, err := receiver.ReadFrom(b[:]); err != nil || string(b[:n]) != "probe" {
						t.Fatalf("empty IP delivery = %q, %v", b[:n], err)
					}
				}
			}
		})
	}
}
