package direct

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

// Invalid integer ports must never wrap into a real receiver's uint16 port.
func TestUDPInvalidDestinationDoesNotSend(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	conn, err := NewDirectDialer(Option{}).ListenPacket(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	port := receiver.LocalAddr().(*net.UDPAddr).Port
	for _, write := range []func([]byte, net.Addr) (int, error){conn.WriteTo, conn.(netproxy.NonBlockingWriter).TryWriteTo} {
		for _, to := range []*net.UDPAddr{
			nil,
			{IP: net.IP{127}, Port: port},
			{IP: net.IPv4(127, 0, 0, 1), Port: port - 65536},
			{IP: net.IPv4(127, 0, 0, 1), Port: port + 65536},
		} {
			if n, err := write([]byte("must not arrive"), to); n != 0 || err == nil {
				t.Fatalf("write to %v = %d, %v", to, n, err)
			}
		}
	}
	_ = receiver.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, _, err := receiver.ReadFrom(make([]byte, 32)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("invalid address sent a datagram: %v", err)
	}
}

func TestUDPEmptyIPDestinationMatchesNative(t *testing.T) {
	receiver, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	conn, err := NewDirectDialer(Option{}).ListenPacket(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	to := &net.UDPAddr{Port: receiver.LocalAddr().(*net.UDPAddr).Port}
	for _, write := range []func([]byte, net.Addr) (int, error){conn.(*PacketConn).UDPConn.WriteTo, conn.WriteTo, conn.(netproxy.NonBlockingWriter).TryWriteTo} {
		if n, err := write([]byte("probe"), to); errors.Is(err, errors.ErrUnsupported) {
			continue
		} else if n != 5 || err != nil {
			t.Fatalf("empty IP write = %d, %v", n, err)
		}
		_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
		var b [16]byte
		if n, _, err := receiver.ReadFrom(b[:]); err != nil || string(b[:n]) != "probe" {
			t.Fatalf("empty IP delivery = %q, %v", b[:n], err)
		}
	}
}
