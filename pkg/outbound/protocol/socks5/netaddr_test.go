package socks5

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

func TestWriteNetAddrMatchesWireCodec(t *testing.T) {
	for _, addr := range []net.Addr{
		&net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 53},
		&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 65535},
		&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 0},
		&net.UDPAddr{IP: net.ParseIP("fe80::1"), Zone: "eth0", Port: 53},
		&net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443},
		netproxy.NewProxyAddr("udp", "example.org:53"),
		netproxy.NewProxyAddr("udp", strings.Repeat("a", 255)+":53"),
	} {
		t.Run(addr.String(), func(t *testing.T) {
			var got, want bytes.Buffer
			if err := WriteAddr(addr.String(), &want); err != nil {
				t.Fatal(err)
			}
			if err := WriteNetAddr(addr, &got); err != nil || !bytes.Equal(got.Bytes(), want.Bytes()) {
				t.Fatalf("wire = %x, %v; want %x", got.Bytes(), err, want.Bytes())
			}
		})
	}
}

func TestWriteNetAddrRejectsInvalidDestination(t *testing.T) {
	for _, addr := range []net.Addr{
		nil, (*net.UDPAddr)(nil),
		&net.UDPAddr{Port: 53},
		&net.UDPAddr{IP: net.IP{1, 2}, Port: 53},
		&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: -1},
		&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 65536},
		netproxy.NewProxyAddr("udp", strings.Repeat("a", 256)+":53"),
	} {
		var buf bytes.Buffer
		if err := WriteNetAddr(addr, &buf); err == nil {
			t.Fatalf("accepted invalid address %v", addr)
		}
	}
}
