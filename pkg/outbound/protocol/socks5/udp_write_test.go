package socks5

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/infra/socks"
)

type udpWriteCapture struct {
	net.PacketConn
	wire  []byte
	to    net.Addr
	short bool
}

func (c *udpWriteCapture) WriteTo(p []byte, to net.Addr) (int, error) {
	c.wire, c.to = bytes.Clone(p), to
	if c.short {
		return len(p) - 1, nil
	}
	return len(p), nil
}

func TestUDPWriteSharedCodecPreservesWireAndLimits(t *testing.T) {
	for _, destination := range []string{"192.0.2.1:53", "[::ffff:192.0.2.1]:53", "[2001:db8::1]:53", "example.org:53", strings.Repeat("a", 255) + ":53"} {
		t.Run(destination, func(t *testing.T) {
			addr := netproxy.NewAddr("udp", destination)
			target, err := socks.ParseAddr(addr.String())
			if err != nil {
				t.Fatal(err)
			}
			raw := new(udpWriteCapture)
			server := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 1080}
			c := &PktConn{PacketConn: raw, server: server, lease: netproxy.NewLease(netproxy.NewResourceRef())}
			limit := 65507 - 3 - len(target)
			for _, size := range []int{0, 64, limit, limit + 1} {
				payload := bytes.Repeat([]byte("x"), size)
				raw.wire = nil
				n, err := c.WriteTo(payload, addr)
				if size > limit {
					if n != 0 || err == nil || raw.wire != nil {
						t.Fatal("oversized packet reached the relay")
					}
					continue
				}
				want := append(append([]byte{0, 0, 0}, target...), payload...)
				if n != size || err != nil || raw.to != server || !bytes.Equal(raw.wire, want) {
					t.Fatalf("WriteTo(%d) = %d, %v; wire or relay differs", size, n, err)
				}
			}
			raw.short = true
			if n, err := c.WriteTo([]byte("query"), addr); n != 0 || !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("short write = %d, %v", n, err)
			}
			for _, invalid := range []net.Addr{nil, (*net.UDPAddr)(nil), &net.UDPAddr{Port: -1}, netproxy.NewProxyAddr("udp", strings.Repeat("a", 256)+":53")} {
				raw.wire = nil
				if _, err := c.WriteTo(nil, invalid); err == nil || raw.wire != nil {
					t.Fatalf("invalid address reached relay: %v", invalid)
				}
			}
		})
	}
}

type discardUDPWrites struct{ net.PacketConn }

func (discardUDPWrites) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }

// Measures full SOCKS5 datagram encoding without socket I/O.
func BenchmarkUDPWriteTo(b *testing.B) {
	for _, destination := range []string{"192.0.2.1:53", "[2001:db8::1]:53", "example.org:53"} {
		for _, size := range []int{64, 1200} {
			b.Run(fmt.Sprintf("%s/bytes=%d", destination, size), func(b *testing.B) {
				c := &PktConn{PacketConn: discardUDPWrites{}, lease: netproxy.NewLease(netproxy.NewResourceRef())}
				addr := netproxy.NewAddr("udp", destination)
				payload := bytes.Repeat([]byte("x"), size)
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for b.Loop() {
					if n, err := c.WriteTo(payload, addr); err != nil || n != size {
						b.Fatalf("WriteTo = %d, %v", n, err)
					}
				}
			})
		}
	}
}
