package shadowsocks_2022_test

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"net"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
	ss2022 "github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks_2022"
)

type discardPacketConn struct{ net.Conn }

func (discardPacketConn) Write(p []byte) (int, error) { return len(p), nil }

// Includes address encoding, salt/nonce handling and encryption; socket I/O is
// excluded. Each connection sends many packets, as an established association.
func BenchmarkUDPWriteTo(b *testing.B) {
	for _, method := range []string{"ss", "ss2022"} {
		for _, address := range []string{"192.0.2.1:53", "[2001:db8::1]:53", "example.org:53"} {
			for _, size := range []int{64, 1200} {
				b.Run(fmt.Sprintf("%s/%s/bytes=%d", method, address, size), func(b *testing.B) {
					key := bytes.Repeat([]byte{0x11}, 16)
					var conn interface {
						WriteTo([]byte, net.Addr) (int, error)
					}
					if method == "ss" {
						conf := ciphers.AeadCiphersConf["aes-128-gcm"]
						conn = shadowsocks.NewUdpConn(discardPacketConn{}, conf, key, shadowsocks.RandomSaltGenerator(conf.SaltLen))
					} else {
						conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-128-gcm"]
						block, err := aes.NewCipher(key)
						if err != nil {
							b.Fatal(err)
						}
						conn = ss2022.NewUdpConn(discardPacketConn{}, conf, block, block, [][]byte{key}, key)
					}
					addr := netproxy.NewAddr("udp", address)
					payload := bytes.Repeat([]byte("x"), size)
					b.ReportAllocs()
					b.SetBytes(int64(size))
					for b.Loop() {
						if n, err := conn.WriteTo(payload, addr); err != nil || n != len(payload) {
							b.Fatalf("WriteTo = %d, %v", n, err)
						}
					}
				})
			}
		}
	}
}
