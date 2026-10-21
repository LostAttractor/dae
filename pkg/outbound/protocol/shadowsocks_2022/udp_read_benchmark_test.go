package shadowsocks_2022

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
)

type repeatingUDPResponses struct {
	net.Conn
	packets [][]byte
	next    int
}

func (c *repeatingUDPResponses) Read(p []byte) (int, error) {
	n := copy(p, c.packets[c.next])
	c.next = (c.next + 1) % len(c.packets)
	return n, nil
}

// Server encryption and socket I/O are excluded. A prebuilt packet corpus is
// reused by rewinding only replay windows between batches, retaining ciphers.
func BenchmarkUDPReadFrom(b *testing.B) {
	for _, keySize := range []int{16, 32} {
		for _, sessions := range []int{1, 2} {
			for _, size := range []int{64, 1200} {
				b.Run(fmt.Sprintf("AES%d/sessions=%d/bytes=%d", keySize*8, sessions, size), func(b *testing.B) {
					key := bytes.Repeat([]byte{1}, keySize)
					conf := ciphers.Aead2022CiphersConf[fmt.Sprintf("2022-blake3-aes-%d-gcm", keySize*8)]
					block, err := aes.NewCipher(key)
					if err != nil {
						b.Fatal(err)
					}
					raw := new(repeatingUDPResponses)
					c := NewUdpConn(raw, conf, block, block, [][]byte{key}, key)
					body := binary.BigEndian.AppendUint64([]byte{1}, uint64(time.Now().Unix()))
					body = append(body, c.sessionID[:]...)
					body = append(body, 0, 0, 1, 127, 0, 0, 1, 0, 53)
					body = append(body, bytes.Repeat([]byte("x"), size)...)
					for i := range 256 {
						server := [8]byte{byte(i%sessions + 1)}
						header := binary.BigEndian.AppendUint64(server[:], uint64(i/sessions))
						wire := make([]byte, 16, 16+len(body)+conf.TagLen)
						block.Encrypt(wire, header)
						wire = peerCipher(b, key, server[:]).Seal(wire, header[4:], body, nil)
						raw.packets = append(raw.packets, wire)
					}
					out := make([]byte, size)
					b.ReportAllocs()
					b.SetBytes(int64(size))
					for b.Loop() {
						if raw.next == 0 {
							for i := range c.serverSessions {
								c.serverSessions[i].initialized = false
								c.serverSessions[i].latest = 0
							}
						}
						if n, _, err := c.ReadFrom(out); err != nil || n != size {
							b.Fatalf("ReadFrom = %d, %v", n, err)
						}
					}
				})
			}
		}
	}
}
