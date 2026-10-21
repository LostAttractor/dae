package shadowsocks

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"golang.org/x/crypto/hkdf"
)

func TestUDPWriteEncryptsCompletePacket(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		for _, size := range []int{0, 64, 1200, 32768} {
			t.Run(fmt.Sprintf("%s/%d", method, size), func(t *testing.T) {
				conf := ciphers.AeadCiphersConf[method]
				key := bytes.Repeat([]byte{0x11}, conf.KeyLen)
				salt := bytes.Repeat([]byte{0x22}, conf.SaltLen)
				raw := new(fullWriteErrorConn)
				conn := NewUdpConn(raw, conf, key, &fixedSaltGenerator{salt: salt})
				payload := bytes.Repeat([]byte("x"), size)
				addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}
				if n, err := conn.WriteTo(payload, addr); n != len(payload) || err != nil {
					t.Fatalf("WriteTo = %d, %v", n, err)
				}
				wire := raw.Bytes()
				if !bytes.Equal(wire[:conf.SaltLen], salt) {
					t.Fatal("salt changed")
				}
				subkey := make([]byte, conf.KeyLen)
				if _, err := io.ReadFull(hkdf.New(sha1.New, key, salt, []byte("ss-subkey")), subkey); err != nil {
					t.Fatal(err)
				}
				aead, err := conf.NewCipher(subkey)
				if err != nil {
					t.Fatal(err)
				}
				plain, err := aead.Open(nil, make([]byte, aead.NonceSize()), wire[conf.SaltLen:], nil)
				want := append([]byte{1, 192, 0, 2, 1, 0, 53}, payload...)
				if err != nil || !bytes.Equal(plain, want) {
					t.Fatalf("decrypted packet length = %d, error = %v", len(plain), err)
				}
			})
		}
	}
}
