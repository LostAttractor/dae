package shadowsocks_2022

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
)

func TestUDPWriteReusesOnlyItsSessionCipher(t *testing.T) {
	for _, keySize := range []int{16, 32} {
		t.Run(fmt.Sprint(keySize), func(t *testing.T) {
			key := bytes.Repeat([]byte{0x11}, keySize)
			conf := *ciphers.Aead2022CiphersConf[fmt.Sprintf("2022-blake3-aes-%d-gcm", keySize*8)]
			create, calls := conf.NewCipher, 0
			conf.NewCipher = func(key []byte) (cipher.AEAD, error) {
				calls++
				return create(key)
			}
			block, err := aes.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}
			for session := range 2 {
				raw := new(memoryConn)
				conn := NewUdpConn(raw, &conf, block, block, [][]byte{key}, key)
				var writers sync.WaitGroup
				for range 16 {
					writers.Go(func() {
						if _, err := conn.WriteTo([]byte("payload"), addr); err != nil {
							t.Error(err)
						}
					})
				}
				writers.Wait()
				if calls != session+1 || len(raw.sent) != 16 {
					t.Fatalf("cipher creations = %d, packets = %d", calls, len(raw.sent))
				}
				peer := peerCipher(t, key, conn.sessionID[:])
				for i, wire := range raw.sent {
					var header [16]byte
					block.Decrypt(header[:], wire[:16])
					if !bytes.Equal(header[:8], conn.sessionID[:]) || binary.BigEndian.Uint64(header[8:]) != uint64(i) {
						t.Fatalf("packet %d has invalid session or nonce", i)
					}
					body, err := peer.Open(nil, header[4:], wire[16:], nil)
					want := append([]byte{0, 0, 1, 192, 0, 2, 1, 0, 53}, []byte("payload")...)
					if err != nil || len(body) < 9 || body[0] != HeaderTypeClientStream || !bytes.Equal(body[9:], want) {
						t.Fatalf("packet %d decrypted incorrectly: %x, %v", i, body, err)
					}
				}
			}
		})
	}
}

func TestUDPWriteCipherCreationFailureCanRetry(t *testing.T) {
	conn, raw := newUDPForTest(t)
	conf := *conn.cipherConf
	create, calls := conf.NewCipher, 0
	want := errors.New("cipher unavailable")
	conf.NewCipher = func(key []byte) (cipher.AEAD, error) {
		calls++
		if calls == 1 {
			return nil, want
		}
		return create(key)
	}
	conn.cipherConf = &conf
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}
	if n, err := conn.WriteTo([]byte("first"), addr); n != 0 || !errors.Is(err, want) || raw.writes != 0 {
		t.Fatalf("failed initialization = %d, %v, %d writes", n, err, raw.writes)
	}
	for range 2 {
		if _, err := conn.WriteTo([]byte("retry"), addr); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatalf("cipher creations = %d, want 2", calls)
	}
	for i, wire := range raw.sent {
		var header [16]byte
		conn.blockCipherDecrypt.Decrypt(header[:], wire[:16])
		if binary.BigEndian.Uint64(header[8:]) != uint64(i+1) {
			t.Fatal("failed initialization caused packet ID reuse")
		}
	}
}
