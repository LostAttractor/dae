package shadowsocks_2022

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
)

func TestUDPReadCipherCacheTracksAcceptedSessions(t *testing.T) {
	for _, keySize := range []int{16, 32} {
		t.Run(fmt.Sprint(keySize), func(t *testing.T) {
			key := bytes.Repeat([]byte{1}, keySize)
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
			raw := new(memoryConn)
			c := NewUdpConn(raw, &conf, block, block, [][]byte{key}, key)
			a, b, next := [8]byte{1}, [8]byte{2}, [8]byte{3}
			now := uint64(time.Now().Unix())
			read := func(valid bool) {
				t.Helper()
				var out [32]byte
				n, addr, err := c.ReadFrom(out[:])
				if valid {
					if err != nil || string(out[:n]) != "answer" || addr.String() != "127.0.0.1:53" {
						t.Errorf("ReadFrom = %d, %v, %v, %q", n, addr, err, out[:n])
					}
				} else if err == nil {
					t.Error("invalid packet accepted")
				}
			}
			for id := range 8 {
				for _, server := range [][8]byte{a, b} {
					raw.packets = append(raw.packets, udpResponse(t, c, server, uint64(id), c.sessionID, now))
				}
			}
			var readers sync.WaitGroup
			for range 16 {
				readers.Go(func() { read(true) })
			}
			readers.Wait()
			if calls != 2 {
				t.Fatalf("cipher creations = %d, want one per server session", calls)
			}
			before := c.serverSessions
			raw.packets = [][]byte{udpResponse(t, c, next, 0, c.sessionID, now)}
			read(false)
			if c.serverSessions != before {
				t.Fatal("third session evicted a recent session")
			}
			c.serverSessions[0].lastSeen = time.Now().Add(-time.Minute)

			// Failures must not change replay state or replace even an expired cache entry.
			for _, server := range [][8]byte{a, next} {
				for _, damage := range []string{"tag", "type", "time", "client", "padding", "address"} {
					wire := udpResponse(t, c, server, 9000, c.sessionID, now)
					if damage == "tag" {
						wire[len(wire)-1] ^= 1
					} else {
						var header [16]byte
						block.Decrypt(header[:], wire[:16])
						peer := peerCipher(t, key, server[:])
						body, err := peer.Open(nil, header[4:], wire[16:], nil)
						if err != nil {
							t.Fatal(err)
						}
						switch damage {
						case "type":
							body[0] = 0
						case "time":
							clear(body[1:9])
						case "client":
							body[9] ^= 1
						case "padding":
							body[17] = 255
						case "address":
							body[19] = 255
						}
						wire = peer.Seal(wire[:16], header[4:], body, nil)
					}
					before := c.serverSessions
					raw.packets = [][]byte{wire}
					read(false)
					if c.serverSessions != before {
						t.Fatalf("%s failure changed session state", damage)
					}
				}
			}
			before = c.serverSessions
			raw.packets = [][]byte{udpResponse(t, c, a, 0, c.sessionID, now)}
			read(false)
			if c.serverSessions != before {
				t.Fatal("replay changed session state")
			}
			creations := calls
			for i, server := range [][8]byte{next, b, next, b} {
				raw.packets = [][]byte{udpResponse(t, c, server, uint64(8+i), c.sessionID, now)}
				read(true)
			}
			if calls != creations+1 || c.serverSessions[0].id != next {
				t.Fatal("server restart failed to replace and reuse only the expired session")
			}
		})
	}
}

func TestUDPReadCipherCreationFailureCanRetry(t *testing.T) {
	c, raw := newUDPForTest(t)
	conf := *c.cipherConf
	create, calls := conf.NewCipher, 0
	want := errors.New("cipher unavailable")
	conf.NewCipher = func(key []byte) (cipher.AEAD, error) {
		calls++
		if calls == 1 {
			return nil, want
		}
		return create(key)
	}
	c.cipherConf = &conf
	packet := udpResponse(t, c, [8]byte{1}, 0, c.sessionID, uint64(time.Now().Unix()))
	raw.packets = [][]byte{packet, packet}
	before := c.serverSessions
	var out [32]byte
	if _, _, err := c.ReadFrom(out[:]); !errors.Is(err, want) || c.serverSessions != before {
		t.Fatalf("failed initialization changed state: %v", err)
	}
	if _, _, err := c.ReadFrom(out[:]); err != nil || calls != 2 {
		t.Fatalf("retry = %v, cipher creations = %d", err, calls)
	}
}
