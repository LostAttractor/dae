package protocol_test

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
)

type countedSeal struct {
	cipher.AEAD
	seals *int
}

func (c countedSeal) Seal(dst, nonce, plaintext, additional []byte) []byte {
	*c.seals++
	return c.AEAD.Seal(dst, nonce, plaintext, additional)
}

type countedSalt struct {
	shadowsocks.SaltGenerator
	salts int
}

func (s *countedSalt) Get() []byte {
	s.salts++
	return s.SaltGenerator.Get()
}

type discardWaitingSocket struct {
	net.PacketConn
	writes int
}

func (s *discardWaitingSocket) WriteTo(b []byte, _ net.Addr) (int, error) {
	s.writes++
	return len(b), nil
}

func waitingCipherChain(depth int, socket net.PacketConn, seals *int, salt shadowsocks.SaltGenerator) net.PacketConn {
	conf := *ciphers.AeadCiphersConf["aes-128-gcm"]
	create := conf.NewCipher
	conf.NewCipher = func(key []byte) (cipher.AEAD, error) {
		c, err := create(key)
		return countedSeal{c, seals}, err
	}
	for range depth {
		carrier := netproxy.TrackConn(&netproxy.BindPacketConn{PacketConn: netproxy.TrackPacketConn(socket, func() {}),
			Address: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 8388}}, func() {})
		socket = shadowsocks.NewUdpConn(carrier, &conf, make([]byte, conf.KeyLen), salt)
	}
	return socket
}

func TestUDPWaitingChainEncryptsOncePerLayer(t *testing.T) {
	for _, depth := range []int{1, 3} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			socket := new(discardWaitingSocket)
			seals := 0
			salt := &countedSalt{SaltGenerator: shadowsocks.RandomSaltGenerator(16)}
			conn := waitingCipherChain(depth, socket, &seals, salt)
			to := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443}
			payload := make([]byte, 1200)
			if _, err := netproxy.TryWriteTo(conn, payload, to); err != errors.ErrUnsupported {
				t.Fatalf("TryWriteTo = %v", err)
			}
			if seals != 0 || salt.salts != 0 || socket.writes != 0 {
				t.Fatalf("unsupported try performed %d seals, %d salts, %d writes", seals, salt.salts, socket.writes)
			}
			if n, err := conn.WriteTo(payload, to); n != len(payload) || err != nil {
				t.Fatalf("WriteTo = %d, %v", n, err)
			}
			if seals != depth || salt.salts != depth || socket.writes != 1 {
				t.Fatalf("fallback performed %d seals, %d salts, %d writes; want %d, %d, 1", seals, salt.salts, socket.writes, depth, depth)
			}
		})
	}
}

func BenchmarkUDPWaitingFallback(b *testing.B) {
	for _, depth := range []int{1, 3} {
		for _, try := range []bool{false, true} {
			b.Run(fmt.Sprintf("layers=%d/try=%t", depth, try), func(b *testing.B) {
				seals := 0
				conn := waitingCipherChain(depth, new(discardWaitingSocket), &seals, shadowsocks.RandomSaltGenerator(16))
				to := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443}
				payload := make([]byte, 1200)
				b.ReportAllocs()
				for b.Loop() {
					if try {
						if _, err := netproxy.TryWriteTo(conn, payload, to); err != errors.ErrUnsupported {
							b.Fatal(err)
						}
					}
					if _, err := conn.WriteTo(payload, to); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
