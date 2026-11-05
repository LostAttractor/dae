package shadowsocks_2022

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func responseStream(t testing.TB, key, requestSalt, payload []byte, frames int) []byte {
	t.Helper()
	wire := responseFrame(t, key, requestSalt, payload, uint64(time.Now().Unix()))
	aead := peerCipher(t, key, bytes.Repeat([]byte{0x31}, len(key)))
	var nonce [12]byte
	length := binary.BigEndian.AppendUint16(nil, uint16(len(payload)))
	for i := 1; i < frames; i++ {
		binary.LittleEndian.PutUint64(nonce[:], uint64(2*i))
		wire = aead.Seal(wire, nonce[:], length, nil)
		binary.LittleEndian.PutUint64(nonce[:], uint64(2*i+1))
		wire = aead.Seal(wire, nonce[:], payload, nil)
	}
	return wire
}

// Each connection receives 64 authenticated frames. Memory isolates decoding;
// loopback includes both ends' socket I/O, connection setup and teardown.
func BenchmarkTCPReadFrames(b *testing.B) {
	for _, loopback := range []bool{false, true} {
		for _, size := range []int{256, 4096, 32768} {
			b.Run(fmt.Sprintf("loopback=%t/bytes=%d", loopback, size), func(b *testing.B) {
				key := bytes.Repeat([]byte{0x11}, 16)
				payload := bytes.Repeat([]byte("x"), size)
				wire := responseStream(b, key, bytes.Repeat([]byte{0x22}, len(key)), payload, 64)
				var listener net.Listener
				var server sync.WaitGroup
				if loopback {
					var err error
					listener, err = net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						b.Fatal(err)
					}
					server.Go(func() {
						for {
							conn, err := listener.Accept()
							if err != nil {
								return
							}
							_, err = conn.Write(wire)
							if err == nil {
								// Closing with the client's request unread would reset the stream.
								err = conn.(*net.TCPConn).CloseWrite()
								_, _ = io.Copy(io.Discard, conn)
							}
							conn.Close()
							if err != nil {
								b.Error(err)
								return
							}
						}
					})
					defer server.Wait()
					defer listener.Close()
				}
				buf := make([]byte, size*64)
				reads := 0
				b.ReportAllocs()
				b.SetBytes(int64(len(buf)))
				for b.Loop() {
					raw := &memoryConn{reader: bytes.NewReader(wire)}
					var carrier net.Conn = raw
					if loopback {
						var err error
						carrier, err = net.Dial("tcp", listener.Addr().String())
						if err != nil {
							b.Fatal(err)
						}
					}
					conn := newClientForTest(b, carrier, key)
					_, err := io.ReadFull(conn, buf)
					conn.Close()
					if err != nil {
						b.Fatal(err)
					}
					reads += raw.reads
				}
				if !loopback {
					b.ReportMetric(float64(reads)/float64(b.N), "reads/op")
				}
				if !bytes.Equal(buf, bytes.Repeat(payload, 64)) {
					b.Fatal("response payload changed")
				}
			})
		}
	}
}

type discardConn struct{ memoryConn }

func (*discardConn) Write(b []byte) (int, error) { return len(b), nil }

// A multiplexer writes batches of frames, each an 8-byte header and its
// payload in one buffer; here two. "copy" joins them before Write, "buffers"
// passes them to WriteBuffers.
func BenchmarkTCPWriteFrames(b *testing.B) {
	for _, mode := range []string{"copy", "buffers"} {
		for _, size := range []int{64, 1300, 32<<10 - 8} {
			b.Run(fmt.Sprintf("%s/bytes=%d", mode, size), func(b *testing.B) {
				key := bytes.Repeat([]byte{0x11}, 16)
				conn := newClientForTest(b, new(discardConn), key)
				if _, err := conn.Write(nil); err != nil {
					b.Fatal(err)
				}
				frame := bytes.Repeat([]byte("x"), 8+size)
				frames := [][]byte{frame, frame}
				joined := make([]byte, 2*len(frame))
				b.ReportAllocs()
				b.SetBytes(int64(len(joined)))
				for b.Loop() {
					var err error
					if mode == "copy" {
						copy(joined[copy(joined, frame):], frame)
						_, err = conn.Write(joined)
					} else {
						_, err = conn.WriteBuffers(frames)
					}
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
