package shadowsocks

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/transport/simpleobfs"
	"golang.org/x/crypto/hkdf"
)

const obfsResponseHeader = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n"

type frameReadConn struct {
	net.Conn
	reader bytes.Reader
	reads  int
}

func (c *frameReadConn) Read(p []byte) (int, error) {
	c.reads++
	return c.reader.Read(p)
}

func (c *frameReadConn) Close() error { return nil }

// Build peer frames independently of TCPConn's framing and key derivation.
func responseStream(t testing.TB, method string, payload []byte, frames int) (key, wire []byte) {
	t.Helper()
	conf := ciphers.AeadCiphersConf[method]
	key = bytes.Repeat([]byte{0x11}, conf.KeyLen)
	salt := bytes.Repeat([]byte{0x22}, conf.SaltLen)
	subkey := make([]byte, conf.KeyLen)
	if _, err := io.ReadFull(hkdf.New(sha1.New, key, salt, []byte("ss-subkey")), subkey); err != nil {
		t.Fatal(err)
	}
	aead, err := conf.NewCipher(subkey)
	if err != nil {
		t.Fatal(err)
	}
	wire = bytes.Clone(salt)
	nonce := make([]byte, aead.NonceSize())
	length := binary.BigEndian.AppendUint16(nil, uint16(len(payload)))
	for i := range frames {
		binary.LittleEndian.PutUint64(nonce, uint64(2*i))
		wire = aead.Seal(wire, nonce, length, nil)
		binary.LittleEndian.PutUint64(nonce, uint64(2*i+1))
		wire = aead.Seal(wire, nonce, payload, nil)
	}
	return key, wire
}

func TestTCPReadFrames(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		for _, size := range []int{256, 4096, TCPChunkMaxLen} {
			for _, obfs := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/bytes=%d/obfs=%t", method, size, obfs), func(t *testing.T) {
					payload := bytes.Repeat([]byte("x"), size)
					key, wire := responseStream(t, method, payload, 3)
					raw := new(frameReadConn)
					var carrier net.Conn = raw
					if obfs {
						wire = append([]byte(obfsResponseHeader), wire...)
						carrier = simpleobfs.NewHTTPObfs(raw, "example.org", "80", "/")
					}
					raw.reader.Reset(wire)
					conn := NewTCPConn(carrier, ciphers.AeadCiphersConf[method], key, nil, nil)
					defer conn.Close()
					var got bytes.Buffer
					buf := make([]byte, 137)
					for {
						n, err := conn.Read(buf)
						got.Write(buf[:n])
						if errors.Is(err, io.EOF) {
							break
						}
						if err != nil {
							t.Fatal(err)
						}
					}
					if !bytes.Equal(got.Bytes(), bytes.Repeat(payload, 3)) {
						t.Fatal("response frames lost or corrupted")
					}
				})
			}
		}
	}
}

func TestTCPReadBufferedAuthenticationFailure(t *testing.T) {
	payload := []byte("authenticated payload")
	key, wire := responseStream(t, "aes-128-gcm", payload, 2)
	wire[len(wire)-1] ^= 1
	raw := new(frameReadConn)
	raw.reader.Reset(wire)
	conn := NewTCPConn(raw, ciphers.AeadCiphersConf["aes-128-gcm"], key, nil, nil)
	defer conn.Close()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("first frame = %q, %v", got, err)
	}
	for range 2 {
		if n, err := conn.Read(got); n != 0 || !errors.Is(err, protocol.ErrFailAuth) {
			t.Fatalf("corrupt buffered frame = %d, %v", n, err)
		}
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(got); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read after Close = %v", err)
	}
}

func TestTCPReadTimeoutAtFrameBoundary(t *testing.T) {
	payload := []byte("fragmented response")
	key, wire := responseStream(t, "aes-128-gcm", payload, 2)
	firstFrameEnd := 16 + 18 + len(payload) + 16
	raw := &interruptedReader{steps: []readStep{{nil, os.ErrDeadlineExceeded}}}
	for i, value := range wire {
		step := readStep{data: []byte{value}}
		if i == firstFrameEnd-1 {
			step.err = os.ErrDeadlineExceeded
		}
		raw.steps = append(raw.steps, step)
	}
	conn := NewTCPConn(raw, ciphers.AeadCiphersConf["aes-128-gcm"], key, nil, nil)
	defer conn.Close()
	got := make([]byte, len(payload))
	if n, err := conn.Read(got); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("initial timeout = %d, %v", n, err)
	}
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("first frame = %q, %v", got, err)
	}
	if n, err := conn.Read(got); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("buffered timeout = %d, %v", n, err)
	}
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("frame after timeout = %q, %v", got, err)
	}
}

// Each operation reads 64 frames and closes the connection. Loopback includes
// both ends' socket I/O; obfs measures the cost of stacking two buffered readers.
func BenchmarkTCPReadFrames(b *testing.B) {
	for _, loopback := range []bool{false, true} {
		for _, obfs := range []bool{false, true} {
			for _, size := range []int{256, 4096, TCPChunkMaxLen} {
				b.Run(fmt.Sprintf("loopback=%t/obfs=%t/bytes=%d", loopback, obfs, size), func(b *testing.B) {
					payload := bytes.Repeat([]byte("x"), size)
					key, wire := responseStream(b, "aes-128-gcm", payload, 64)
					if obfs {
						wire = append([]byte(obfsResponseHeader), wire...)
					}
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
						raw := new(frameReadConn)
						raw.reader.Reset(wire)
						var carrier net.Conn = raw
						if loopback {
							var err error
							carrier, err = net.Dial("tcp", listener.Addr().String())
							if err != nil {
								b.Fatal(err)
							}
						}
						if obfs {
							carrier = simpleobfs.NewHTTPObfs(carrier, "example.org", "80", "/")
						}
						conn := NewTCPConn(carrier, ciphers.AeadCiphersConf["aes-128-gcm"], key, nil, nil)
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
}
