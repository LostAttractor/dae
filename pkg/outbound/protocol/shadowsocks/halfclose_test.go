package shadowsocks_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
	ss2022 "github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks_2022"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
	"golang.org/x/crypto/hkdf"
	"lukechampine.com/blake3"
)

type salt []byte

func (s salt) Get() []byte { b := pool.GetBuffer(len(s)); copy(b, s); return b }

func encryptedClient(raw net.Conn, modern bool) net.Conn {
	key := bytes.Repeat([]byte{0x11}, 16)
	requestSalt := salt(bytes.Repeat([]byte{0x22}, 16))
	target, _ := socks5.AddressFromString("example.org:443")
	if modern {
		return ss2022.NewTCPConn(raw, ciphers.Aead2022CiphersConf["2022-blake3-aes-128-gcm"], [][]byte{key}, key, requestSalt, target)
	}
	return shadowsocks.NewTCPConn(raw, ciphers.AeadCiphersConf["aes-128-gcm"], key, requestSalt, target)
}

// The peer response is independent of either client's encoder.
func peerResponse(t *testing.T, modern bool) []byte {
	t.Helper()
	key := bytes.Repeat([]byte{0x11}, 16)
	responseSalt := bytes.Repeat([]byte{0x33}, 16)
	subkey := make([]byte, 16)
	if modern {
		blake3.DeriveKey(subkey, "shadowsocks 2022 session subkey", append(bytes.Clone(key), responseSalt...))
	} else {
		if _, err := io.ReadFull(hkdf.New(sha1.New, key, responseSalt, []byte("ss-subkey")), subkey); err != nil {
			t.Fatal(err)
		}
	}
	block, _ := aes.NewCipher(subkey)
	aead, _ := cipher.NewGCM(block)
	payload := []byte("response after FIN")
	header := binary.BigEndian.AppendUint16(nil, uint16(len(payload)))
	if modern {
		header = binary.BigEndian.AppendUint64([]byte{1}, uint64(time.Now().Unix()))
		header = append(header, bytes.Repeat([]byte{0x22}, 16)...)
		header = binary.BigEndian.AppendUint16(header, uint16(len(payload)))
	}
	nonce := make([]byte, 12)
	wire := aead.Seal(responseSalt, nonce, header, nil)
	nonce[0] = 1
	return aead.Seal(wire, nonce, payload, nil)
}

type gatedWriteConn struct {
	*net.TCPConn
	entered, release, halfCalled chan struct{}
	frame                        []byte
}

func (c *gatedWriteConn) Write(b []byte) (int, error) {
	c.frame = bytes.Clone(b)
	n, err := c.TCPConn.Write(b[:len(b)/2])
	if err != nil {
		return n, err
	}
	close(c.entered)
	<-c.release
	rest, err := c.TCPConn.Write(b[n:])
	return n + rest, err
}
func (c *gatedWriteConn) CloseWrite() error { close(c.halfCalled); return c.TCPConn.CloseWrite() }

func TestEncryptedCloseWriteWaitsForFrameAndKeepsRead(t *testing.T) {
	for _, modern := range []bool{false, true} {
		name := "SS"
		if modern {
			name = "SS2022"
		}
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			raw, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			server, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			_ = raw.SetDeadline(time.Now().Add(time.Second))
			_ = server.SetDeadline(time.Now().Add(time.Second))
			gate := &gatedWriteConn{TCPConn: raw.(*net.TCPConn), entered: make(chan struct{}), release: make(chan struct{}), halfCalled: make(chan struct{})}
			defer func() {
				select {
				case <-gate.release:
				default:
					close(gate.release)
				}
			}()
			client := encryptedClient(gate, modern)
			defer client.Close()
			response := peerResponse(t, modern)
			received := make(chan []byte, 1)
			peerDone := make(chan error, 1)
			go func() {
				wire, err := io.ReadAll(server)
				received <- wire
				if err == nil {
					_, err = server.Write(response)
				}
				if err == nil {
					err = server.(*net.TCPConn).CloseWrite()
				}
				peerDone <- err
			}()
			written := make(chan error, 1)
			go func() { _, err := client.Write([]byte("a complete encrypted application frame")); written <- err }()
			select {
			case <-gate.entered:
			case <-time.After(time.Second):
				t.Fatal("write did not reach carrier")
			}
			halfDone := make(chan error, 1)
			go func() { halfDone <- client.(netproxy.CloseWriter).CloseWrite() }()
			select {
			case <-gate.halfCalled:
				t.Fatal("FIN overtook incomplete ciphertext")
			case <-time.After(20 * time.Millisecond):
			}
			close(gate.release)
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if err := <-halfDone; err != nil {
				t.Fatal(err)
			}
			if got := <-received; !bytes.Equal(got, gate.frame) {
				t.Fatalf("FIN split ciphertext: received %d of %d bytes", len(got), len(gate.frame))
			}
			if _, err := client.Write([]byte("after FIN")); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("write after FIN: %v", err)
			}
			got, err := io.ReadAll(client)
			if err != nil || string(got) != "response after FIN" {
				t.Fatalf("reverse read %q: %v", got, err)
			}
			if err := <-peerDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

type failingHalfClose struct {
	net.Conn
	cause error
	calls int
}

func (c *failingHalfClose) CloseWrite() error { c.calls++; return c.cause }

func TestEncryptedCloseWriteFailureIsSticky(t *testing.T) {
	for _, modern := range []bool{false, true} {
		cause := errors.New("half-close failed")
		raw := &failingHalfClose{cause: cause}
		client := encryptedClient(raw, modern)
		if err := client.(netproxy.CloseWriter).CloseWrite(); !errors.Is(err, cause) {
			t.Fatal(err)
		}
		if err := client.(netproxy.CloseWriter).CloseWrite(); !errors.Is(err, cause) || raw.calls != 1 {
			t.Fatalf("half-close retried: %v, %d", err, raw.calls)
		}
		if _, err := client.Write(nil); !errors.Is(err, cause) {
			t.Fatalf("failed half-close permitted write: %v", err)
		}
		client = encryptedClient(struct{ net.Conn }{}, modern)
		if err := client.(netproxy.CloseWriter).CloseWrite(); !errors.Is(err, errors.ErrUnsupported) {
			t.Fatalf("unsupported half-close: %v", err)
		}
	}
}
