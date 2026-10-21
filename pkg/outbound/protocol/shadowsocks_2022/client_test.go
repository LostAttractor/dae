package shadowsocks_2022

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
	"lukechampine.com/blake3"
)

type memoryConn struct {
	reader        *bytes.Reader
	packets       [][]byte
	sent          [][]byte
	reads, writes int
	short         bool
	closed        bool
}

func (c *memoryConn) Read(b []byte) (int, error) {
	c.reads++
	if len(c.packets) > 0 {
		p := c.packets[0]
		c.packets = c.packets[1:]
		return copy(b, p), nil
	}
	if c.reader == nil {
		return 0, io.EOF
	}
	return c.reader.Read(b)
}
func (c *memoryConn) Write(b []byte) (int, error) {
	c.writes++
	n := len(b)
	if c.short {
		n /= 2
	}
	c.sent = append(c.sent, append([]byte(nil), b[:n]...))
	return n, nil
}
func (c *memoryConn) Close() error                     { c.closed = true; return nil }
func (c *memoryConn) LocalAddr() net.Addr              { return nil }
func (c *memoryConn) RemoteAddr() net.Addr             { return nil }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }

type fixedSalt []byte

func (s fixedSalt) Get() []byte { b := pool.GetBuffer(len(s)); copy(b, s); return b }

// Peer codecs live only in tests and use the specified BLAKE3/AES construction.
func peerCipher(t testing.TB, key, salt []byte) cipher.AEAD {
	t.Helper()
	derived := make([]byte, len(key))
	material := append(append([]byte(nil), key...), salt...)
	blake3.DeriveKey(derived, "shadowsocks 2022 session subkey", material)
	block, err := aes.NewCipher(derived)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}
func responseFrame(t testing.TB, key, requestSalt, payload []byte, seconds uint64) []byte {
	salt := bytes.Repeat([]byte{0x31}, len(key))
	aead := peerCipher(t, key, salt)
	header := binary.BigEndian.AppendUint64([]byte{1}, seconds)
	header = append(header, requestSalt...)
	header = binary.BigEndian.AppendUint16(header, uint16(len(payload)))
	nonce := make([]byte, 12)
	wire := append([]byte(nil), salt...)
	wire = aead.Seal(wire, nonce, header, nil)
	nonce[0] = 1
	return aead.Seal(wire, nonce, payload, nil)
}
func newClientForTest(t testing.TB, raw net.Conn, key []byte) *TCPConn {
	t.Helper()
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-128-gcm"]
	if len(key) == 32 {
		conf = ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	}
	addr, err := socks5.AddressFromString("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	return NewTCPConn(raw, conf, [][]byte{key}, key, fixedSalt(bytes.Repeat([]byte{0x22}, len(key))), addr).(*TCPConn)
}

func TestClientTCPResponseBufferOwnership(t *testing.T) {
	for _, size := range []int{16, 32} {
		t.Run(string(rune('a'+size)), func(t *testing.T) {
			key := bytes.Repeat([]byte{0x11}, size)
			raw := new(memoryConn)
			c := newClientForTest(t, raw, key)
			payload := []byte("response remains owned until consumed")
			raw.reader = bytes.NewReader(responseFrame(t, key, c.requestSalt, payload, uint64(time.Now().Unix())))
			first := make([]byte, 3)
			if n, err := c.Read(first); err != nil || n != 3 {
				t.Fatalf("Read=%d %v", n, err)
			}
			if c.readBuf == nil {
				t.Fatal("partial response released its storage")
			}
			scratch := pool.GetBuffer(len(payload) + c.cipherConf.TagLen)
			for i := range scratch {
				scratch[i] = 0xcc
			}
			defer pool.PutBuffer(scratch)
			rest, err := io.ReadAll(c)
			if err != nil || string(append(first, rest...)) != string(payload) {
				t.Fatalf("response=%q err=%v", append(first, rest...), err)
			}
			if c.readBuf != nil || c.readOffset != 0 {
				t.Fatal("fully read payload retained storage")
			}
			raw.reader = bytes.NewReader(responseFrame(t, key, c.requestSalt, payload, uint64(time.Now().Unix())))
			fresh := newClientForTest(t, raw, key)
			if _, err := fresh.Read(first); err != nil {
				t.Fatal(err)
			}
			if err := fresh.Close(); err != nil {
				t.Fatal(err)
			}
			if fresh.readBuf != nil || fresh.readOffset != 0 || fresh.reader != nil {
				t.Fatal("Close retained read storage")
			}
		})
	}
}

func TestClientTCPRejectsResponseReplayAndKeepsFailure(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	for _, tc := range []struct {
		name      string
		delta     int64
		wrongSalt bool
	}{
		{"old timestamp", -31, false}, {"future timestamp", 31, false}, {"wrong request salt", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := new(memoryConn)
			c := newClientForTest(t, raw, key)
			salt := append([]byte(nil), c.requestSalt...)
			if tc.wrongSalt {
				salt[0] ^= 1
			}
			raw.reader = bytes.NewReader(responseFrame(t, key, salt, []byte("payload"), uint64(time.Now().Unix()+tc.delta)))
			if _, err := c.Read(make([]byte, 8)); !errors.Is(err, protocol.ErrReplayAttack) {
				t.Fatalf("Read=%v", err)
			}
			reads := raw.reads
			if _, err := c.Read(make([]byte, 8)); !errors.Is(err, protocol.ErrReplayAttack) || raw.reads != reads {
				t.Fatalf("retry re-read header: %v calls=%d", err, raw.reads)
			}
		})
	}
}

func TestClientTCPTruncatedFrameIsSticky(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	for _, cut := range []int{4, 40, 60} {
		t.Run(string(rune('a'+cut)), func(t *testing.T) {
			raw := new(memoryConn)
			c := newClientForTest(t, raw, key)
			wire := responseFrame(t, key, c.requestSalt, []byte("long enough payload"), uint64(time.Now().Unix()))
			raw.reader = bytes.NewReader(wire[:cut])
			_, first := c.Read(make([]byte, 4))
			if first == nil {
				t.Fatal("truncation accepted")
			}
			calls := raw.reads
			raw.reader = bytes.NewReader(wire[cut:])
			_, second := c.Read(make([]byte, 4))
			if second != first || raw.reads != calls {
				t.Fatal("retry consumed more of an incomplete frame")
			}
		})
	}
}

func TestClientTCPReadFrames(t *testing.T) {
	for _, keySize := range []int{16, 32} {
		for _, size := range []int{256, 4096, TCPChunkMaxLen} {
			t.Run(fmt.Sprintf("key=%d/payload=%d", keySize, size), func(t *testing.T) {
				key := bytes.Repeat([]byte{0x11}, keySize)
				raw := new(memoryConn)
				c := newClientForTest(t, raw, key)
				defer c.Close()
				payload := bytes.Repeat([]byte("x"), size)
				raw.reader = bytes.NewReader(responseStream(t, key, c.requestSalt, payload, 3))
				var got bytes.Buffer
				buf := make([]byte, 137)
				for {
					n, err := c.Read(buf)
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
				if size == 256 && raw.reads != 2 {
					t.Fatalf("coalesced frames used %d reads, want one data read and EOF", raw.reads)
				}
			})
		}
	}
}

func TestClientTCPBufferedAuthenticationFailure(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 16)
	raw := new(memoryConn)
	c := newClientForTest(t, raw, key)
	defer c.Close()
	payload := []byte("authenticated payload")
	wire := responseStream(t, key, c.requestSalt, payload, 2)
	wire[len(wire)-1] ^= 1
	raw.reader = bytes.NewReader(wire)
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil || !bytes.Equal(buf, payload) {
		t.Fatalf("valid first frame = %q, %v", buf, err)
	}
	if n, err := c.Read(buf); n != 0 || !errors.Is(err, protocol.ErrFailAuth) {
		t.Fatalf("unauthenticated payload returned: %d, %v", n, err)
	}
	reads := raw.reads
	if _, err := c.Read(buf); !errors.Is(err, protocol.ErrFailAuth) || raw.reads != reads {
		t.Fatalf("authentication failure was not sticky: %v", err)
	}
}

func TestClientTCPReadBoundaryTimeoutRetry(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 16)
	raw, peer := net.Pipe()
	defer peer.Close()
	c := newClientForTest(t, raw, key)
	defer c.Close()
	payload := []byte("retry after a boundary timeout")
	wire := responseStream(t, key, c.requestSalt, payload, 2)
	if err := raw.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("expired deadline did not fail")
	} else if timeout, ok := errors.AsType[net.Error](err); !ok || !timeout.Timeout() {
		t.Fatalf("Read = %v, want timeout", err)
	}
	if err := raw.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		// Fragment the peer's stream across frame headers and payloads.
		for len(wire) > 0 {
			n, err := peer.Write(wire[:min(7, len(wire))])
			if err != nil {
				done <- err
				return
			}
			wire = wire[n:]
		}
		done <- peer.Close()
	}()
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, bytes.Repeat(payload, 2)) {
		t.Fatalf("retry response = %q, %v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestClientTCPIncompleteWriteAndInitFailureAreSticky(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	raw := &memoryConn{short: true}
	c := newClientForTest(t, raw, key)
	if n, err := c.Write([]byte("hello")); n != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Write=%d %v", n, err)
	}
	if _, err := c.Write([]byte("again")); !errors.Is(err, io.ErrShortWrite) || raw.writes != 1 {
		t.Fatal("partial request was retried")
	}
	raw = new(memoryConn)
	c = newClientForTest(t, raw, key)
	c.addr = &socks5.AddressInfo{Type: socks5.AddressTypeDomain, Hostname: strings.Repeat("x", 256)}
	_, first := c.Write(nil)
	if first == nil {
		t.Fatal("invalid address accepted")
	}
	c.addr, _ = socks5.AddressFromString("valid.test:443")
	_, second := c.Write(nil)
	if second != first || raw.writes != 0 {
		t.Fatal("failed initial header was retried")
	}
}

func udpResponse(t *testing.T, c *UdpConn, server [8]byte, packetID uint64, client [8]byte, seconds uint64) []byte {
	separate := append([]byte(nil), server[:]...)
	separate = binary.BigEndian.AppendUint64(separate, packetID)
	encrypted := make([]byte, 16)
	block, err := aes.NewCipher(c.uPSK)
	if err != nil {
		t.Fatal(err)
	}
	block.Encrypt(encrypted, separate)
	body := binary.BigEndian.AppendUint64([]byte{1}, seconds)
	body = append(body, client[:]...)
	body = append(body, 0, 0)
	body = append(body, 1, 127, 0, 0, 1, 0, 53)
	body = append(body, []byte("answer")...)
	return peerCipher(t, c.uPSK, server[:]).Seal(encrypted, separate[4:], body, nil)
}
func newUDPForTest(t *testing.T) (*UdpConn, *memoryConn) {
	key := bytes.Repeat([]byte{1}, 16)
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-128-gcm"]
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	raw := new(memoryConn)
	c := NewUdpConn(raw, conf, block, block, [][]byte{key}, key)
	return c, raw
}
func TestClientUDPReplayWindowCommitsOnlyValidPackets(t *testing.T) {
	c, raw := newUDPForTest(t)
	server := [8]byte{3}
	now := uint64(time.Now().Unix())
	wrong := c.sessionID
	wrong[0] ^= 1
	cases := []struct {
		id      uint64
		session [8]byte
		seconds uint64
		valid   bool
	}{
		{0, c.sessionID, now, true}, {0, c.sessionID, now, false},
		{9000, wrong, now, false}, {1, c.sessionID, now, true},
		{9000, c.sessionID, now + 31, false}, {2, c.sessionID, now, true},
		{1025, c.sessionID, now, true}, {0, c.sessionID, now, false}, {1024, c.sessionID, now, true},
	}
	for _, tc := range cases {
		raw.packets = append(raw.packets, udpResponse(t, c, server, tc.id, tc.session, tc.seconds))
		tiny := make([]byte, 2)
		n, addr, err := c.ReadFrom(tiny)
		if tc.valid {
			if !errors.Is(err, io.ErrShortBuffer) || n != 2 || string(tiny) != "an" || addr.String() != "127.0.0.1:53" {
				t.Fatalf("valid packet=%d %v %v", n, addr, err)
			}
		} else if !errors.Is(err, protocol.ErrReplayAttack) {
			t.Fatalf("invalid packet accepted: %v", err)
		}
	}
}
func TestClientUDPServerRestartHistoryIsBounded(t *testing.T) {
	c, _ := newUDPForTest(t)
	now := time.Now()
	a, b, next := [8]byte{1}, [8]byte{2}, [8]byte{3}
	if !c.acceptServerPacket(a, 0, now, nil) || !c.acceptServerPacket(b, 0, now, nil) {
		t.Fatal("two server sessions rejected")
	}
	if c.acceptServerPacket(next, 0, now, nil) {
		t.Fatal("discarded a recent server session")
	}
	if !c.acceptServerPacket(next, 0, now.Add(time.Minute), nil) {
		t.Fatal("expired server session prevented restart")
	}
	var window serverSession
	if !window.accept(math.MaxUint64-1) || !window.accept(math.MaxUint64) || window.accept(math.MaxUint64) || window.accept(0) {
		t.Fatal("packet counter overflow broke replay window")
	}
}
func TestClientUDPWriteNeverReusesNonce(t *testing.T) {
	c, raw := newUDPForTest(t)
	if _, err := c.WriteTo(make([]byte, 65507), netproxy.NewAddr("udp", "127.0.0.1:53")); !errors.Is(err, io.ErrShortBuffer) || raw.writes != 0 || c.packetID != 0 {
		t.Fatalf("oversized datagram reached the carrier: %v", err)
	}
	raw.short = true
	addr := netproxy.NewAddr("udp", "127.0.0.1:53")
	if _, err := c.WriteTo([]byte("q"), addr); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	raw.short = false
	if _, err := c.WriteTo([]byte("q"), addr); err != nil {
		t.Fatal(err)
	}
	for i, packet := range raw.sent {
		var separate [16]byte
		c.blockCipherDecrypt.Decrypt(separate[:], packet[:16])
		if id := binary.BigEndian.Uint64(separate[8:]); id != uint64(i) {
			t.Fatalf("packet %d ID=%d", i, id)
		}
	}
	c.packetID = math.MaxUint64
	if _, err := c.WriteTo(nil, addr); err != nil {
		t.Fatal(err)
	}
	writes := raw.writes
	if _, err := c.WriteTo(nil, addr); err == nil || raw.writes != writes {
		t.Fatal("exhausted counter reused nonce")
	}
}

type pipeParent struct{ conn net.Conn }

func (p pipeParent) DialContext(context.Context, string, string) (net.Conn, error) {
	return p.conn, nil
}
func (p pipeParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unused")
}

func TestDialContextSendsRequestBeforeApplicationWrite(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	key := bytes.Repeat([]byte{7}, 16)
	done := make(chan error, 1)
	go func() {
		salt := make([]byte, 16)
		if _, err := io.ReadFull(server, salt); err != nil {
			done <- err
			return
		}
		aead := peerCipher(t, key, salt)
		encrypted := make([]byte, 11+16)
		if _, err := io.ReadFull(server, encrypted); err != nil {
			done <- err
			return
		}
		nonce := make([]byte, 12)
		fixed, err := aead.Open(nil, nonce, encrypted, nil)
		if err != nil {
			done <- err
			return
		}
		variable := make([]byte, int(binary.BigEndian.Uint16(fixed[9:]))+16)
		if _, err = io.ReadFull(server, variable); err != nil {
			done <- err
			return
		}
		nonce[0] = 1
		plain, err := aead.Open(nil, nonce, variable, nil)
		if err != nil {
			done <- err
			return
		}
		reader := bytes.NewReader(plain)
		addr, err := socks5.ReadAddrInfo(reader)
		if err != nil {
			done <- err
			return
		}
		var padding [2]byte
		_, err = io.ReadFull(reader, padding[:])
		if err == nil && ((addr.Hostname != "example.com" || addr.Port != 443) || binary.BigEndian.Uint16(padding[:]) == 0) {
			err = errors.New("empty request missing target or mandatory padding")
		}
		done <- err
	}()
	dialer, err := NewDialer(pipeParent{client}, protocol.Header{Cipher: "2022-blake3-aes-128-gcm", Password: base64.StdEncoding.EncodeToString(key), ProxyAddress: "proxy:443"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDialContextCancellationClosesIncompleteRequest(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	key := bytes.Repeat([]byte{7}, 16)
	dialer, err := NewDialer(pipeParent{client}, protocol.Header{Cipher: "2022-blake3-aes-128-gcm", Password: base64.StdEncoding.EncodeToString(key), ProxyAddress: "proxy:443"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if conn, err := dialer.DialContext(ctx, "tcp", "example.com:443"); conn != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled dial=%v %v", conn, err)
	}
	if _, err := client.Write([]byte("retry")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("partial request kept carrier open: %v", err)
	}
}

func TestClientTCPLargeRequestKeepsNonceSequence(t *testing.T) {
	key := bytes.Repeat([]byte{5}, 16)
	raw := new(memoryConn)
	c := newClientForTest(t, raw, key)
	payload := bytes.Repeat([]byte{0x5a}, 2*TCPChunkMaxLen+19)
	if n, err := c.Write(payload); n != len(payload) || err != nil {
		t.Fatalf("Write=%d %v", n, err)
	}
	wire := bytes.NewReader(raw.sent[0])
	salt := make([]byte, 16)
	io.ReadFull(wire, salt)
	aead := peerCipher(t, key, salt)
	nonce := make([]byte, 12)
	open := func(size int) []byte {
		t.Helper()
		ciphertext := make([]byte, size+aead.Overhead())
		if _, err := io.ReadFull(wire, ciphertext); err != nil {
			t.Fatal(err)
		}
		plain, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			t.Fatal(err)
		}
		for i := range nonce {
			nonce[i]++
			if nonce[i] != 0 {
				break
			}
		}
		return plain
	}
	fixed := open(11)
	initial := open(int(binary.BigEndian.Uint16(fixed[9:])))
	reader := bytes.NewReader(initial)
	if _, err := socks5.ReadAddrInfo(reader); err != nil {
		t.Fatal(err)
	}
	var pad [2]byte
	io.ReadFull(reader, pad[:])
	if padding := int(binary.BigEndian.Uint16(pad[:])); padding != 0 {
		t.Fatal("unexpected padding with application payload")
	}
	got := append([]byte(nil), initial[len(initial)-reader.Len():]...)
	for wire.Len() > 0 {
		length := open(2)
		got = append(got, open(int(binary.BigEndian.Uint16(length)))...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("large request changed chunk contents or nonce sequence")
	}
}

func TestClientTCPIdentityHeaderWire(t *testing.T) {
	key := bytes.Repeat([]byte{4}, 16)
	outer := bytes.Repeat([]byte{6}, 16)
	raw := new(memoryConn)
	c := newClientForTest(t, raw, key)
	c.pskList = [][]byte{outer, key}
	if _, err := c.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	derived := make([]byte, 16)
	blake3.DeriveKey(derived, "shadowsocks 2022 identity subkey", append(append([]byte(nil), outer...), c.requestSalt...))
	block, err := aes.NewCipher(derived)
	if err != nil {
		t.Fatal(err)
	}
	var actual [16]byte
	block.Decrypt(actual[:], raw.sent[0][16:32])
	expected := blake3.Sum512(key)
	if !bytes.Equal(actual[:], expected[:16]) {
		t.Fatal("identity header does not name the next PSK")
	}
}
