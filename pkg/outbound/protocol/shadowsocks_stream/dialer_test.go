package shadowsocks_stream

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

type memoryConn struct {
	net.Conn
	input          *bytes.Reader
	output         bytes.Buffer
	short          bool
	writes, halves int
}

func (c *memoryConn) Read(p []byte) (int, error) { return c.input.Read(p) }
func (c *memoryConn) Write(p []byte) (int, error) {
	c.writes++
	if c.short {
		return len(p) - 1, nil
	}
	return c.output.Write(p)
}
func (c *memoryConn) CloseWrite() error { c.halves++; return nil }
func (c *memoryConn) Close() error      { return nil }
func cipherForTest(t *testing.T) *ciphers.StreamCipher {
	t.Helper()
	c, err := ciphers.NewStreamCipher("aes-128-cfb", "secret")
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestTCPWirePreservesCallerBufferAndHalfClose(t *testing.T) {
	raw := &memoryConn{input: bytes.NewReader(nil)}
	conn := NewTCPConn(raw, cipherForTest(t))
	payload := bytes.Repeat([]byte("payload"), 10000)
	original := bytes.Clone(payload)
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write=%d,%v", n, err)
	}
	if !bytes.Equal(payload, original) {
		t.Fatal("Write mutated caller bytes")
	}
	wire := raw.output.Bytes()
	dec := cipherForTest(t)
	if err := dec.InitDecrypt(wire[:16]); err != nil {
		t.Fatal(err)
	}
	plain := bytes.Clone(wire[16:])
	dec.Decrypt(plain, plain)
	if !bytes.Equal(plain, payload) {
		t.Fatal("stream IV/framing corrupted")
	}
	if err := conn.CloseWrite(); err != nil || raw.halves != 1 {
		t.Fatalf("half-close=%v count=%d", err, raw.halves)
	}
	if _, err := conn.Write(payload); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after half-close=%v", err)
	}
	serverCipher := cipherForTest(t)
	iv, err := serverCipher.InitEncrypt()
	if err != nil {
		t.Fatal(err)
	}
	reply := append(bytes.Clone(iv), []byte("reply")...)
	serverCipher.Encrypt(reply[16:], reply[16:])
	raw.input = bytes.NewReader(reply)
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "reply" {
		t.Fatalf("reverse after half-close=%q,%v", got, err)
	}
}
func TestTCPShortWriteIsTerminal(t *testing.T) {
	raw := &memoryConn{input: bytes.NewReader(nil), short: true}
	conn := NewTCPConn(raw, cipherForTest(t))
	if _, err := conn.Write([]byte("hello")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("again")); !errors.Is(err, io.ErrShortWrite) || raw.writes != 1 {
		t.Fatalf("retried consumed keystream: %v,%d", err, raw.writes)
	}
}
func TestUDPPacketsAndTruncation(t *testing.T) {
	raw := &memoryConn{input: bytes.NewReader(nil)}
	conn := &packetConn{UdpConn: NewUDPConn(raw, cipherForTest(t))}
	addr := netproxy.NewAddr("udp", "[2001:db8::1]:53")
	if n, err := conn.WriteTo([]byte("first"), addr); err != nil || n != 5 {
		t.Fatalf("WriteTo=%d,%v", n, err)
	}
	first := bytes.Clone(raw.output.Bytes())
	raw.input = bytes.NewReader(first)
	got := make([]byte, 2)
	n, from, err := conn.ReadFrom(got)
	if n != 2 || !errors.Is(err, io.ErrShortBuffer) || from.String() != addr.String() {
		t.Fatalf("truncated packet=%d,%v,%v", n, from, err)
	}
	raw.input = bytes.NewReader(first)
	got = make([]byte, 20)
	n, from, err = conn.ReadFrom(got)
	if err != nil || n != 5 || string(got[:n]) != "first" || from.String() != addr.String() {
		t.Fatalf("packet=%d,%v,%v", n, from, err)
	}
}

type oneConnDialer struct {
	conn  net.Conn
	calls atomic.Int32
}

func (d *oneConnDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.calls.Add(1)
	return d.conn, nil
}
func (*oneConnDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.ErrUnsupported
}
func TestDialCancellationClosesUnfinishedHeader(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	dialer, err := NewDialer(&oneConnDialer{conn: local}, protocol.Header{Cipher: "aes-128-cfb", Password: "secret", ProxyAddress: "proxy:1"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.AfterFunc(20*time.Millisecond, cancel)
	defer timer.Stop()
	conn, err := dialer.DialContext(ctx, "tcp", "example.com:443")
	if conn != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial=%v,%v", conn, err)
	}
	if _, err := local.Write([]byte("after cancel")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("leaked parent: %v", err)
	}
}
