package shadowsocks_stream

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

type memoryConn struct {
	net.Conn
	input          *bytes.Reader
	output         bytes.Buffer
	short          bool
	writes, halves int
	trace          string // carrier calls in order: Read, Write, CloseWrite, Close
	lease          *netproxy.Lease
}

func (c *memoryConn) Read(p []byte) (int, error) { c.trace += "r"; return c.input.Read(p) }
func (c *memoryConn) Write(p []byte) (int, error) {
	c.trace += "w"
	c.writes++
	if c.short {
		return len(p) - 1, nil
	}
	return c.output.Write(p)
}
func (c *memoryConn) CloseWrite() error                { c.trace += "h"; c.halves++; return nil }
func (c *memoryConn) Close() error                     { c.trace += "c"; return nil }
func (c *memoryConn) DependencyLease() *netproxy.Lease { return c.lease }
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
func TestDialClosesParentAfterCancellation(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	dialer, err := NewDialer(&oneConnDialer{conn: local}, protocol.Header{Cipher: "aes-128-cfb", Password: "secret", ProxyAddress: "proxy:1"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	conn, err := dialer.DialContext(ctx, "tcp", "example.com:443")
	if conn != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial=%v,%v", conn, err)
	}
	if _, err := local.Write([]byte("after cancel")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("leaked parent: %v", err)
	}
}

// dialTCP returns a client conn over raw and checks the dial wrote nothing.
func dialTCP(t *testing.T, raw *memoryConn) net.Conn {
	t.Helper()
	dialer, err := NewDialer(&oneConnDialer{conn: raw}, protocol.Header{Cipher: "aes-128-cfb", Password: "secret", ProxyAddress: "proxy:1"})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.DialContext(t.Context(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if raw.writes != 0 {
		t.Fatalf("dial wrote %d times", raw.writes)
	}
	return conn
}

// serverRequest decodes the client stream as a server does: IV, target, payload.
func serverRequest(t *testing.T, wire []byte) (string, []byte) {
	t.Helper()
	dec := cipherForTest(t)
	if err := dec.InitDecrypt(wire[:16]); err != nil {
		t.Fatal(err)
	}
	plain := bytes.Clone(wire[16:])
	dec.Decrypt(plain, plain)
	r := bytes.NewReader(plain)
	target, err := socks5.ReadAddr(r)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := io.ReadAll(r)
	return target.String(), payload
}

func TestFirstWriteCarriesHeader(t *testing.T) {
	raw := &memoryConn{input: bytes.NewReader(nil)}
	conn := dialTCP(t, raw)
	if n, err := conn.Write([]byte("hello")); err != nil || n != 5 {
		t.Fatalf("Write=%d,%v", n, err)
	}
	if raw.writes != 1 {
		t.Fatalf("first Write used %d carrier writes", raw.writes)
	}
	if target, payload := serverRequest(t, raw.output.Bytes()); target != "example.com:443" || string(payload) != "hello" {
		t.Fatalf("request=%s,%q", target, payload)
	}
}

func TestReadBeforeWriteSendsHeader(t *testing.T) {
	server := cipherForTest(t)
	iv, err := server.InitEncrypt()
	if err != nil {
		t.Fatal(err)
	}
	reply := append(bytes.Clone(iv), "banner"...)
	server.Encrypt(reply[16:], reply[16:])
	raw := &memoryConn{input: bytes.NewReader(reply)}
	conn := dialTCP(t, raw)
	got := make([]byte, 6)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "banner" {
		t.Fatalf("Read=%q,%v", got, err)
	}
	if target, payload := serverRequest(t, raw.output.Bytes()); raw.writes != 1 || !strings.HasPrefix(raw.trace, "wr") || target != "example.com:443" || len(payload) != 0 {
		t.Fatalf("request=%s,%s,%q", raw.trace, target, payload)
	}
}

func TestCloseWriteBeforeWriteSendsHeader(t *testing.T) {
	raw := &memoryConn{input: bytes.NewReader(nil)}
	conn := dialTCP(t, raw)
	if err := conn.(netproxy.CloseWriter).CloseWrite(); err != nil || raw.trace != "wh" {
		t.Fatalf("CloseWrite=%v trace=%s", err, raw.trace)
	}
	if target, payload := serverRequest(t, raw.output.Bytes()); target != "example.com:443" || len(payload) != 0 {
		t.Fatalf("request=%s,%q", target, payload)
	}
}

func TestDialRejectsInvalidDependency(t *testing.T) {
	cause := errors.New("parent gone")
	raw := &memoryConn{input: bytes.NewReader(nil), lease: netproxy.NewLease(netproxy.NewResourceRef())}
	raw.lease.Invalidate(cause)
	dialer, err := NewDialer(&oneConnDialer{conn: raw}, protocol.Header{Cipher: "aes-128-cfb", Password: "secret", ProxyAddress: "proxy:1"})
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := dialer.DialContext(t.Context(), "tcp", "example.com:443"); conn != nil || !errors.Is(err, cause) || raw.trace != "c" {
		t.Fatalf("Dial=%v,%v trace=%s", conn, err, raw.trace)
	}
}

// A peer may reply after the first chunk before reading more, so a concurrent
// Read must wait for the header's carrier write only.
func TestReadDuringFirstWriteWaitsForHeaderOnly(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	dialer, err := NewDialer(&oneConnDialer{conn: local}, protocol.Header{Cipher: "aes-128-cfb", Password: "secret", ProxyAddress: "proxy:1"})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.DialContext(t.Context(), "tcp", "1.2.3.4:80")
	if err != nil {
		t.Fatal(err)
	}
	go conn.Write(make([]byte, 64<<10))
	first := make([]byte, 16+7+32<<10) // IV, IPv4 address header, first chunk
	if _, err := io.ReadFull(peer, first[:1]); err != nil {
		t.Fatal(err)
	}
	// The first Write now holds the write lock inside its first carrier write.
	read := make(chan string, 1)
	go func() {
		got := make([]byte, 2)
		_, _ = io.ReadFull(conn, got)
		read <- string(got)
	}()
	if _, err := io.ReadFull(peer, first[1:]); err != nil {
		t.Fatal(err)
	}
	server := cipherForTest(t)
	iv, err := server.InitEncrypt()
	if err != nil {
		t.Fatal(err)
	}
	reply := append(bytes.Clone(iv), "ok"...)
	server.Encrypt(reply[16:], reply[16:])
	_ = peer.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := peer.Write(reply); err != nil {
		t.Fatalf("Read waited for the rest of the first Write: %v", err)
	}
	if got := <-read; got != "ok" {
		t.Fatalf("Read=%q", got)
	}
}

func TestFailedHeaderIsSticky(t *testing.T) {
	raw := &memoryConn{input: bytes.NewReader(nil), short: true}
	conn := dialTCP(t, raw)
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Read=%v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("second Read=%v", err)
	}
	if _, err := conn.Write([]byte("x")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Write=%v", err)
	}
	if err := conn.(netproxy.CloseWriter).CloseWrite(); !errors.Is(err, io.ErrShortWrite) || raw.writes != 1 || raw.halves != 0 {
		t.Fatalf("CloseWrite=%v writes=%d halves=%d", err, raw.writes, raw.halves)
	}
}
