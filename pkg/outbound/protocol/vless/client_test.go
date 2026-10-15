package vless

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

type testConn struct {
	net.Conn
	input          *bytes.Reader
	output         bytes.Buffer
	closed, short  bool
	halves, writes int
}

func (c *testConn) Read(p []byte) (int, error) { return c.input.Read(p) }
func (c *testConn) Write(p []byte) (int, error) {
	c.writes++
	if c.short {
		return len(p) - 1, nil
	}
	return c.output.Write(p)
}
func (c *testConn) Close() error                { c.closed = true; return nil }
func (c *testConn) CloseWrite() error           { c.halves++; return nil }
func (c *testConn) SetDeadline(time.Time) error { return nil }

type testParent struct{ conn net.Conn }

func (p testParent) DialContext(context.Context, string, string) (net.Conn, error) {
	return p.conn, nil
}
func (testParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.ErrUnsupported
}
func clientDialer(t *testing.T, parent net.Conn, flow string) netproxy.Dialer {
	t.Helper()
	d, err := NewDialer(testParent{parent}, protocol.Header{Password: "01234567-89ab-cdef-0123-456789abcdef", Feature1: flow})
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func TestRequestHeaderServerFirstAndHalfClose(t *testing.T) {
	raw := &testConn{input: bytes.NewReader([]byte{0, 2, 9, 9, 'o', 'k'})}
	c, err := clientDialer(t, raw, "").DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	header := raw.output.Bytes()
	if len(header) != 34 || header[0] != 0 || header[17] != 0 || header[18] != 1 || !bytes.Equal(header[19:], append([]byte{1, 187, 2, 11}, []byte("example.com")...)) {
		t.Fatalf("request wire=%x", header)
	}
	if err := c.(netproxy.CloseWriter).CloseWrite(); err != nil || raw.halves != 1 {
		t.Fatalf("CloseWrite=%v", err)
	}
	reply, err := io.ReadAll(c)
	if err != nil || string(reply) != "ok" {
		t.Fatalf("server first reply=%q,%v", reply, err)
	}
}
func TestUDPTruncationConsumesOneDatagram(t *testing.T) {
	raw := &testConn{input: bytes.NewReader([]byte{0, 0, 0, 3, 'a', 'b', 'c', 0, 2, 'd', 'e'})}
	c, err := clientDialer(t, raw, "").(*Dialer).openPacket(context.Background(), "[2001:db8::1]:53")
	if err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 1)
	n, addr, err := c.ReadFrom(p)
	if n != 1 || !errors.Is(err, io.ErrShortBuffer) || addr.String() != "[2001:db8::1]:53" {
		t.Fatalf("first=%d,%v,%v", n, addr, err)
	}
	p = make([]byte, 20)
	n, _, err = c.ReadFrom(p)
	if err != nil || string(p[:n]) != "de" {
		t.Fatalf("next=%q,%v", p[:n], err)
	}
	before := raw.output.Len()
	if _, err := c.WriteTo([]byte("x"), netproxy.NewAddr("udp", "127.0.0.1:53")); err == nil || raw.output.Len() != before {
		t.Fatal("accepted different destination on bound UDP stream")
	}
}
func TestMalformedResponseAndShortWriteStayTerminal(t *testing.T) {
	raw := &testConn{input: bytes.NewReader([]byte{1, 0, 'x'})}
	c := &Conn{Conn: raw}
	_, err := c.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("accepted version1")
	}
	_, again := c.Read(make([]byte, 1))
	if err != again {
		t.Fatal("lost response failure")
	}
	raw.short = true
	if _, err := c.Write([]byte("payload")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	writes := raw.writes
	if _, err := c.Write([]byte("again")); !errors.Is(err, io.ErrShortWrite) || writes != raw.writes {
		t.Fatal("retried short write")
	}
}
func TestFailedVisionInitializationClosesCarrier(t *testing.T) {
	raw := &testConn{input: bytes.NewReader(nil)}
	conn, err := clientDialer(t, raw, XRV).DialContext(context.Background(), "tcp", "example.com:443")
	if conn != nil || err == nil || !raw.closed || raw.writes != 0 {
		t.Fatalf("failed Vision init leaked/sent request: %v,%v,%+v", conn, err, raw)
	}
}
func TestCancellationAndPartialResponseDeadline(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.AfterFunc(20*time.Millisecond, cancel)
	defer timer.Stop()
	if conn, err := clientDialer(t, local, "").DialContext(ctx, "tcp", "example.com:443"); conn != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Dial=%v,%v", conn, err)
	}
	local, peer2 := net.Pipe()
	defer local.Close()
	defer peer2.Close()
	c := &Conn{Conn: local}
	first := make(chan error, 1)
	go func() { _, err := peer2.Write([]byte{0}); first <- err }()
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, err := c.Read(make([]byte, 1))
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("partial header deadline=%v", err)
	}
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	go func() { _, _ = peer2.Write([]byte{0, 'x'}) }()
	p := make([]byte, 1)
	if n, err := c.Read(p); n != 1 || err != nil || p[0] != 'x' {
		t.Fatalf("header resume=%d,%q,%v", n, p, err)
	}
}
