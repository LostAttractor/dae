package vless

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"sync/atomic"
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

const testUUID = "01234567-89ab-cdef-0123-456789abcdef"

func clientDialer(t *testing.T, parent net.Conn, flow string) netproxy.Dialer {
	t.Helper()
	d, err := NewDialer(testParent{parent}, protocol.Header{Password: testUUID, Feature1: flow})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// request is the VLESS request header for addons, command and target.
func request(addons []byte, command byte, target ...byte) []byte {
	key, _ := Password2Key(testUUID)
	header := append([]byte{0}, key...)
	header = append(append(header, byte(len(addons))), addons...)
	return append(append(header, command), target...)
}

var exampleTarget = append([]byte{1, 187, 2, 11}, "example.com"...)

func dialExample(t *testing.T, raw *testConn) net.Conn {
	t.Helper()
	c, err := clientDialer(t, raw, "").DialContext(t.Context(), "tcp", "example.com:443")
	if err != nil || raw.writes != 0 {
		t.Fatalf("Dial=%v, carrier writes=%d", err, raw.writes)
	}
	return c
}
func TestFirstWriteCarriesRequestHeader(t *testing.T) {
	raw := &testConn{input: bytes.NewReader(nil)}
	c := dialExample(t, raw)
	if n, err := c.Write([]byte("hello")); n != 5 || err != nil {
		t.Fatalf("Write=%d,%v", n, err)
	}
	if n, err := c.Write([]byte("!")); n != 1 || err != nil {
		t.Fatalf("Write=%d,%v", n, err)
	}
	want := append(request(nil, 1, exampleTarget...), "hello!"...)
	if raw.writes != 2 || !bytes.Equal(raw.output.Bytes(), want) {
		t.Fatalf("carrier writes=%d wire=%x", raw.writes, raw.output.Bytes())
	}
}
func TestReadFirstSendsRequestHeaderAlone(t *testing.T) {
	raw := &testConn{input: bytes.NewReader([]byte{0, 2, 9, 9, 'o', 'k'})}
	c := dialExample(t, raw)
	p := make([]byte, 2)
	if n, err := c.Read(p); n != 2 || err != nil || string(p) != "ok" {
		t.Fatalf("Read=%q,%v", p[:n], err)
	}
	if raw.writes != 1 || !bytes.Equal(raw.output.Bytes(), request(nil, 1, exampleTarget...)) {
		t.Fatalf("carrier writes=%d wire=%x", raw.writes, raw.output.Bytes())
	}
}
func TestCloseWriteFirstSendsRequestHeaderAlone(t *testing.T) {
	raw := &testConn{input: bytes.NewReader([]byte{0, 0, 'o', 'k'})}
	c := dialExample(t, raw)
	if err := c.(netproxy.CloseWriter).CloseWrite(); err != nil || raw.halves != 1 {
		t.Fatalf("CloseWrite=%v", err)
	}
	if raw.writes != 1 || !bytes.Equal(raw.output.Bytes(), request(nil, 1, exampleTarget...)) {
		t.Fatalf("carrier writes=%d wire=%x", raw.writes, raw.output.Bytes())
	}
	reply, err := io.ReadAll(c)
	if err != nil || string(reply) != "ok" {
		t.Fatalf("server first reply=%q,%v", reply, err)
	}
}
func TestFailedRequestHeaderIsSticky(t *testing.T) {
	raw := &testConn{input: bytes.NewReader([]byte{0, 0, 'o', 'k'}), short: true}
	c := dialExample(t, raw)
	if n, err := c.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Read=%d,%v", n, err)
	}
	if n, err := c.Write([]byte("x")); n != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Write=%d,%v", n, err)
	}
	if err := c.(netproxy.CloseWriter).CloseWrite(); !errors.Is(err, io.ErrShortWrite) || raw.writes != 1 || raw.halves != 0 {
		t.Fatalf("CloseWrite=%v, carrier writes=%d halves=%d", err, raw.writes, raw.halves)
	}
}

// A peer may reply after part of the first Write and read on only once the
// client has read that reply.
func TestReadDoesNotWaitForBlockedFirstWrite(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	c, err := clientDialer(t, local, "").DialContext(t.Context(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go c.Write(make([]byte, 64<<10))
	got := make([]byte, 1<<10)
	if _, err := io.ReadFull(peer, got); err != nil || !bytes.HasPrefix(got, request(nil, 1, exampleTarget...)) {
		t.Fatalf("peer read %x, %v", got, err)
	}
	read := make(chan string, 1)
	go func() {
		reply := make([]byte, 2)
		n, _ := io.ReadFull(c, reply)
		read <- string(reply[:n])
	}()
	_ = peer.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := peer.Write([]byte{0, 0, 'o', 'k'}); err != nil {
		t.Fatalf("Read waited for the first Write: %v", err)
	}
	if got := <-read; got != "ok" {
		t.Fatalf("reply=%q", got)
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
	if _, err := c.WriteTo([]byte("x"), netproxy.NewAddr("udp", "127.0.0.1:53")); err == nil {
		t.Fatal("accepted different destination on bound UDP stream")
	}
	if raw.writes != 0 {
		t.Fatalf("reads or a rejected datagram sent %d writes", raw.writes)
	}
	if _, err := c.WriteTo([]byte("x"), addr); err != nil {
		t.Fatal(err)
	}
	target := append([]byte{0, 53, 3}, netip.MustParseAddr("2001:db8::1").AsSlice()...)
	target = append(target, 0, 1, 'x')
	if want := request(nil, 2, target...); raw.writes != 1 || !bytes.Equal(raw.output.Bytes(), want) {
		t.Fatalf("carrier writes=%d wire=%x", raw.writes, raw.output.Bytes())
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
	raw := &testConn{input: bytes.NewReader(nil)}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if conn, err := clientDialer(t, raw, "").DialContext(ctx, "tcp", "example.com:443"); conn != nil || !errors.Is(err, context.Canceled) || !raw.closed {
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

type tlsCarrier struct {
	*gotls.Conn
	writes atomic.Int32
	fail   error
	hold   chan struct{} // blocks writes until closed
}

func (c *tlsCarrier) TLSConn() net.Conn { return c.Conn }
func (c *tlsCarrier) Write(p []byte) (int, error) {
	c.writes.Add(1)
	if c.fail != nil {
		return 0, c.fail
	}
	if c.hold != nil {
		<-c.hold
	}
	return c.Conn.Write(p)
}
func tlsPair(t *testing.T) (*tlsCarrier, *gotls.Conn) {
	t.Helper()
	seed := httptest.NewTLSServer(nil)
	cert := seed.TLS.Certificates[0]
	seed.Close()
	listener, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{Certificates: []gotls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *gotls.Conn, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		server := c.(*gotls.Conn)
		_ = server.Handshake()
		accepted <- server
	}()
	client, err := gotls.Dial("tcp", listener.Addr().String(), &gotls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	return &tlsCarrier{Conn: client}, server
}

func dialVision(t *testing.T, carrier *tlsCarrier) net.Conn {
	t.Helper()
	c, err := clientDialer(t, carrier, XRV).DialContext(t.Context(), "tcp", "example.com:443")
	if err != nil || carrier.writes.Load() != 0 {
		t.Fatalf("Dial=%v, carrier writes=%d", err, carrier.writes.Load())
	}
	return c
}

// visionRequest reads the VLESS request header for command and target plus the
// first Vision record, and returns the record command and content.
func visionRequest(t *testing.T, server net.Conn, command byte, target ...byte) (byte, []byte) {
	t.Helper()
	key, _ := Password2Key(testUUID)
	want := append(request(append([]byte{10, byte(len(XRV))}, XRV...), command, target...), key...)
	got := make([]byte, len(want)+5)
	if _, err := io.ReadFull(server, got); err != nil || !bytes.Equal(got[:len(want)], want) {
		t.Fatalf("request=%x,%v", got, err)
	}
	record := got[len(want):] // command, content length, padding length
	size := int(binary.BigEndian.Uint16(record[1:]))
	content := make([]byte, size+int(binary.BigEndian.Uint16(record[3:])))
	if _, err := io.ReadFull(server, content); err != nil {
		t.Fatal(err)
	}
	return record[0], content[:size]
}

// Like Xray, the request header and the first Vision record share one TLS
// write, also when the client reads first and the record carries no payload.
func TestVisionCoalescesRequestHeaderWithFirstRecord(t *testing.T) {
	for _, payload := range []string{"hello", ""} {
		carrier, server := tlsPair(t)
		c := dialVision(t, carrier)
		reply := make(chan string, 1)
		if payload != "" {
			if _, err := c.Write([]byte(payload)); err != nil {
				t.Fatal(err)
			}
		} else {
			go func() {
				p := make([]byte, 2)
				n, _ := c.Read(p)
				reply <- string(p[:n])
			}()
		}
		if command, content := visionRequest(t, server, 1, exampleTarget...); command != 0 || string(content) != payload || carrier.writes.Load() != 1 {
			t.Fatalf("first record=%d,%q, carrier writes=%d", command, content, carrier.writes.Load())
		}
		if payload == "" {
			key, _ := Password2Key(testUUID)
			if _, err := server.Write(append(append([]byte{0, 0}, key...), 1, 0, 2, 0, 0, 'o', 'k')); err != nil {
				t.Fatal(err)
			}
			if got := <-reply; got != "ok" {
				t.Fatalf("reply=%q", got)
			}
		}
	}
}
func TestVisionReadDoesNotWaitForBlockedFirstWrite(t *testing.T) {
	carrier, server := tlsPair(t)
	carrier.hold = make(chan struct{})
	defer close(carrier.hold)
	c := dialVision(t, carrier)
	go c.Write([]byte("hello"))
	for deadline := time.Now().Add(2 * time.Second); carrier.writes.Load() == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("first record not written")
		}
	}
	key, _ := Password2Key(testUUID)
	if _, err := server.Write(append(append([]byte{0, 0}, key...), 1, 0, 2, 0, 0, 'o', 'k')); err != nil {
		t.Fatal(err)
	}
	read := make(chan string, 1)
	go func() {
		p := make([]byte, 2)
		n, _ := io.ReadFull(c, p)
		read <- string(p[:n])
	}()
	select {
	case got := <-read:
		if got != "ok" {
			t.Fatalf("reply=%q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read waited for the first Write")
	}
}
func TestVisionCloseWriteFirstCoalescesPaddingEnd(t *testing.T) {
	carrier, server := tlsPair(t)
	c := dialVision(t, carrier)
	if err := c.(netproxy.CloseWriter).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if command, content := visionRequest(t, server, 1, exampleTarget...); command != 1 || len(content) != 0 || carrier.writes.Load() != 1 {
		t.Fatalf("first record=%d,%x, carrier writes=%d", command, content, carrier.writes.Load())
	}
	if rest, err := io.ReadAll(server); err != nil || len(rest) != 0 {
		t.Fatalf("after half-close=%x,%v", rest, err)
	}
}

// An XUDP read waits for replies to the first datagram, which carries the
// request header and the first record.
func TestVisionPacketCoalescesRequestHeaderWithFirstDatagram(t *testing.T) {
	carrier, server := tlsPair(t)
	target := netproxy.NewAddr("udp", "127.0.0.1:53")
	c, err := clientDialer(t, carrier, XRV).ListenPacket(t.Context(), target.String())
	if err != nil || carrier.writes.Load() != 0 {
		t.Fatalf("ListenPacket=%v, carrier writes=%d", err, carrier.writes.Load())
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, _, err := c.ReadFrom(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) || carrier.writes.Load() != 0 {
		t.Fatalf("ReadFrom=%v, carrier writes=%d", err, carrier.writes.Load())
	}
	if _, err := c.WriteTo([]byte("x"), target); err != nil {
		t.Fatal(err)
	}
	xudp := []byte{0, 12, 0, 0, 1, 1, 2, 0, 53, 1, 127, 0, 0, 1, 0, 1, 'x'} // new session to 127.0.0.1:53
	if command, content := visionRequest(t, server, 3); command != 0 || !bytes.Equal(content, xudp) || carrier.writes.Load() != 1 {
		t.Fatalf("first record=%d,%x, carrier writes=%d", command, content, carrier.writes.Load())
	}
}
func TestVisionFailedRequestHeaderIsSticky(t *testing.T) {
	carrier, _ := tlsPair(t)
	carrier.fail = errors.New("carrier failed")
	c := dialVision(t, carrier)
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, carrier.fail) {
		t.Fatalf("Read=%v", err)
	}
	if _, err := c.Write([]byte("x")); !errors.Is(err, carrier.fail) {
		t.Fatalf("Write=%v", err)
	}
	if err := c.(netproxy.CloseWriter).CloseWrite(); !errors.Is(err, carrier.fail) || carrier.writes.Load() != 1 {
		t.Fatalf("CloseWrite=%v, carrier writes=%d", err, carrier.writes.Load())
	}
}
