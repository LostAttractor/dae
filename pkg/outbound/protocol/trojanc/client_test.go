package trojanc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

type testParent struct{ conn net.Conn }

func (p testParent) DialContext(context.Context, string, string) (net.Conn, error) {
	return p.conn, nil
}
func (p testParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	panic("unexpected UDP carrier")
}

func TestDialSendsHeaderBeforeApplicationWrite(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			d, _ := NewDialer(testParent{client}, protocol.Header{Password: "secret", ProxyAddress: "proxy:443"})
			done := make(chan error, 1)
			go func() {
				hash := sha256.Sum224([]byte("secret"))
				expected := []byte(hex.EncodeToString(hash[:]) + "\r\n")
				cmd := byte(1)
				if network == "udp" {
					cmd = 3
				}
				expected = append(expected, cmd, 3, 11)
				expected = append(expected, []byte("example.org")...)
				expected = append(expected, 0, 80, 13, 10)
				got := make([]byte, len(expected))
				_, err := io.ReadFull(server, got)
				if err == nil && !bytes.Equal(got, expected) {
					err = errors.New("incorrect request wire")
				}
				done <- err
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := d.DialContext(ctx, network, "example.org:80")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDialCancellationClosesIncompleteRequest(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	d, _ := NewDialer(testParent{client}, protocol.Header{Password: "secret", ProxyAddress: "proxy:443"})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "example.org:80")
	if conn != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("conn=%v error=%v", conn, err)
	}
	if _, err := server.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("carrier remained open: %v", err)
	}
}

type memoryConn struct {
	reader  io.Reader
	written bytes.Buffer
	short   bool
	writes  int
	closed  bool
}

func (c *memoryConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
func (c *memoryConn) Write(b []byte) (int, error) {
	c.writes++
	if c.short {
		return len(b) - 1, nil
	}
	return c.written.Write(b)
}
func (c *memoryConn) Close() error                   { c.closed = true; return nil }
func (*memoryConn) LocalAddr() net.Addr              { return netproxy.NewAddr("tcp", "local:1") }
func (*memoryConn) RemoteAddr() net.Addr             { return netproxy.NewAddr("tcp", "remote:1") }
func (*memoryConn) SetDeadline(time.Time) error      { return nil }
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }

type interruptedReader struct {
	prefix, suffix *bytes.Reader
	interrupted    bool
}

func (r *interruptedReader) Read(b []byte) (int, error) {
	if r.prefix.Len() > 0 {
		return r.prefix.Read(b)
	}
	if !r.interrupted {
		r.interrupted = true
		return 0, os.ErrDeadlineExceeded
	}
	return r.suffix.Read(b)
}

func udpFrame(payload []byte) []byte {
	b := []byte{3, 11}
	b = append(b, []byte("example.org")...)
	b = append(b, 0, 53, byte(len(payload)>>8), byte(len(payload)), 13, 10)
	return append(b, payload...)
}

func TestUDPHalfFrameDeadlineResumesAtEveryField(t *testing.T) {
	frame := udpFrame([]byte("response"))
	for cut := 1; cut < len(frame); cut++ {
		t.Run(strconv.Itoa(cut), func(t *testing.T) {
			carrier := &memoryConn{reader: &interruptedReader{prefix: bytes.NewReader(frame[:cut]), suffix: bytes.NewReader(append(bytes.Clone(frame[cut:]), udpFrame([]byte("next"))...))}}
			conn := &PacketConn{Conn: carrier}
			defer conn.Close()
			b := make([]byte, 128)
			if _, _, err := conn.ReadFrom(b); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("first read: %v", err)
			}
			_ = conn.SetReadDeadline(time.Time{})
			n, addr, err := conn.ReadFrom(b)
			if err != nil || string(b[:n]) != "response" || addr.String() != "example.org:53" {
				t.Fatalf("resume %q %v %v", b[:n], addr, err)
			}
			n, _, err = conn.ReadFrom(b)
			if err != nil || string(b[:n]) != "next" {
				t.Fatalf("next %q %v", b[:n], err)
			}
		})
	}
}

func TestUDPBoundsShortBufferAndWriteFailure(t *testing.T) {
	carrier := &memoryConn{reader: bytes.NewReader(append(udpFrame([]byte("reply")), udpFrame(nil)...))}
	conn := &PacketConn{Conn: carrier}
	b := make([]byte, 2)
	if n, _, err := conn.ReadFrom(b); n != 2 || string(b) != "re" || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short read %d %q %v", n, b, err)
	}
	if n, _, err := conn.ReadFrom(b); n != 0 || err != nil {
		t.Fatalf("empty next %d %v", n, err)
	}
	addr := netproxy.NewAddr("udp", "example.org:53")
	if _, err := conn.WriteTo(make([]byte, 65536), addr); err == nil || carrier.writes != 0 {
		t.Fatal("oversized payload written")
	}
	if n, err := conn.WriteTo(make([]byte, 65535), addr); n != 65535 || err != nil {
		t.Fatalf("maximum payload %d %v", n, err)
	}
	carrier.short = true
	if _, err := conn.WriteTo([]byte("x"), addr); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	calls := carrier.writes
	carrier.short = false
	if _, err := conn.WriteTo([]byte("x"), addr); !errors.Is(err, io.ErrShortWrite) || carrier.writes != calls {
		t.Fatal("partial frame replayed")
	}
	if err := conn.Close(); err != nil || conn.readBuf != nil {
		t.Fatal("buffer retained at close")
	}
}

func TestInitialShortWriteIsSticky(t *testing.T) {
	carrier := &memoryConn{reader: bytes.NewReader(nil), short: true}
	addr, _ := socks5.AddressFromString("example.org:80")
	conn := newConn(carrier, addr, commandConnect, "secret")
	if _, err := conn.Write(nil); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	carrier.short = false
	if _, err := conn.Write(nil); !errors.Is(err, io.ErrShortWrite) || carrier.writes != 1 {
		t.Fatal("header replayed after partial write")
	}
}

func TestUDPCloseUnblocksReadAndWrite(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	conn := &PacketConn{Conn: client}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _, _ = conn.ReadFrom(make([]byte, 16)) }()
	go func() {
		defer wg.Done()
		_, _ = conn.WriteTo([]byte("payload"), netproxy.NewAddr("udp", "example.org:53"))
	}()
	closed := make(chan struct{})
	go func() { _ = conn.Close(); wg.Wait(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("close waited for blocked read/write")
	}
	if conn.readBuf != nil {
		t.Fatal("receive buffer retained")
	}
}

func TestUDPTruncatedFrameIsNotCleanEOF(t *testing.T) {
	frame := udpFrame([]byte("response"))
	for cut := 0; cut < len(frame); cut++ {
		t.Run(strconv.Itoa(cut), func(t *testing.T) {
			conn := &PacketConn{Conn: &memoryConn{reader: bytes.NewReader(frame[:cut])}}
			defer conn.Close()
			_, _, err := conn.ReadFrom(make([]byte, 32))
			want := io.ErrUnexpectedEOF
			if cut == 0 {
				want = io.EOF
			}
			if !errors.Is(err, want) {
				t.Fatalf("cut %d: %v", cut, err)
			}
			if cut > 0 && netproxy.ClassifyFailure(err).Scope != netproxy.ScopeStream {
				t.Fatalf("unscoped incomplete frame: %v", err)
			}
		})
	}
}

type finalEOFReader struct{ *bytes.Reader }

func (r finalEOFReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	if r.Len() == 0 {
		err = io.EOF
	}
	return n, err
}
func TestUDPCompleteFrameBeforeEOF(t *testing.T) {
	conn := &PacketConn{Conn: &memoryConn{reader: finalEOFReader{bytes.NewReader(udpFrame([]byte("last")))}}}
	defer conn.Close()
	b := make([]byte, 16)
	if n, _, err := conn.ReadFrom(b); n != 4 || string(b[:n]) != "last" || err != nil {
		t.Fatalf("last frame %q %v", b[:n], err)
	}
	if _, _, err := conn.ReadFrom(b); err != io.EOF {
		t.Fatalf("next EOF: %v", err)
	}
}
