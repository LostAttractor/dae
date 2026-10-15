package ws

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestMessageStreamAndClose(t *testing.T) {
	peerDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(peerDone)
		if r.Host != "front.example" {
			t.Errorf("WebSocket Host = %q", r.Host)
		}
		peer, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer peer.Close()
		for _, data := range []string{"", "abc", "defgh"} {
			if err := peer.WriteMessage(websocket.BinaryMessage, []byte(data)); err != nil {
				return
			}
		}
		_, data, err := peer.ReadMessage()
		if err != nil || string(data) != "request" {
			return
		}
		_ = peer.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
		_, _, _ = peer.ReadMessage()
	}))
	defer server.Close()

	ws := &Ws{ParentDialer: wsTestDialer{}, wsAddr: "ws" + strings.TrimPrefix(server.URL, "http"), host: "front.example"}
	raw, err := ws.DialContext(context.Background(), "tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	c := raw.(*conn)
	defer c.Close()
	if _, err := c.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 8)
	for i := range got {
		if _, err := io.ReadFull(c, got[i:i+1]); err != nil {
			t.Fatal(err)
		}
	}
	if string(got) != "abcdefgh" {
		t.Fatalf("message boundaries: %q", got)
	}
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("normal close %v", err)
	}
	<-peerDone
	_ = c.Close()
	if n, err := c.Write([]byte("failed")); n != 0 || err == nil {
		t.Fatalf("failed write n=%d err=%v", n, err)
	}
	if _, err2 := c.Write([]byte("again")); !errors.Is(err2, net.ErrClosed) {
		t.Fatalf("write after local Close %v", err2)
	}
}

type wsTestDialer struct{}

func (wsTestDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return new(net.Dialer).DialContext(ctx, network, address)
}
func (wsTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected packet")
}

func TestGorillaPeerFragmentationControlAndLargeFrames(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789abcdef"), 8192)
	received := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, err := (&websocket.Upgrader{WriteBufferSize: 128}).Upgrade(w, r, nil)
		if err != nil {
			received <- err
			return
		}
		defer peer.Close()
		// Gorilla emits continuation frames after the small write buffer fills.
		writer, err := peer.NextWriter(websocket.BinaryMessage)
		if err != nil {
			received <- err
			return
		}
		if _, err = writer.Write(payload[:8192]); err == nil {
			err = peer.WriteControl(websocket.PingMessage, []byte("alive"), time.Now().Add(time.Second))
		}
		if err == nil {
			_, err = writer.Write(payload[8192:])
		}
		if err == nil {
			err = writer.Close()
		}
		if err == nil {
			err = peer.WriteMessage(websocket.BinaryMessage, payload)
		}
		if err != nil {
			received <- err
			return
		}
		pong := false
		peer.SetPongHandler(func(data string) error { pong = data == "alive"; return nil })
		_, actual, err := peer.ReadMessage()
		if err == nil && (!pong || !bytes.Equal(actual, payload)) {
			err = errors.New("missing pong or invalid masked fragmented payload")
		}
		received <- err
	}))
	defer server.Close()
	ws := &Ws{ParentDialer: wsTestDialer{}, wsAddr: "ws" + strings.TrimPrefix(server.URL, "http")}
	c, err := ws.DialContext(context.Background(), "tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, ok := c.(netproxy.CloseWriter); ok {
		t.Fatal("WebSocket advertised half-close")
	}
	actual := make([]byte, len(payload))
	if _, err := io.ReadFull(c, actual); err != nil || !bytes.Equal(actual, payload) {
		t.Fatalf("fragmented read %v", err)
	}
	if _, err := io.ReadFull(c, actual); err != nil || !bytes.Equal(actual, payload) {
		t.Fatalf("Gorilla 64-bit frame %v", err)
	}
	if n, err := c.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("masked write %d %v", n, err)
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
}

func TestServerFrameLengthsAndValidation(t *testing.T) {
	cases := []struct {
		name string
		wire []byte
		want string
	}{
		{"rsv", []byte{0xc2, 0}, "reserved"}, {"mask", []byte{0x82, 0x80}, "masked"},
		{"fragmented_control", []byte{0x09, 0}, "control"}, {"long_control", []byte{0x89, 126, 0, 126}, "control"},
		{"unexpected_continuation", []byte{0x80, 0}, "continuation"}, {"nonminimal", []byte{0x82, 126, 0, 1}, "minimal"},
		{"truncated_header", []byte{0x82, 127, 0}, "unexpected EOF"}, {"invalid_close", []byte{0x88, 1, 0}, "close"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			c := newConn(nil, bufio.NewReader(bytes.NewReader(test.wire)), nil)
			_, err := c.Read(make([]byte, 1))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid frame error=%v", err)
			}
			failure := netproxy.ClassifyFailure(err)
			if failure.Layer != netproxy.LayerProxy || failure.Scope != netproxy.ScopeStream || failure.Origin != netproxy.OriginPeer || failure.Reason != netproxy.ReasonProtocol {
				t.Fatalf("untyped malformed peer frame: %+v", failure)
			}
		})
	}
	// RFC 6455 uses an eight-byte network-order length above 65535 bytes.
	data := bytes.Repeat([]byte("a"), 70000)
	wire := []byte{0x82, 127, 0, 0, 0, 0, 0, 1, 0x11, 0x70}
	wire = append(wire, data...)
	c := newConn(nil, bufio.NewReader(bytes.NewReader(wire)), nil)
	actual := make([]byte, len(data))
	if _, err := io.ReadFull(c, actual); err != nil || !bytes.Equal(actual, data) {
		t.Fatalf("64-bit frame %v", err)
	}
}

type shortWriteCarrier struct {
	net.Conn
	calls int
}

func (c *shortWriteCarrier) Write(p []byte) (int, error) { c.calls++; return len(p) - 1, nil }
func TestShortFrameWriteIsSticky(t *testing.T) {
	raw := &shortWriteCarrier{}
	c := newConn(raw, nil, nil)
	for range 2 {
		if n, err := c.Write([]byte("owned payload")); n != 0 || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short write %d %v", n, err)
		}
	}
	if raw.calls != 1 {
		t.Fatal("continued a partially written frame")
	}
}
func TestWriteDeadlineInterruptsCarrierWithoutRace(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	c := newConn(client, nil, nil)
	defer c.Close()
	result := make(chan error, 1)
	go func() { _, err := c.Write(bytes.Repeat([]byte("x"), 1<<16)); result <- err }()
	for range 20 {
		_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	}
	_ = c.SetWriteDeadline(time.Now())
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not interrupt frame write")
	}
}
func TestCancelDuringUpgradeClosesCarrier(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	started := make(chan struct{})
	parent := wsPipeDialer{conn: client, started: started}
	ws := &Ws{ParentDialer: parent, wsAddr: "ws://peer.test/"}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := ws.DialContext(ctx, "tcp", ""); result <- err }()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("upgrade cancellation blocked")
	}
	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Fatal("upgrade left socket open")
	}
}

type wsPipeDialer struct {
	conn    net.Conn
	started chan struct{}
}

func (p wsPipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	close(p.started)
	return p.conn, nil
}
func (p wsPipeDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected packet")
}

func TestReadDeadlineRetainsPartialFrameHeader(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	c := newConn(client, bufio.NewReader(client), nil)
	defer c.Close()
	continuation := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = server.Write([]byte{0x82, 126, 0})
		<-continuation
		_, _ = server.Write(append([]byte{126}, bytes.Repeat([]byte("x"), 126)...))
	}()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Time{})
	close(continuation)
	actual := make([]byte, 126)
	if _, err := io.ReadFull(c, actual); err != nil || !bytes.Equal(actual, bytes.Repeat([]byte("x"), 126)) {
		t.Fatalf("partial header lost %v", err)
	}
	<-done
}

func TestReadDeadlineInterruptsPongWhenPeerDoesNotRead(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	c := newConn(client, bufio.NewReader(client), nil)
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	sent := make(chan struct{})
	go func() { _, _ = peer.Write([]byte{0x89, 1, 'p'}); close(sent) }()
	result := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); result <- err }()
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Pong write deadline %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read stuck writing Pong beyond read deadline")
	}
	<-sent
}

type writeSignalConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *writeSignalConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}
func TestReadDeadlineDoesNotWaitForOccupiedWriter(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	carrier := &writeSignalConn{Conn: client, started: make(chan struct{})}
	c := newConn(carrier, bufio.NewReader(carrier), nil)
	defer c.Close()
	writer := make(chan error, 1)
	go func() { _, err := c.Write([]byte("application")); writer <- err }()
	<-carrier.started
	sent := make(chan struct{})
	go func() { _, _ = peer.Write([]byte{0x89, 1, 'p'}); close(sent) }()
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	result := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); result <- err }()
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read waited on blocked app writer")
	}
	<-sent
	select {
	case err := <-writer:
		t.Fatalf("read deadline interrupted independent application write: %v", err)
	default:
	}
	// Clear only the read deadline and drain the original application frame.
	// It must retain its own write deadline and finish successfully.
	_ = c.SetReadDeadline(time.Time{})
	frame := make([]byte, 6+len("application"))
	if _, err := io.ReadFull(peer, frame); err != nil {
		t.Fatal(err)
	}
	if err := <-writer; err != nil {
		t.Fatalf("application writer polluted by read deadline: %v", err)
	}
}

type deadlineRecordConn struct {
	*writeSignalConn
	mu            sync.Mutex
	writeDeadline time.Time
}

func (c *deadlineRecordConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}
func TestControlWriteRestoresLatestConcurrentWriteDeadline(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	carrier := &deadlineRecordConn{writeSignalConn: &writeSignalConn{Conn: client, started: make(chan struct{})}}
	c := newConn(carrier, bufio.NewReader(carrier), nil)
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	go func() { _, _ = peer.Write([]byte{0x89, 1, 'p'}) }()
	result := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); result <- err }()
	<-carrier.started
	latest := time.Now().Add(time.Hour)
	_ = c.SetWriteDeadline(latest)
	_ = c.SetReadDeadline(time.Now())
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("control write did not observe updated read deadline")
	}
	carrier.mu.Lock()
	actual := carrier.writeDeadline
	carrier.mu.Unlock()
	if actual != latest {
		t.Fatalf("restored stale write deadline %s, want %s", actual, latest)
	}
}
