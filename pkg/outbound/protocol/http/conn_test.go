package http

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// tunnelEnd is how the server saw a CONNECT stream's request side end.
type tunnelEnd struct {
	bytes            int
	endStream, reset bool
}

// serveEndingTunnels answers every CONNECT with 200 and "bye", and unless
// open, at once ends the response, as a target that closes first. It
// reports how each stream's request side ended.
func serveEndingTunnels(conn net.Conn, ends chan<- tunnelEnd, open bool) {
	defer conn.Close()
	if _, err := io.ReadFull(conn, make([]byte, len(http2.ClientPreface))); err != nil {
		return
	}
	f := http2.NewFramer(conn, conn)
	_ = f.WriteSettings()
	received := map[uint32]int{}
	for {
		frame, err := f.ReadFrame()
		if err != nil {
			return
		}
		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			if !frame.IsAck() {
				_ = f.WriteSettingsAck()
			}
		case *http2.HeadersFrame:
			var block bytes.Buffer
			_ = hpack.NewEncoder(&block).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			_ = f.WriteHeaders(http2.HeadersFrameParam{StreamID: frame.StreamID, BlockFragment: block.Bytes(), EndHeaders: true})
			_ = f.WriteData(frame.StreamID, !open, []byte("bye"))
		case *http2.DataFrame:
			n := len(frame.Data())
			received[frame.StreamID] += n
			if n > 0 {
				_ = f.WriteWindowUpdate(0, uint32(n))
				_ = f.WriteWindowUpdate(frame.StreamID, uint32(n))
			}
			if frame.StreamEnded() {
				ends <- tunnelEnd{bytes: received[frame.StreamID], endStream: true}
			}
		case *http2.RSTStreamFrame:
			ends <- tunnelEnd{bytes: received[frame.StreamID], reset: true}
		}
	}
}

type endingTunnelParent struct {
	ends chan tunnelEnd
	open bool
}

func (p endingTunnelParent) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	client, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		return nil, err
	}
	server, err := listener.Accept()
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	go serveEndingTunnels(server, p.ends, p.open)
	return &negotiatedTestConn{Conn: client, proto: "h2", lease: netproxy.NewLease(netproxy.NewResourceRef())}, nil
}

func (endingTunnelParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, fmt.Errorf("unexpected packet dial")
}

// The relay's order when the target closes first: read EOF, write the last
// upload, CloseWrite, then Close. The server gets all of it and END_STREAM,
// not a reset. Close without CloseWrite resets the stream, even when x/net
// reads the end of the request body before it sees the cancellation.
func TestH2CloseAfterCloseWriteEndsStream(t *testing.T) {
	parent := endingTunnelParent{ends: make(chan tunnelEnd, 1)}
	proxy := &HttpProxy{ParentDialer: parent, https: true, Addr: "local:443", pool: newH2ConnsPool(parent, "local:443")}
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err := proxy.pool.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{'x'}, 40<<10)
	upload := func(closeWrite bool) tunnelEnd {
		t.Helper()
		conn, err := proxy.DialContext(ctx, "tcp", "target.test:443")
		if err != nil {
			t.Fatal(err)
		}
		if reply, err := io.ReadAll(conn); err != nil || string(reply) != "bye" {
			t.Fatalf("reply = %q, %v", reply, err)
		}
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		if closeWrite {
			if err := netproxy.CloseWrite(conn); err != nil {
				t.Fatal(err)
			}
		}
		_ = conn.Close()
		select {
		case end := <-parent.ends:
			return end
		case <-time.After(3 * time.Second):
			t.Fatal("server saw neither END_STREAM nor RST_STREAM")
			return tunnelEnd{}
		}
	}
	for range 50 {
		if end := upload(true); !end.endStream || end.bytes != len(payload) {
			t.Fatalf("after CloseWrite the server saw %+v, want all %d bytes and END_STREAM", end, len(payload))
		}
		if end := upload(false); !end.reset {
			t.Fatalf("without CloseWrite the server saw %+v, want RST_STREAM", end)
		}
	}
}

// A relay torn down before the response ended, here after CloseWrite,
// resets the stream at once: x/net holds the request body until the peer
// ends its side, so waiting for it would last netproxy.CloseLinger.
func TestH2CloseBeforeResponseEndResets(t *testing.T) {
	parent := endingTunnelParent{ends: make(chan tunnelEnd, 2), open: true}
	proxy := &HttpProxy{ParentDialer: parent, https: true, Addr: "local:443", pool: newH2ConnsPool(parent, "local:443")}
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err := proxy.pool.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	conn, err := proxy.DialContext(ctx, "tcp", "target.test:443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, len("bye"))); err != nil {
		t.Fatal(err)
	}
	if err := netproxy.CloseWrite(conn); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = conn.Close()
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("Close took %v", waited)
	}
	for {
		select {
		case end := <-parent.ends:
			if end.reset {
				return
			}
		case <-time.After(3 * time.Second):
			t.Fatal("server saw no RST_STREAM")
		}
	}
}
