package juicity

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/internal/testutil"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/qlog"
	"github.com/daeuniverse/quic-go/qlogwriter"
)

// tcpRequest opens a TCP stream to 1.2.3.4:443.
var tcpRequest = []byte{1, 1, 1, 2, 3, 4, 1, 187}

func newPendingConn(t *testing.T) (*Conn, *quic.Conn) {
	t.Helper()
	pair := testutil.NewQUICPair(t)
	stream, err := pair.Client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := protocol.ParseMetadata("1.2.3.4:443")
	if err != nil {
		t.Fatal(err)
	}
	conn := newConn(stream, &Metadata{Metadata: metadata, Network: "tcp"})
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn, pair.Server
}

func acceptStream(t *testing.T, server *quic.Conn) *quic.Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	remote, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = remote.SetDeadline(time.Now().Add(5 * time.Second))
	return remote
}

// receivedStreamFrames records the STREAM frames a QUIC connection receives.
type receivedStreamFrames struct {
	mu     sync.Mutex
	frames []qlog.StreamFrame
}

func (r *receivedStreamFrames) AddProducer() qlogwriter.Recorder { return r }
func (*receivedStreamFrames) SupportsSchemas(string) bool        { return true }
func (*receivedStreamFrames) Close() error                       { return nil }
func (r *receivedStreamFrames) RecordEvent(event qlogwriter.Event) {
	packet, ok := event.(qlog.PacketReceived)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, frame := range packet.Frames {
		if stream, ok := frame.Frame.(*qlog.StreamFrame); ok {
			r.frames = append(r.frames, *stream)
		}
	}
}

// DialContext leaves the request for the first write, which carries both.
func TestDialDefersRequestToFirstWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	received := &receivedStreamFrames{}
	listener, err := quic.ListenAddr("127.0.0.1:0", recoveryTLS(t), &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return received }})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	d, err := NewDialer(loopbackPacketParent{}, protocol.Header{ProxyAddress: listener.Addr().String(), User: "00000000-0000-0000-0000-000000000000", Password: "test", Feature1: "bbr", TlsConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"juicity-test"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.CloseWithError(0, "")
	conn, err := d.DialContext(ctx, "tcp", "1.2.3.4:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !conn.(*Conn).first.Pending() {
		t.Fatal("DialContext wrote the request")
	}
	// More than quic-go buffers into one frame, so a request written on its
	// own would reach the peer as a STREAM frame of its own.
	payload := bytes.Repeat([]byte{'x'}, 2000)
	if n, err := conn.Write(payload); n != len(payload) || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if err := conn.(netproxy.CloseWriter).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	remote := acceptStream(t, server)
	if got, err := io.ReadAll(remote); err != nil || !bytes.Equal(got, append(tcpRequest, payload...)) {
		t.Fatalf("peer read %x, %v", got, err)
	}
	_ = server.CloseWithError(0, "") // returns once every received packet is recorded
	received.mu.Lock()
	defer received.mu.Unlock()
	i := slices.IndexFunc(received.frames, func(f qlog.StreamFrame) bool { return f.StreamID == remote.StreamID() && f.Offset == 0 })
	if i < 0 || received.frames[i].Length <= int64(len(tcpRequest)) {
		t.Fatalf("first STREAM frame does not carry payload after the request: %+v", received.frames)
	}
}

func TestReadBeforeWriteSendsRequest(t *testing.T) {
	conn, server := newPendingConn(t)
	read := make(chan error, 1)
	greeting := make([]byte, 5)
	go func() { _, err := io.ReadFull(conn, greeting); read <- err }()
	remote := acceptStream(t, server)
	got := make([]byte, len(tcpRequest))
	if _, err := io.ReadFull(remote, got); err != nil || !bytes.Equal(got, tcpRequest) {
		t.Fatalf("request %x, %v", got, err)
	}
	if _, err := remote.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := <-read; err != nil || string(greeting) != "hello" {
		t.Fatalf("Read = %q, %v", greeting, err)
	}
	if _, err := conn.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if rest, err := io.ReadAll(remote); err != nil || string(rest) != "reply" {
		t.Fatalf("after request %q, %v", rest, err)
	}
}

// A peer may reply after part of the first Write and read on only once the
// client has read that reply.
func TestReadDoesNotWaitForBlockedFirstWrite(t *testing.T) {
	conn, server := newPendingConn(t)
	go conn.Write(make([]byte, 8<<20)) // beyond the stream's flow-control window
	remote := acceptStream(t, server)
	if _, err := io.ReadFull(remote, make([]byte, 1<<10)); err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	read := make(chan string, 1)
	go func() {
		reply := make([]byte, 5)
		n, _ := io.ReadFull(conn, reply)
		read <- string(reply[:n])
	}()
	select {
	case got := <-read:
		if got != "reply" {
			t.Fatalf("reply=%q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read waited for the first Write")
	}
}

func TestCloseWriteBeforeWriteSendsRequest(t *testing.T) {
	conn, server := newPendingConn(t)
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	remote := acceptStream(t, server)
	if got, err := io.ReadAll(remote); err != nil || !bytes.Equal(got, tcpRequest) {
		t.Fatalf("peer read %x, %v", got, err)
	}
	if _, err := remote.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	_ = remote.Close()
	if got, err := io.ReadAll(conn); err != nil || string(got) != "response" {
		t.Fatalf("Read after CloseWrite = %q, %v", got, err)
	}
}

func TestFailedRequestWriteIsSticky(t *testing.T) {
	conn, _ := newPendingConn(t)
	_ = conn.SetWriteDeadline(time.Now().Add(-time.Second))
	_, want := conn.Write([]byte("payload"))
	if want == nil {
		t.Fatal("write past its deadline succeeded")
	}
	_ = conn.SetWriteDeadline(time.Time{})
	if _, err := conn.Write([]byte("payload")); !errors.Is(err, want) {
		t.Fatalf("Write = %v, want %v", err, want)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, want) {
		t.Fatalf("Read = %v, want %v", err, want)
	}
	if err := conn.CloseWrite(); !errors.Is(err, want) {
		t.Fatalf("CloseWrite = %v, want %v", err, want)
	}
}

// A UDP stream's reader starts before its first datagram, so reading leaves
// the request to that datagram.
func TestUDPReadLeavesRequestToFirstDatagram(t *testing.T) {
	pair := testutil.NewQUICPair(t)
	stream, err := pair.Client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := protocol.ParseMetadata("1.2.3.4:53")
	if err != nil {
		t.Fatal(err)
	}
	conn := &PacketConn{Conn: newConn(stream, &Metadata{Metadata: metadata, Network: "udp"})}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, _, err := conn.ReadFrom(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) || !conn.first.Pending() {
		t.Fatalf("ReadFrom = %v, request sent = %v", err, !conn.first.Pending())
	}
}
