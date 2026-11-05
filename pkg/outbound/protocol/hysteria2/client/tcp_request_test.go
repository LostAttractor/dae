package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/internal/protocol"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/qlog"
	"github.com/daeuniverse/quic-go/qlogwriter"
	"github.com/daeuniverse/quic-go/quicvarint"
)

// fastOpenClient is a FastOpen client over one loopback QUIC connection; the
// peer end, configured by serverConfig, is returned.
func fastOpenClient(t *testing.T, serverConfig *quic.Config) (*Client, *quic.Conn) {
	t.Helper()
	client, server := quicTestPair(t, serverConfig)
	resource := &clientResource{conn: client}
	c := &Client{config: &Config{FastOpen: true}}
	c.lifecycle = netproxy.NewSingleSession(netproxy.SingleSessionConfig[*clientResource]{
		Layer:     netproxy.LayerQUIC,
		Establish: func(context.Context) (*clientResource, error) { return resource, nil },
	})
	if err := c.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	return c, server
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

// The peer fixture deliberately lives in tests; the production codec is client-only.
func readTCPRequest(r io.Reader) (string, error) {
	q := quicvarint.NewReader(r)
	if frame, err := quicvarint.Read(q); err != nil || frame != protocol.FrameTypeTCPRequest {
		return "", errors.Join(err, errors.New("not a TCP request"))
	}
	n, err := quicvarint.Read(q)
	if err != nil {
		return "", err
	}
	addr := make([]byte, n)
	if _, err := io.ReadFull(r, addr); err != nil {
		return "", err
	}
	if n, err = quicvarint.Read(q); err != nil {
		return "", err
	}
	_, err = io.CopyN(io.Discard, r, int64(n))
	return string(addr), err
}

func acceptTCPRequest(t *testing.T, server *quic.Conn) *quic.Stream {
	t.Helper()
	peer, err := server.AcceptStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
	if addr, err := readTCPRequest(peer); err != nil || addr != "example.test:443" {
		t.Fatalf("request=%q err=%v", addr, err)
	}
	return peer
}

// DialContext sends nothing; the request rides the first payload in one
// stream write.
func TestFastOpenRequestRidesFirstWrite(t *testing.T) {
	received := &receivedStreamFrames{}
	c, server := fastOpenClient(t, &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return received }})
	conn, err := c.DialContext(t.Context(), "tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	requestLen := len(conn.(*tcpConn).request)
	idle, stop := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer stop()
	if _, err := server.AcceptStream(idle); err == nil {
		t.Fatal("DialContext sent the stream")
	}
	// More than quic-go buffers into one frame, so a request written on its
	// own would reach the peer as a STREAM frame of its own.
	payload := bytes.Repeat([]byte{'x'}, 2000)
	if n, err := conn.Write(payload); n != len(payload) || err != nil {
		t.Fatalf("first write = %d, %v", n, err)
	}
	peer := acceptTCPRequest(t, server)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(peer, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("payload after the request: %v", err)
	}
	_ = server.CloseWithError(0, "") // returns once every received packet is recorded
	received.mu.Lock()
	defer received.mu.Unlock()
	i := slices.IndexFunc(received.frames, func(f qlog.StreamFrame) bool { return f.StreamID == peer.StreamID() && f.Offset == 0 })
	if i < 0 || received.frames[i].Length <= int64(requestLen) {
		t.Fatalf("first STREAM frame does not carry payload after the request: %+v", received.frames)
	}
}

// A Read or CloseWrite before any Write sends the request alone.
func TestFastOpenReadOrCloseWriteSendsRequestAlone(t *testing.T) {
	c, server := fastOpenClient(t, nil)
	reading, err := c.DialContext(t.Context(), "tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer reading.Close()
	reply := make(chan error, 1)
	go func() {
		b := make([]byte, 4)
		_, err := io.ReadFull(reading, b)
		if err == nil && string(b) != "pong" {
			err = errors.New("wrong reply " + string(b))
		}
		reply <- err
	}()
	peer := acceptTCPRequest(t, server)
	if _, err := peer.Write([]byte{0, 0, 0, 'p', 'o', 'n', 'g'}); err != nil {
		t.Fatal(err)
	}
	if err := <-reply; err != nil {
		t.Fatal(err)
	}
	if err := netproxy.CloseWrite(reading); err != nil {
		t.Fatal(err)
	}
	if rest, err := io.ReadAll(peer); err != nil || len(rest) != 0 {
		t.Fatalf("after the request: %q, %v", rest, err)
	}

	closing, err := c.DialContext(t.Context(), "tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer closing.Close()
	if err := netproxy.CloseWrite(closing); err != nil {
		t.Fatal(err)
	}
	if rest, err := io.ReadAll(acceptTCPRequest(t, server)); err != nil || len(rest) != 0 {
		t.Fatalf("after the request: %q, %v", rest, err)
	}
}

func TestFastOpenFailedRequestSticks(t *testing.T) {
	c, _ := fastOpenClient(t, nil)
	conn, err := c.DialContext(t.Context(), "tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(-time.Second))
	_, err = conn.Write([]byte("hello"))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("request write = %v", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})
	_, writeErr := conn.Write([]byte("hello"))
	_, readErr := conn.Read(make([]byte, 1))
	if writeErr != err || readErr != err || netproxy.CloseWrite(conn) != err {
		t.Fatalf("failure not sticky: write=%v read=%v", writeErr, readErr)
	}
}

// A reconnect resumes the node's TLS session without 0-RTT, even when the
// server would accept early data.
func TestReconnectResumesTLSWithoutEarlyData(t *testing.T) {
	addr := serveH3(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(protocol.StatusAuthOK) })
	// NewDialer gives every node one session cache.
	client, err := NewClient(&Config{Addr: addr, NextDialer: authTestDialer{}, TLSConfig: tls.Config{InsecureSkipVerify: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for i := range 2 {
		if err := client.Connect(t.Context()); err != nil {
			t.Fatal(err)
		}
		resource, err := client.currentResource()
		if err != nil {
			t.Fatal(err)
		}
		if state := resource.conn.ConnectionState(); state.TLS.DidResume != (i == 1) || state.Used0RTT {
			t.Fatalf("connection %d: resumed=%v 0-RTT=%v", i, state.TLS.DidResume, state.Used0RTT)
		}
		_ = resource.conn.CloseWithError(0, "")
	}
}
