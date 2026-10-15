package anytls

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

func TestSlowReaderDoesNotBlockSibling(t *testing.T) {
	carrier, peer := net.Pipe()
	s := newSession(carrier, nil, nil)
	a, b := newStream(s, 1), newStream(s, 2)
	s.streams[1], s.streams[2] = a, b
	done := make(chan error, 1)
	go func() { done <- s.run() }()
	defer func() { _ = s.Close(); _ = peer.Close(); <-done }()

	var wire bytes.Buffer
	appendFrame(&wire, cmdPSH, 1, []byte("unread"))
	appendFrame(&wire, cmdFIN, 1, nil)
	appendFrame(&wire, cmdPSH, 2, []byte("sibling"))
	go func() { _, _ = peer.Write(wire.Bytes()) }()
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, len("sibling"))
	if _, err := io.ReadFull(b, buf); err != nil || string(buf) != "sibling" {
		t.Fatalf("sibling read = %q, %v", buf, err)
	}
	// A FIN follows the already queued bytes; it must not discard them.
	_ = a.SetReadDeadline(time.Now().Add(time.Second))
	got, err := io.ReadAll(a)
	if err != nil || string(got) != "unread" {
		t.Fatalf("FIN discarded buffered data: %q, %v", got, err)
	}
	_ = a.Close()
}

func TestListenPacketSharesLifetimeAcrossDestinations(t *testing.T) {
	d, err := NewDialer(testParentDialer{}, protocol.Header{Password: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	carrier, peer := net.Pipe()
	defer peer.Close()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	s := newSession(carrier, d.sessionIdle, nil)
	d.sessions[s], d.idleSessions[s] = struct{}{}, struct{}{}
	conn, err := d.ListenPacket(context.Background(), "192.0.2.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i, target := range []string{"192.0.2.1:53", "[2001:db8::1]:123"} {
		if _, err := conn.WriteTo([]byte("request"), netproxy.NewAddr("udp", target)); err != nil {
			t.Fatal(err)
		}
		s.streamLock.RLock()
		stream := s.streams[uint32(i+1)]
		s.streamLock.RUnlock()
		if stream == nil {
			t.Fatalf("missing target stream %d", i+1)
		}
		stream.receive([]byte{0, 2, 'o', 'k'})
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		var buf [8]byte
		n, from, err := conn.ReadFrom(buf[:])
		if err != nil || string(buf[:n]) != "ok" || from.String() != target {
			t.Fatalf("target reply = %q, %v, %v", buf[:n], from, err)
		}
	}
	_ = conn.Close()
	s.streamLock.RLock()
	remaining := len(s.streams)
	s.streamLock.RUnlock()
	if remaining != 0 || !s.lease.Valid() {
		t.Fatalf("association cleanup: streams=%d, session valid=%v", remaining, s.lease.Valid())
	}
}

func TestReceiveOverflowClosesOnlyStalledStream(t *testing.T) {
	carrier, peer := net.Pipe()
	defer peer.Close()
	s := newSession(carrier, nil, nil)
	defer s.Close()
	a, b := newStream(s, 1), newStream(s, 2)
	s.streams[1], s.streams[2] = a, b
	a.receive(make([]byte, maxStreamReceiveBuffer))
	a.receive([]byte("overflow"))
	_, err := a.Read(make([]byte, 1))
	failure := netproxy.ClassifyFailure(err)
	if failure.Scope != netproxy.ScopeStream || failure.Reason != netproxy.ReasonCapacity {
		t.Fatalf("overflow = %v", err)
	}
	b.receive([]byte("b"))
	var buf [1]byte
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := b.Read(buf[:]); err != nil || buf[0] != 'b' {
		t.Fatalf("sibling read = %q, %v", buf, err)
	}
	if !s.lease.Valid() || !b.lease.Valid() || a.received != nil {
		t.Fatal("overflow invalidated siblings or retained the stalled buffer")
	}
}

func TestCarrierEOFPreservesReceivedFrames(t *testing.T) {
	carrier, peer := net.Pipe()
	s := newSession(carrier, nil, nil)
	c := newStream(s, 1)
	s.streams[1] = c
	defer c.Close()
	defer peer.Close()
	done := make(chan error, 1)
	go func() { done <- s.run() }()

	var wire bytes.Buffer
	appendFrame(&wire, cmdPSH, 1, []byte("reply"))
	if _, err := peer.Write(wire.Bytes()); err != nil {
		t.Fatal(err)
	}
	_ = peer.Close()
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("carrier shutdown = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("carrier EOF did not stop session")
	}

	// EOF may be observed by the frame reader before the application is
	// scheduled. A complete PSH remains readable before the terminal error.
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var response [5]byte
	if _, err := io.ReadFull(c, response[:]); err != nil || string(response[:]) != "reply" {
		t.Fatalf("response before carrier EOF = %q, %v", response, err)
	}
	if _, err := c.Read(response[:]); !errors.Is(err, io.EOF) || netproxy.ClassifyFailure(err).Scope != netproxy.ScopeSharedResource {
		t.Fatalf("terminal read lost the shared failure: %v", err)
	}
}

func TestLocalSessionCloseDiscardsBufferedFrames(t *testing.T) {
	carrier, peer := net.Pipe()
	defer peer.Close()
	s := newSession(carrier, nil, nil)
	c := newStream(s, 1)
	s.streams[1] = c
	c.receive([]byte("unread"))
	_ = s.Close()
	var data [8]byte
	if n, err := c.Read(data[:]); n != 0 || !errors.Is(err, net.ErrClosed) || c.received != nil {
		t.Fatalf("local close retained received data: %q, %v", data[:n], err)
	}
}
