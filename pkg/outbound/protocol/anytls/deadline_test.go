package anytls

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type deadlineSpyConn struct {
	net.Conn
	readDeadlines, writeDeadlines atomic.Int32
}

func (c *deadlineSpyConn) SetDeadline(time.Time) error {
	c.readDeadlines.Add(1)
	c.writeDeadlines.Add(1)
	return nil
}
func (c *deadlineSpyConn) SetReadDeadline(time.Time) error  { c.readDeadlines.Add(1); return nil }
func (c *deadlineSpyConn) SetWriteDeadline(time.Time) error { c.writeDeadlines.Add(1); return nil }

func TestStreamReadDeadlineIsolatedFromCarrierAndSibling(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	carrier := &deadlineSpyConn{Conn: client}
	s := newSession(carrier, nil, nil)
	defer s.Close()
	first, second := newStream(s, 1), newStream(s, 2)
	s.streams[1], s.streams[2] = first, second
	_ = first.SetDeadline(time.Now().Add(-time.Second))
	if _, err := first.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read deadline=%v", err)
	}
	_ = first.SetReadDeadline(time.Time{})
	go func() { second.receive([]byte("b")) }()
	var result [1]byte
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := second.Read(result[:]); err != nil || result[0] != 'b' {
		t.Fatalf("sibling read=%q,%v", result, err)
	}
	if carrier.readDeadlines.Load() != 0 || carrier.writeDeadlines.Load() != 0 {
		t.Fatal("stream deadline modified shared transport")
	}
	if !s.lease.Valid() || !first.lease.Valid() || !second.lease.Valid() {
		t.Fatal("operation deadline invalidated shared resource or stream")
	}
}

type blockedOwnedWriteConn struct {
	*deadlineSpyConn
	entered   chan struct{}
	release   chan struct{}
	captured  chan []byte
	once      sync.Once
	closeOnce sync.Once
	writes    atomic.Int32
}

func (c *blockedOwnedWriteConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	c.once.Do(func() { close(c.entered) })
	<-c.release
	c.captured <- append([]byte(nil), p...)
	return len(p), nil
}
func (c *blockedOwnedWriteConn) Close() error {
	c.closeOnce.Do(func() { close(c.release) })
	return c.Conn.Close()
}

func TestStreamWriteDeadlineBoundsPendingWorkAndOwnsBuffer(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	carrier := &blockedOwnedWriteConn{deadlineSpyConn: &deadlineSpyConn{Conn: client}, entered: make(chan struct{}), release: make(chan struct{}), captured: make(chan []byte, 8)}
	s := newSession(carrier, nil, nil)
	s.sendPadding = false
	c := newStream(s, 1)
	s.streams[1] = c
	defer s.Close()
	payload := []byte("hello")
	_ = c.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
	result := make(chan error, 1)
	go func() { _, err := c.Write(payload); result <- err }()
	<-carrier.entered
	if err := <-result; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write deadline=%v", err)
	}
	copy(payload, []byte("XXXXX"))
	for range 3 {
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
		if _, err := c.Write([]byte("queued")); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("queued deadline=%v", err)
		}
	}
	if carrier.writes.Load() != 1 {
		t.Fatalf("timed-out writes created %d pending carrier writes", carrier.writes.Load())
	}
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("stream Close waited for shared write")
	}
	if carrier.writeDeadlines.Load() != 0 {
		t.Fatal("stream write deadline modified carrier")
	}
	_ = s.Close()
	select {
	case actual := <-carrier.captured:
		if !bytes.Equal(actual[len(actual)-5:], []byte("hello")) {
			t.Fatalf("caller buffer reused during pending write: %q", actual)
		}
	case <-time.After(time.Second):
		t.Fatal("pending write did not finish after carrier close")
	}
	select {
	case <-c.writeDone:
	case <-time.After(time.Second):
		t.Fatal("stream writer leaked after carrier close")
	}
}

func TestClosedStreamsDoNotAccumulateWorkersBehindCarrierWrite(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	carrier := &blockedOwnedWriteConn{deadlineSpyConn: &deadlineSpyConn{Conn: client}, entered: make(chan struct{}), release: make(chan struct{}), captured: make(chan []byte, 8)}
	s := newSession(carrier, nil, nil)
	s.sendPadding = false
	defer s.Close()
	first := newStream(s, 1)
	s.streams[1] = first
	_ = first.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := first.Write([]byte("held")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("initial deadline=%v", err)
	}
	_ = first.Close()
	for id := uint32(2); id < 32; id++ {
		stream := newStream(s, id)
		s.streamLock.Lock()
		s.streams[id] = stream
		s.streamLock.Unlock()
		_ = stream.SetWriteDeadline(time.Now().Add(5 * time.Millisecond))
		if _, err := stream.Write([]byte("queued")); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("stream %d deadline=%v", id, err)
		}
		_ = stream.Close()
		select {
		case <-stream.writeDone:
		case <-time.After(time.Second):
			t.Fatalf("closed stream %d retained its blocked writer", id)
		}
	}
	if carrier.writes.Load() != 1 {
		t.Fatalf("carrier writers=%d", carrier.writes.Load())
	}
	if !s.lease.Valid() {
		t.Fatal("ordinary operation deadlines killed carrier")
	}
	_ = s.Close()
	select {
	case <-first.writeDone:
	case <-time.After(time.Second):
		t.Fatal("active carrier writer survived carrier Close")
	}
}

func TestCanceledOpenStreamsLeaveNoWorkBehindSharedWriter(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	carrier := &blockedOwnedWriteConn{deadlineSpyConn: &deadlineSpyConn{Conn: client}, entered: make(chan struct{}), release: make(chan struct{}), captured: make(chan []byte, 8)}
	s := newSession(carrier, nil, nil)
	s.sendPadding = false
	defer s.Close()
	first := newStream(s, 1)
	s.streams[1] = first
	_ = first.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := first.Write([]byte("held")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	_ = first.Close()
	for range 30 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		done := make(chan error, 1)
		go func() { _, err := s.newStreamContext(ctx, "target.example:443"); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("canceled open succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("canceled open remained behind shared writer")
		}
		cancel()
		s.streamLock.RLock()
		count := len(s.streams)
		s.streamLock.RUnlock()
		if count != 0 {
			t.Fatalf("canceled open retained %d streams", count)
		}
	}
	if carrier.writes.Load() != 1 {
		t.Fatalf("carrier writers=%d", carrier.writes.Load())
	}
	if !s.lease.Valid() {
		t.Fatal("open cancellation killed shared carrier")
	}
}

type capturedFrameConn struct {
	net.Conn
	frames chan []byte
}

func (c *capturedFrameConn) Write(p []byte) (int, error) {
	c.frames <- append([]byte(nil), p...)
	return len(p), nil
}
func TestCanceledFirstPacketKeepsAddressHeaderForNextWrite(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	carrier := &capturedFrameConn{Conn: client, frames: make(chan []byte, 8)}
	s := newSession(carrier, nil, nil)
	s.sendPadding = false
	defer s.Close()
	stream := newStream(s, 1)
	s.streams[1] = stream
	packet := &packetStream{stream: stream, addr: "1.1.1.1:53"}
	<-s.writeGate
	_ = packet.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	addr := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}
	if _, err := packet.WriteTo([]byte("first"), addr); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("first packet=%v", err)
	}
	select {
	case <-packet.writeAdmission:
		packet.writeAdmission <- struct{}{}
	case <-time.After(time.Second):
		t.Fatal("canceled packet did not release stream admission")
	}
	s.writeGate <- struct{}{}
	_ = packet.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := packet.WriteTo([]byte("second"), addr); err != nil {
		t.Fatal(err)
	}
	actual := <-carrier.frames
	if len(actual) <= headerOverHeadSize || actual[headerOverHeadSize] != 1 {
		t.Fatalf("next packet omitted connected-mode address header: %v", actual)
	}
}
