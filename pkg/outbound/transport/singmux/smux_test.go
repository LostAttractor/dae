package singmux

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/transport/singmux/smuxtest"
)

func newTestSmuxSession(conn net.Conn) *smuxSession {
	return newSmuxSession(&monitoredConn{Conn: conn, failed: make(chan error, 1)})
}

// smuxStreamPair opens a client stream over net.Pipe to a test server.
func smuxStreamPair(tb testing.TB) (net.Conn, *smuxtest.Stream) {
	tb.Helper()
	local, remote := net.Pipe()
	session := newTestSmuxSession(local)
	server := smuxtest.Server(remote)
	tb.Cleanup(func() {
		_ = session.Close()
		_ = server.Close()
	})
	stream, err := session.OpenStream(context.Background())
	if err != nil {
		tb.Fatal(err)
	}
	peer, err := server.Accept()
	if err != nil {
		tb.Fatal(err)
	}
	return stream, peer
}

// waitIdle waits until the session has written every queued frame.
func waitIdle(t *testing.T, s *smuxSession) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		writing := s.writing
		s.mu.Unlock()
		if !writing {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("session did not flush its queue")
		}
		time.Sleep(time.Millisecond)
	}
}

// gatedConn holds its first write until the gate opens.
type gatedConn struct {
	net.Conn
	once    sync.Once
	entered chan struct{}
	gate    chan struct{}
}

func newGatedConn(conn net.Conn) *gatedConn {
	return &gatedConn{Conn: conn, entered: make(chan struct{}), gate: make(chan struct{})}
}

func (c *gatedConn) Write(p []byte) (int, error) {
	c.once.Do(func() {
		close(c.entered)
		<-c.gate
	})
	return c.Conn.Write(p)
}

type wireFrame struct {
	cmd  byte
	sid  uint32
	data []byte
}

// readFrames decodes client frames until the connection fails.
func readFrames(conn net.Conn) <-chan wireFrame {
	frames := make(chan wireFrame, 64)
	go func() {
		defer close(frames)
		var header [smuxHeaderSize]byte
		for {
			if _, err := io.ReadFull(conn, header[:]); err != nil || header[0] != smuxVersion {
				return
			}
			data := make([]byte, binary.LittleEndian.Uint16(header[2:]))
			if _, err := io.ReadFull(conn, data); err != nil {
				return
			}
			frames <- wireFrame{header[1], binary.LittleEndian.Uint32(header[4:]), data}
		}
	}()
	return frames
}

func nextFrame(t *testing.T, frames <-chan wireFrame) wireFrame {
	t.Helper()
	select {
	case f, ok := <-frames:
		if !ok {
			t.Fatal("carrier closed")
		}
		return f
	case <-time.After(time.Second):
		t.Fatal("no frame")
	}
	return wireFrame{}
}

// Streams send SYN, their data and FIN in order; the writer takes one frame
// per stream in turn, up to smuxWriteBatch bytes per carrier write.
func TestSmuxFramesKeepStreamOrderAndAlternate(t *testing.T) {
	local, remote := net.Pipe()
	carrier := newGatedConn(local)
	s := newTestSmuxSession(carrier)
	defer s.Close()
	a, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	<-carrier.entered // SYN a is being written
	frame := func(c byte) []byte { return bytes.Repeat([]byte{c}, smuxMaxFrame) }
	if _, err := a.Write(append(frame('a'), frame('A')...)); err != nil {
		t.Fatal(err)
	}
	b, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write(append(frame('b'), frame('B')...)); err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	_ = b.Close()
	frames := readFrames(remote)
	close(carrier.gate)
	want := []struct {
		cmd  byte
		sid  uint32
		fill byte
	}{
		{smuxCmdSYN, 1, 0},
		{smuxCmdPSH, 1, 'a'}, {smuxCmdSYN, 3, 0}, {smuxCmdPSH, 1, 'A'},
		{smuxCmdPSH, 3, 'b'}, {smuxCmdFIN, 1, 0}, {smuxCmdPSH, 3, 'B'},
		{smuxCmdFIN, 3, 0},
	}
	for i, w := range want {
		f := nextFrame(t, frames)
		if f.cmd != w.cmd || f.sid != w.sid || w.fill != 0 && !bytes.Equal(f.data, frame(w.fill)) || w.fill == 0 && len(f.data) != 0 {
			t.Fatalf("frame %d = cmd %d sid %d %d bytes, want cmd %d sid %d", i, f.cmd, f.sid, len(f.data), w.cmd, w.sid)
		}
	}
}

// A stream queues smuxStreamQueue bytes of frames; further writes wait for
// the writer within their deadline and are woken by Close. A write past its
// deadline fails even with room.
func TestSmuxWriteWaitsForQueue(t *testing.T) {
	local, remote := net.Pipe()
	carrier := newGatedConn(local)
	s := newTestSmuxSession(carrier)
	defer s.Close()
	go io.Copy(io.Discard, remote)
	st, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	<-carrier.entered
	_ = st.SetWriteDeadline(time.Now().Add(-time.Second))
	if n, err := st.Write([]byte{1}); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write past its deadline = %d, %v; want a timeout", n, err)
	}
	_ = st.SetWriteDeadline(time.Time{})
	if n, err := st.Write(make([]byte, 2*smuxMaxFrame)); n != 2*smuxMaxFrame || err != nil {
		t.Fatalf("queued write = %d, %v", n, err)
	}
	_ = st.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	if n, err := st.Write([]byte{1}); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write to a full queue = %d, %v; want a timeout", n, err)
	}
	_ = st.SetWriteDeadline(time.Time{})
	written := make(chan error, 1)
	go func() {
		_, err := st.Write([]byte{1})
		written <- err
	}()
	select {
	case err := <-written:
		t.Fatalf("write did not wait: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(carrier.gate)
	if err := <-written; err != nil {
		t.Fatal(err)
	}

	other, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	other.(*smuxStream).queued = smuxStreamQueue // as if the writer were stuck
	s.mu.Unlock()
	go func() {
		_, err := other.Write([]byte{1})
		written <- err
	}()
	time.Sleep(10 * time.Millisecond)
	_ = other.Close()
	if err := <-written; !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Close woke a waiting writer with %v", err)
	}
}

// Small writes behind a busy carrier join the stream's last queued frame.
func TestSmuxSmallWritesShareFrames(t *testing.T) {
	local, remote := net.Pipe()
	carrier := newGatedConn(local)
	s := newTestSmuxSession(carrier)
	defer s.Close()
	st, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	<-carrier.entered // the writer holds SYN
	var want []byte
	for i := range 3000 {
		if _, err := st.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		want = append(want, byte(i))
	}
	frames := readFrames(remote)
	close(carrier.gate)
	if f := nextFrame(t, frames); f.cmd != smuxCmdSYN {
		t.Fatalf("first frame cmd %d", f.cmd)
	}
	var got []byte
	count := 0
	for len(got) < len(want) {
		f := nextFrame(t, frames)
		got, count = append(got, f.data...), count+1
	}
	if !bytes.Equal(got, want) || count != 2 {
		t.Fatalf("%d bytes in %d frames, want %d in 2 frames of %d byte buffers", len(got), count, len(want), smuxCoalesce)
	}
}

// The streams of a session queue smuxSessionQueue bytes of frames; then
// writers wait until the queue drains.
func TestSmuxSessionQueueBoundsWriters(t *testing.T) {
	local, remote := net.Pipe()
	carrier := newGatedConn(local)
	s := newTestSmuxSession(carrier)
	defer s.Close()
	go io.Copy(io.Discard, remote)
	open := func() net.Conn {
		st, err := s.OpenStream(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	open()
	<-carrier.entered
	for range smuxSessionQueue / smuxStreamQueue {
		if _, err := open().Write(make([]byte, 2*smuxMaxFrame)); err != nil {
			t.Fatal(err)
		}
	}
	late := open()
	_ = late.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := late.Write(make([]byte, smuxCoalesce)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write to a full session = %v; want a timeout", err)
	}
	_ = late.SetWriteDeadline(time.Time{})
	written := make(chan error, 2)
	for _, st := range []net.Conn{late, open()} {
		go func() {
			_, err := st.Write(make([]byte, 2*smuxMaxFrame))
			written <- err
		}()
	}
	select {
	case err := <-written:
		t.Fatalf("write did not wait: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	s.mu.Lock()
	queued := s.queued
	s.mu.Unlock()
	if queued != smuxSessionQueue {
		t.Fatalf("session queued %d bytes, want %d", queued, smuxSessionQueue)
	}
	close(carrier.gate)
	for range 2 {
		if err := <-written; err != nil {
			t.Fatal(err)
		}
	}
	waitIdle(t, s)
	if s.queued != 0 {
		t.Fatalf("session queued %d bytes once idle", s.queued)
	}
}

// A writer waiting for the session keeps its turn: a later write that would
// fit the space left waits behind it.
func TestSmuxSessionQueueKeepsTurns(t *testing.T) {
	local, remote := net.Pipe()
	carrier := newGatedConn(local)
	s := newTestSmuxSession(carrier)
	defer s.Close()
	go io.Copy(io.Discard, remote)
	first, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	<-carrier.entered
	later, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.queued = smuxSessionQueue - 2*smuxCoalesce // as if other streams queued it
	s.mu.Unlock()
	written := make(chan error, 2)
	go func() {
		_, err := first.Write(make([]byte, smuxMaxFrame))
		written <- err
	}()
	for waiting := 0; waiting == 0; {
		time.Sleep(time.Millisecond)
		s.mu.Lock()
		waiting = s.waiting
		s.mu.Unlock()
	}
	_ = later.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := later.Write([]byte{1}); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("later write = %v; want it to wait its turn", err)
	}
	_ = later.SetWriteDeadline(time.Time{})
	go func() {
		_, err := later.Write([]byte{1})
		written <- err
	}()
	s.mu.Lock()
	s.queued = 0 // the other streams' frames were written
	s.grantLocked()
	s.mu.Unlock()
	close(carrier.gate)
	for range 2 {
		if err := <-written; err != nil {
			t.Fatal(err)
		}
	}
	waitIdle(t, s)
	if s.queued != 0 || s.waiting != 0 {
		t.Fatalf("queued %d, %d waiting once idle", s.queued, s.waiting)
	}
}

// Waiting writers are granted session space in turn, as far as it lasts,
// skipping those that left.
func TestSmuxSessionQueueGrantsInTurn(t *testing.T) {
	s := &smuxSession{queued: smuxSessionQueue - smuxFullFrame}
	needs := []int{smuxFullFrame, smuxFullFrame / 2, smuxFullFrame / 2, 1}
	streams := make([]*smuxStream, len(needs))
	for i, need := range needs {
		streams[i] = &smuxStream{need: need, writable: make(chan struct{}, 1)}
		s.blocked.push(streams[i])
		s.waiting++
	}
	streams[0].need = 0 // its writer left
	s.waiting--
	s.grantLocked()
	for i, st := range streams {
		granted := len(st.writable) == 1
		if want := i == 1 || i == 2; granted != want || want && st.reserved != needs[i] {
			t.Fatalf("stream %d granted %v (%d bytes)", i, granted, st.reserved)
		}
	}
	if s.queued != smuxSessionQueue || s.waiting != 1 || s.blocked.len() != 1 {
		t.Fatalf("queued %d, %d waiting, %d in line", s.queued, s.waiting, s.blocked.len())
	}
}

// Close sends FIN only after every byte already written.
func TestSmuxCloseFollowsWrittenData(t *testing.T) {
	stream, peer := smuxStreamPair(t)
	payload := make([]byte, 1<<20+5)
	for i := range payload {
		payload[i] = byte(i)
	}
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(peer)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("peer read %d bytes, %v", len(got), err)
	}
}

// smux v1 cannot half-close: its FIN ends both directions. CloseWrite says
// so with errors.ErrUnsupported itself, without sending the stream request,
// and the stream stays usable.
func TestSmuxCloseWriteUnsupported(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requests := make(chan muxRequest, 1)
		mux := newTestMux(t, ProtocolSmux, func(request muxRequest, stream net.Conn) {
			requests <- request
			_, _ = io.Copy(stream, stream)
		})
		conn, err := mux.DialContext(t.Context(), "tcp", "target.example:443")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := netproxy.CloseWrite(conn); err != errors.ErrUnsupported {
			t.Fatalf("CloseWrite = %v, want errors.ErrUnsupported", err)
		}
		synctest.Wait()
		select {
		case request := <-requests:
			t.Fatalf("CloseWrite sent the stream request %+v", request)
		default:
		}
		if _, err := conn.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 5)
		if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "hello" {
			t.Fatalf("echo = %q, %v", reply, err)
		}
	})
}

// Closing the session writes the frames already queued, such as the last data
// and FIN of a stream closed just before, and accepts no new data meanwhile.
func TestSmuxSessionCloseWritesQueuedFrames(t *testing.T) {
	local, remote := net.Pipe()
	carrier := newGatedConn(local)
	s := newTestSmuxSession(carrier)
	server := smuxtest.Server(remote)
	defer server.Close()
	st, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	<-carrier.entered // the writer holds SYN; everything else queues
	other, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 2*smuxMaxFrame)
	for i := range payload {
		payload[i] = byte(i)
	}
	if _, err := st.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	for closing := false; !closing; {
		time.Sleep(time.Millisecond)
		s.mu.Lock()
		closing = s.closing
		s.mu.Unlock()
	}
	if _, err := other.Write([]byte{1}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Write while closing = %v", err)
	}
	if _, err := s.OpenStream(t.Context()); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("OpenStream while closing = %v", err)
	}
	close(carrier.gate)
	peer, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(peer)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("peer read %d of %d bytes, %v", len(got), len(payload), err)
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close waited after the queue was written")
	}
}

type failingCarrier struct {
	net.Conn
	err    error
	writes atomic.Int32
}

func (c *failingCarrier) Write([]byte) (int, error) {
	c.writes.Add(1)
	return 0, c.err
}

// A carrier write failure is reported once, kills the session and fails
// every stream operation with it.
func TestSmuxCarrierWriteFailureIsSticky(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	carrier := &failingCarrier{Conn: local, err: errors.New("carrier write")}
	monitor := &monitoredConn{Conn: carrier, failed: make(chan error, 1)}
	s := newSmuxSession(monitor)
	st, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.CloseChan():
	case <-time.After(time.Second):
		t.Fatal("session survived a carrier write failure")
	}
	if _, err := st.Write([]byte{1}); !errors.Is(err, carrier.err) {
		t.Fatalf("Write = %v", err)
	}
	if _, err := st.Read(make([]byte, 1)); !errors.Is(err, carrier.err) {
		t.Fatalf("Read = %v", err)
	}
	if _, err := s.OpenStream(t.Context()); !errors.Is(err, carrier.err) {
		t.Fatalf("OpenStream = %v", err)
	}
	if !errors.Is(monitor.cause(), carrier.err) || carrier.writes.Load() != 1 {
		t.Fatalf("cause %v after %d writes", monitor.cause(), carrier.writes.Load())
	}
	if err := s.Close(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Close of a dead session = %v", err)
	}
}

// buffersCarrier records vectorised writes, which must pass whole frames.
type buffersCarrier struct {
	net.Conn
	calls  atomic.Int32
	frames atomic.Int32
}

func (c *buffersCarrier) Write([]byte) (int, error) { panic("joined write on a vectorised carrier") }

func (c *buffersCarrier) WriteBuffers(v [][]byte) (int, error) {
	c.calls.Add(1)
	n := 0
	for _, b := range v {
		if len(b) != smuxHeaderSize+int(binary.LittleEndian.Uint16(b[2:])) {
			panic("buffer is not a frame")
		}
		c.frames.Add(1)
		n += len(b)
	}
	return n, nil
}

func TestSmuxBatchesFramesIntoOneVectorisedWrite(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	carrier := &buffersCarrier{Conn: local}
	gate := newGatedConn(carrier)
	// The gate hides WriteBuffers; let the session see it behind tracking.
	s := newTestSmuxSession(netproxy.TrackConn(&gatedBuffers{gatedConn: gate, buffers: carrier}, func() {}))
	defer s.Close()
	st, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	<-gate.entered
	for range 3 {
		if _, err := st.Write(make([]byte, smuxCoalesce)); err != nil {
			t.Fatal(err)
		}
	}
	close(gate.gate)
	waitIdle(t, s)
	if calls, frames := carrier.calls.Load(), carrier.frames.Load(); calls != 2 || frames != 4 {
		t.Fatalf("%d frames in %d carrier writes, want 4 in 2", frames, calls)
	}
}

type gatedBuffers struct {
	*gatedConn
	buffers *buffersCarrier
}

func (c *gatedBuffers) WriteBuffers(v [][]byte) (int, error) {
	c.once.Do(func() {
		close(c.entered)
		<-c.gate
	})
	return c.buffers.WriteBuffers(v)
}

// Read drains buffered data before the peer's FIN reports io.EOF; data for
// unknown or closed streams is dropped without holding receive buffer.
func TestSmuxReceive(t *testing.T) {
	local, remote := net.Pipe()
	s := newTestSmuxSession(local)
	defer s.Close()
	server := smuxtest.Server(remote)
	defer server.Close()
	st, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	closed, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_ = closed.Close()
	for _, f := range []struct {
		cmd  byte
		sid  uint32
		data string
	}{{smuxCmdPSH, 1, "hello "}, {smuxCmdPSH, 3, "closed"}, {smuxCmdPSH, 9, "unknown"}, {smuxCmdNOP, 0, ""}, {smuxCmdPSH, 1, "world"}, {smuxCmdFIN, 1, ""}} {
		if err := server.WriteFrame(smuxVersion, f.cmd, f.sid, []byte(f.data)); err != nil {
			t.Fatal(err)
		}
	}
	_ = st.SetReadDeadline(time.Now().Add(time.Second))
	got, err := io.ReadAll(st)
	if err != nil || string(got) != "hello world" {
		t.Fatalf("read %q, %v", got, err)
	}
	if budget := s.budget.Load(); budget != smuxReceiveBuffer {
		t.Fatalf("receive buffer %d after draining, want %d", budget, smuxReceiveBuffer)
	}
	if _, err := closed.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Read after Close = %v", err)
	}
}

// Unread data holds the session-wide receive buffer: the session stops
// reading the carrier until the stream is read or closed.
func TestSmuxReceiveBufferIsSharedBySession(t *testing.T) {
	local, remote := net.Pipe()
	s := newTestSmuxSession(local)
	defer s.Close()
	server := smuxtest.Server(remote)
	defer server.Close()
	stalled, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	flood := make([]byte, smuxMaxFrame)
	sent := make(chan error, 1)
	go func() {
		for range smuxReceiveBuffer / smuxMaxFrame {
			if err := server.WriteFrame(smuxVersion, smuxCmdPSH, 1, flood); err != nil {
				sent <- err
				return
			}
		}
		sent <- server.WriteFrame(smuxVersion, smuxCmdPSH, 3, []byte("next"))
	}()
	_ = other.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := other.Read(make([]byte, 4)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("other stream read past a full receive buffer: %v", err)
	}
	if _, err := stalled.Read(make([]byte, smuxMaxFrame)); err != nil {
		t.Fatal(err)
	}
	_ = other.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(other, buf); err != nil || string(buf) != "next" {
		t.Fatalf("read %q, %v after the buffer drained", buf, err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	_ = stalled.Close()
	if budget := s.budget.Load(); budget != smuxReceiveBuffer {
		t.Fatalf("receive buffer %d after Close, want %d", budget, smuxReceiveBuffer)
	}
}

// Frames a sing-box server would reject end the session as a protocol
// failure, which streams then report.
func TestSmuxInvalidFramesFailSession(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version byte
		cmd     byte
		data    []byte
	}{
		{"version 2", 2, smuxCmdPSH, []byte{1}},
		{"window update", smuxVersion, 4, make([]byte, 8)},
		{"unknown command", smuxVersion, 9, nil},
		{"NOP with payload", smuxVersion, smuxCmdNOP, []byte{1}},
		{"SYN with payload", smuxVersion, smuxCmdSYN, []byte{1}},
		{"FIN with payload", smuxVersion, smuxCmdFIN, []byte{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local, remote := net.Pipe()
			defer remote.Close()
			monitor := &monitoredConn{Conn: local, failed: make(chan error, 1)}
			s := newSmuxSession(monitor)
			defer s.Close()
			st, err := s.OpenStream(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			go io.Copy(io.Discard, remote)
			frame := []byte{tc.version, tc.cmd}
			frame = binary.LittleEndian.AppendUint16(frame, uint16(len(tc.data)))
			frame = binary.LittleEndian.AppendUint32(frame, 1)
			// The session may close before reading the payload.
			_, _ = remote.Write(append(frame, tc.data...))
			_ = st.SetReadDeadline(time.Now().Add(time.Second))
			_, err = st.Read(make([]byte, 1))
			if failure := netproxy.ClassifyFailure(err); failure.Reason != netproxy.ReasonProtocol || !errors.Is(monitor.cause(), err) {
				t.Fatalf("Read = %v (%+v), monitor %v", err, failure, monitor.cause())
			}
		})
	}
}

// The last odd stream ID is used once; then opens fail so that the pool
// replaces the session.
func TestSmuxStreamIDsRunOut(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	go io.Copy(io.Discard, remote)
	s := newTestSmuxSession(local)
	defer s.Close()
	s.mu.Lock()
	s.nextID = math.MaxUint32
	s.mu.Unlock()
	last, err := s.OpenStream(t.Context())
	if err != nil || last.(*smuxStream).id != math.MaxUint32 {
		t.Fatalf("last ID: %v", err)
	}
	if _, err := s.OpenStream(t.Context()); !idsExhausted(err) {
		t.Fatalf("open after the last ID = %v", err)
	}
}
