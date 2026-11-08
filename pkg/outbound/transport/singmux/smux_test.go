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
	"github.com/daeuniverse/dae/pkg/outbound/netproxy/fq"
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

// Streams send SYN, their data and FIN in order; the writer shares the
// carrier among them by bytes, a batch of up to smuxWriteBatch bytes per carrier
// write.
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
	// Ten quanta each; the SYN and two frames fit a stream's queue.
	frame := func(c byte) []byte { return bytes.Repeat([]byte{c}, (16<<10)-smuxHeaderSize) }
	write := func(st net.Conn, fills ...byte) {
		for _, fill := range fills {
			if _, err := st.Write(frame(fill)); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(a, 'a', 'A')
	b, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	write(b, 'b', 'B')
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
		{smuxCmdPSH, 1, 'a'}, {smuxCmdSYN, 3, 0}, {smuxCmdPSH, 3, 'b'},
		{smuxCmdPSH, 1, 'A'}, {smuxCmdPSH, 3, 'B'}, {smuxCmdFIN, 1, 0},
		{smuxCmdFIN, 3, 0},
	}
	for i, w := range want {
		f := nextFrame(t, frames)
		if f.cmd != w.cmd || f.sid != w.sid || w.fill != 0 && !bytes.Equal(f.data, frame(w.fill)) || w.fill == 0 && len(f.data) != 0 {
			t.Fatalf("frame %d = cmd %d sid %d %d bytes, want cmd %d sid %d", i, f.cmd, f.sid, len(f.data), w.cmd, w.sid)
		}
	}
}

// smuxFrame includes the header in a pooled stream frame.
const smuxFrame = smuxMaxFrame

// fqStreamBytes is the stream data that fills a stream's queue: whole
// frames up to fq.StreamLimit of buffers.
const fqStreamBytes = fq.StreamLimit / smuxFrame * (smuxFrame - smuxHeaderSize)

// A stream queues fq.StreamLimit bytes of frame buffers; further writes wait
// for the writer within their deadline and are woken by Close. A write past
// its deadline fails even with room. The streams of a session queue
// independently: no session bound holds an idle stream's write.
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
	if n, err := st.Write(make([]byte, fqStreamBytes)); n != fqStreamBytes || err != nil {
		t.Fatalf("queued write = %d, %v", n, err)
	}
	_ = st.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	if n, err := st.Write([]byte{1}); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write to a full queue = %d, %v; want a timeout", n, err)
	}
	_ = st.SetWriteDeadline(time.Time{})

	// More than the old 1 MiB session queue held. Their SYNs queue too.
	frames := func(n int) []byte { return make([]byte, n*(smuxFrame-smuxHeaderSize)) }
	for range 40 {
		other, err := s.OpenStream(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := other.Write(frames(1)); err != nil {
			t.Fatal(err)
		}
		defer other.Close()
	}
	other, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Write(frames(1)); err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() {
		_, err := other.Write(frames(1))
		written <- err
	}()
	time.Sleep(10 * time.Millisecond)
	_ = other.Close()
	if err := <-written; !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Close woke a waiting writer with %v", err)
	}

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
}

// steppedConn holds every write until step lets it through.
type steppedConn struct {
	net.Conn
	entered, step chan struct{}
}

func (c *steppedConn) Write(p []byte) (int, error) {
	c.entered <- struct{}{}
	<-c.step
	return c.Conn.Write(p)
}

// A stream that turns busy leads the next carrier write, ahead of streams
// that queued long before.
func TestSmuxSparseStreamGoesFirst(t *testing.T) {
	local, remote := net.Pipe()
	carrier := &steppedConn{Conn: local, entered: make(chan struct{}), step: make(chan struct{})}
	s := newTestSmuxSession(carrier)
	defer s.Close()
	frames := readFrames(remote)
	bulk, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	<-carrier.entered // the SYN
	if _, err := bulk.Write(make([]byte, fqStreamBytes)); err != nil {
		t.Fatal(err)
	}
	carrier.step <- struct{}{}
	<-carrier.entered // the first data batch is already committed
	if _, err := bulk.Write(make([]byte, fqStreamBytes)); err != nil {
		t.Fatal(err)
	}
	sparse, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sparse.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			select {
			case carrier.step <- struct{}{}:
			case <-s.CloseChan():
				return
			}
			select {
			case <-carrier.entered:
			case <-s.CloseChan():
				return
			}
		}
	}()
	for i, want := range []struct {
		cmd byte
		sid uint32
	}{{smuxCmdSYN, 1}, {smuxCmdPSH, 1}, {smuxCmdPSH, 1}, {smuxCmdSYN, 3}, {smuxCmdPSH, 3}, {smuxCmdPSH, 1}, {smuxCmdPSH, 1}} {
		if f := nextFrame(t, frames); f.cmd != want.cmd || f.sid != want.sid {
			t.Fatalf("frame %d = cmd %d sid %d, want cmd %d sid %d", i, f.cmd, f.sid, want.cmd, want.sid)
		}
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
	payload := make([]byte, fqStreamBytes)
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

// A FIN ends both directions: the server drops later data, so the writer
// learns of it, including one already waiting for queue space.
func TestSmuxWriteFailsAfterPeerFIN(t *testing.T) {
	local, remote := net.Pipe()
	carrier := newGatedConn(local)
	s := newTestSmuxSession(carrier)
	defer s.Close()
	server := smuxtest.Server(remote)
	defer server.Close()
	st, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	<-carrier.entered
	if _, err := st.Write(make([]byte, fqStreamBytes)); err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() {
		_, err := st.Write([]byte{1})
		written <- err
	}()
	select {
	case err := <-written:
		t.Fatalf("write to a full queue did not wait: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := server.WriteFrame(smuxVersion, smuxCmdFIN, 1, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-written:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("waiting write after FIN = %v, want io.EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("FIN did not wake the waiting writer")
	}
	if n, err := st.Write([]byte{1}); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("write after FIN = %d, %v; want io.EOF", n, err)
	}
	if err := st.(*smuxStream).writeDatagram(nil, nil, []byte{1}); !errors.Is(err, io.EOF) {
		t.Fatalf("datagram after FIN = %v, want io.EOF", err)
	}
	close(carrier.gate)
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

type chunkRecordingCarrier struct {
	net.Conn
	data    bytes.Buffer
	largest int
}

func (c *chunkRecordingCarrier) Write(b []byte) (int, error) {
	c.largest = max(c.largest, len(b))
	return c.data.Write(b)
}

func TestSmuxLargeDatagramRespectsBatchLimit(t *testing.T) {
	carrier := new(chunkRecordingCarrier)
	s := &smuxSession{conn: &monitoredConn{Conn: carrier}}
	data := bytes.Repeat([]byte("payload"), 10000)
	s.fq.Release = putFrame
	if !s.fq.Force(new(fq.Flow), time.Now(), data) {
		t.Fatal("datagram admission failed")
	}
	defer s.fq.Clear()
	for s.fq.Queued() {
		batch := s.fq.Take(time.Now(), smuxWriteBatch, nil)
		err := s.write(batch)
		s.fq.ReleaseBatch()
		if err != nil {
			t.Fatal(err)
		}
	}
	if carrier.largest != smuxWriteBatch || !bytes.Equal(carrier.data.Bytes(), data) {
		t.Fatalf("largest write %d, delivered %d of %d bytes", carrier.largest, carrier.data.Len(), len(data))
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

func TestSmuxConcurrentWritersUseFreedSpace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, remote := net.Pipe()
		carrier := newGatedConn(local)
		s := newTestSmuxSession(carrier)
		defer s.Close()
		defer remote.Close()
		go io.Copy(io.Discard, remote)
		st, err := s.OpenStream(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		<-carrier.entered
		if _, err := st.Write(make([]byte, fqStreamBytes)); err != nil {
			t.Fatal(err)
		}
		var writers sync.WaitGroup
		var failures atomic.Int32
		for range 10 {
			writers.Go(func() {
				_ = st.SetWriteDeadline(time.Now().Add(time.Second))
				if _, err := st.Write([]byte{1}); err != nil {
					failures.Add(1)
				}
			})
		}
		synctest.Wait()
		close(carrier.gate)
		writers.Wait()
		if failures.Load() != 0 {
			t.Fatalf("%d writers timed out despite space in their queue", failures.Load())
		}
	})
}
