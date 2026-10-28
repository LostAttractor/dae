package singmux

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/bits"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy/fq"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

// smux v1 as sing-box servers speak it (xtaci/smux with its default
// configuration and keepalive disabled): every frame is an 8-byte header of
// version, command, little-endian payload length and stream ID, then the
// payload. The server checks the version of every frame.
const (
	smuxVersion    = 1
	smuxCmdSYN     = 0
	smuxCmdFIN     = 1
	smuxCmdPSH     = 2
	smuxCmdNOP     = 3
	smuxHeaderSize = 8
	// smuxMaxFrame is the most payload one frame carries, the server's
	// MaxFrameSize, and smuxFullFrame the size of such a frame.
	smuxMaxFrame  = 32 << 10
	smuxFullFrame = smuxHeaderSize + smuxMaxFrame
	// smuxWriteBatch bounds each carrier write without changing socket policy.
	smuxWriteBatch = 64 << 10
	// smuxReceiveBuffer is the payload a session holds for its readers
	// before it stops reading the carrier, the server's MaxReceiveBuffer. v1
	// has no per-stream flow control: a stalled reader stalls the session.
	smuxReceiveBuffer = 4 << 20
	// smuxCoalesce is the smallest data buffer while queue space permits;
	// later writes fill its unused capacity before allocating another frame.
	smuxCoalesce = 2 << 10
	// Closed streams retain their send ownership; stop replacing them while
	// the carrier is stalled, without a FIFO budget for live stream writers.
	smuxRetiredLimit = smuxReceiveBuffer / fq.StreamLimit
)

var (
	errSmuxProtocol  = errors.New("smux: invalid frame")
	errSmuxStreamIDs = errors.New("smux: stream IDs exhausted")
	errSmuxRetired   = errors.New("smux: closed streams still draining")

	smuxQueueDelay = netproxy.NewQueueDelay("smux")
)

// smuxHeader fills in the header that frame f starts with.
func smuxHeader(f []byte, cmd byte, sid uint32) {
	f[0], f[1] = smuxVersion, cmd
	binary.LittleEndian.PutUint16(f[2:], uint16(len(f)-smuxHeaderSize))
	binary.LittleEndian.PutUint32(f[4:], sid)
}

// smuxControl returns a pooled frame without payload.
func smuxControl(cmd byte, sid uint32) []byte {
	f := pool.GetBuffer(smuxHeaderSize)
	smuxHeader(f, cmd, sid)
	return f
}

// newFrame returns a pooled frame buffer of size bytes and at least
// capacity.
func newFrame(size, capacity int) []byte { return pool.GetBuffer(max(size, capacity))[:size] }

func putFrame(f []byte) { pool.PutBuffer(f) }

// smuxSession is a client session. It runs two goroutines: recvLoop reads
// frames into per-stream buffers, and sendLoop, woken only when the send
// queue turns non-empty, writes queued frames in batches. Streams queue
// frames in order, so SYN precedes and FIN follows a stream's data; the
// scheduler fq shares the carrier among the streams by bytes. The carrier
// write provides backpressure. A frame is one pooled buffer, its
// header and payload; a datagram is one buffer of one or more frames. Batches
// may split buffers, but a started buffer finishes before another starts.
type smuxSession struct {
	conn    *monitoredConn
	buffers netproxy.BuffersWriter // the carrier's vectorised writer, if any

	mu      sync.Mutex
	streams map[uint32]*smuxStream // receive or retain send ownership until FIN leaves
	retired int
	// nextID passes math.MaxUint32 once stream IDs are exhausted.
	nextID   uint64
	fq       fq.Scheduler
	writing  bool          // sendLoop is busy; enqueuers wake it otherwise
	draining chan struct{} // closed when queued and in-flight frames have left
	closing  bool          // Close is writing the queue; only FIN may join
	sealed   bool          // flushed while closing; not even a FIN joins
	dead     bool
	err      error // why the session died; set before die closes
	wake     chan struct{}

	budget     atomic.Int64 // receive buffer left
	budgetWake chan struct{}

	die             chan struct{}
	dieOnce         sync.Once
	carrierCloseErr error
}

func newSmuxSession(conn *monitoredConn) *smuxSession {
	s := &smuxSession{
		conn:       conn,
		buffers:    netproxy.BuffersWriterOf(conn.Conn),
		streams:    make(map[uint32]*smuxStream),
		nextID:     1,
		wake:       make(chan struct{}, 1),
		budgetWake: make(chan struct{}, 1),
		die:        make(chan struct{}),
	}
	s.fq.Release, s.fq.Delay = s.releaseFrame, smuxQueueDelay
	s.budget.Store(smuxReceiveBuffer)
	go s.recvLoop()
	go s.sendLoop()
	return s
}

func signal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

func (s *smuxSession) OpenStream(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead {
		return nil, s.err
	}
	if s.closing {
		return nil, io.ErrClosedPipe
	}
	if s.retired >= smuxRetiredLimit {
		return nil, netproxy.WrapFailure(errSmuxRetired, netproxy.Failure{Reason: netproxy.ReasonCapacity})
	}
	if s.nextID > math.MaxUint32 {
		return nil, errSmuxStreamIDs
	}
	st := &smuxStream{
		session:       s,
		id:            uint32(s.nextID),
		done:          make(chan struct{}),
		readable:      make(chan struct{}, 1),
		readDeadline:  protocol.MakeDeadline(),
		writeDeadline: protocol.MakeDeadline(),
	}
	// Client IDs are odd.
	s.nextID += 2
	s.streams[st.id] = st
	st.enqueueLocked(smuxControl(smuxCmdSYN, st.id))
	return st, nil
}

func (s *smuxSession) IsClosed() bool {
	select {
	case <-s.die:
		return true
	default:
		return false
	}
}

func (s *smuxSession) CloseChan() <-chan struct{} { return s.die }

// Close ends the session; its streams fail with io.ErrClosedPipe. Frames
// already queued, such as the last data and FIN of a stream closed just
// before, are written first: Write and Close return once queued, and the
// peer would otherwise see a clean but cut stream. Meanwhile streams accept
// no data and no stream opens. The carrier is then half-closed until the
// peer's EOF, all within netproxy.CloseLinger.
func (s *smuxSession) Close() error {
	s.mu.Lock()
	if !s.dead && !s.closing {
		s.closing = true
		if s.writing {
			if s.draining == nil {
				s.draining = make(chan struct{})
			}
		} else {
			s.sealed = true
		}
	}
	flushed := s.draining
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), netproxy.CloseLinger)
	defer cancel()
	if flushed != nil {
		select {
		case <-flushed:
		case <-s.die:
		case <-ctx.Done():
		}
	}
	lingerCarrier(ctx, s.conn, s.die)
	return s.abort()
}

func (s *smuxSession) abort() error {
	if !s.shutdown(io.ErrClosedPipe) {
		return io.ErrClosedPipe
	}
	return s.carrierCloseErr
}

// The carrier monitor records why the session failed.
func (*smuxSession) closeErr() error { return nil }

// smux v1 has no per-stream window: a session whose receive buffer is full
// stops reading, and a new stream would wait behind the stalled one.
func (s *smuxSession) saturated() bool { return s.budget.Load() <= 0 }

// drained returns nil when the sender is idle, otherwise its next idle event.
// writing includes the batch outside fq, including a last FIN in Write.
func (s *smuxSession) drained() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.writing || s.dead {
		return nil
	}
	if s.draining == nil {
		s.draining = make(chan struct{})
	}
	return s.draining
}

// shutdown kills the session with err once, dropping queued frames and closing
// the carrier, which stops both loops. It reports whether this call did so.
func (s *smuxSession) shutdown(err error) bool {
	first := false
	s.dieOnce.Do(func() {
		first = true
		s.mu.Lock()
		s.dead, s.err = true, err
		s.fq.Clear()
		streams := make([]*smuxStream, 0, len(s.streams))
		for _, st := range s.streams {
			streams = append(streams, st)
		}
		s.mu.Unlock()
		close(s.die)
		s.carrierCloseErr = s.conn.Close()
		// Streams that push have no reader to see the session end.
		for _, st := range streams {
			st.rmu.Lock()
			st.endPushLocked(err)
			st.unlockReceive()
		}
	})
	return first
}

// fail reports a carrier or protocol failure and kills the session with it.
func (s *smuxSession) fail(err error) {
	s.conn.report(err)
	s.shutdown(err)
}

func (s *smuxSession) stream(sid uint32) *smuxStream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[sid]
}

// release returns consumed receive buffer and resumes a waiting recvLoop.
func (s *smuxSession) release(n int) {
	if after := s.budget.Add(int64(n)); after > 0 && after <= int64(n) {
		signal(s.budgetWake)
	}
}

func (s *smuxSession) recvLoop() {
	var header [smuxHeaderSize]byte
	for {
		for s.budget.Load() <= 0 {
			select {
			case <-s.budgetWake:
			case <-s.die:
				return
			}
		}
		if _, err := io.ReadFull(s.conn, header[:]); err != nil {
			// The carrier monitor has reported err.
			s.shutdown(err)
			return
		}
		length, sid := int(binary.LittleEndian.Uint16(header[2:])), binary.LittleEndian.Uint32(header[4:])
		valid := header[0] == smuxVersion
		switch header[1] {
		case smuxCmdNOP, smuxCmdSYN:
			// sing-mux servers never open streams; there is nothing to accept.
			valid = valid && length == 0
		case smuxCmdFIN:
			if valid = valid && length == 0; valid {
				if st := s.stream(sid); st != nil {
					st.finish()
				}
			}
		case smuxCmdPSH:
			if !valid || length == 0 {
				break
			}
			buf := pool.GetBuffer(length)
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				pool.PutBuffer(buf)
				s.shutdown(err)
				return
			}
			// Data for a stream closed here is dropped, as by the server.
			if st := s.stream(sid); st == nil || !st.deliver(buf) {
				pool.PutBuffer(buf)
			}
		default:
			valid = false
		}
		if !valid {
			s.fail(netproxy.WrapFailure(errSmuxProtocol, netproxy.Failure{Reason: netproxy.ReasonProtocol}))
			return
		}
	}
}

func (s *smuxSession) sendLoop() {
	var batch [][]byte
	for {
		select {
		case <-s.wake:
		case <-s.die:
			return
		}
		for {
			s.mu.Lock()
			if !s.fq.Queued() || s.dead {
				s.writing = false
				if s.draining != nil {
					close(s.draining)
					s.draining = nil
				}
				s.sealed = s.closing
				s.mu.Unlock()
				break
			}
			s.mu.Unlock()
			if err := s.conn.SetWriteDeadline(time.Now().Add(netproxy.DialTimeout)); err != nil {
				s.fail(err)
				return
			}
			s.mu.Lock()
			batch = s.fq.Take(time.Now(), smuxWriteBatch, batch[:0])
			s.mu.Unlock()
			var err error
			if len(batch) != 0 {
				err = s.write(batch)
			}
			clear(batch)
			s.mu.Lock()
			s.fq.ReleaseBatch()
			s.mu.Unlock()
			if err != nil {
				// The carrier monitor has reported err.
				s.shutdown(err)
				return
			}
		}
	}
}

// releaseFrame ends send ownership only after the writer returns its buffer.
func (s *smuxSession) releaseFrame(f []byte) {
	if f[1] == smuxCmdFIN {
		id := binary.LittleEndian.Uint32(f[4:])
		if st := s.streams[id]; st != nil && st.closed {
			delete(s.streams, id)
			s.retired--
		}
	}
	putFrame(f)
}

// wakeLocked wakes sendLoop for frames just queued.
func (s *smuxSession) wakeLocked() {
	if !s.writing {
		s.writing = true
		signal(s.wake)
	}
}

// write sends a batch with one carrier write, joining it into a pooled
// buffer only if the carrier cannot write vectors.
func (s *smuxSession) write(batch [][]byte) error {
	size := 0
	for _, f := range batch {
		size += len(f)
	}
	if s.buffers != nil {
		n, err := s.buffers.WriteBuffers(batch)
		if err == nil && n != size {
			err = io.ErrShortWrite
		}
		s.conn.report(err)
		return err
	}
	buf := pool.GetBuffer(size)
	defer pool.PutBuffer(buf)
	joined := buf[:0]
	for _, f := range batch {
		joined = append(joined, f...)
	}
	n, err := s.conn.Write(joined)
	if err == nil && n != size {
		err = io.ErrShortWrite
		s.conn.report(err)
	}
	return err
}

// smuxStream is a client stream. Write queues frames, waiting only while the
// stream's queue is full; Read drains buffered frames and then reports the
// peer's FIN as io.EOF. A dead session fails both with its cause.
type smuxStream struct {
	session *smuxSession
	id      uint32
	done    chan struct{} // closed by Close

	// Send state, guarded by session.mu.
	flow   fq.Flow
	closed bool

	// Receive state, guarded by rmu.
	rmu      sync.Mutex
	in       fq.FIFO[[]byte] // pooled frame payloads; in.Peek()[inOff:] is next
	inOff    int
	finished bool // the peer sent FIN
	released bool // Close returned the buffered payload
	readable chan struct{}
	// In push mode payloads go to push instead of in; pushEnd reports once
	// why delivery ended, after which push and pushEnd are nil. ended holds
	// it, with endErr, until rmu is unlocked.
	pushing bool
	push    func([]byte) error
	pushEnd func(error)
	ended   func(error)
	endErr  error

	readDeadline, writeDeadline protocol.Deadline
}

// enqueueLocked queues a frame behind the stream's earlier frames.
func (st *smuxStream) enqueueLocked(f []byte) {
	st.session.fq.Push(&st.flow, f)
	st.session.wakeLocked()
}

func (st *smuxStream) Write(b []byte) (int, error) {
	// writeFrame only sees the deadline while it waits for queue space.
	select {
	case <-st.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	written := 0
	for len(b) > 0 {
		n, err := st.writeFrame(b)
		written += n
		if err != nil {
			return written, err
		}
		b = b[n:]
	}
	return written, nil
}

// writeFrame fills existing capacity first, then allocates only what fits the
// queued budget. Waiting writers retain no unaccounted pooled copy.
func (st *smuxStream) writeFrame(b []byte) (int, error) {
	s := st.session
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		switch {
		case st.closed || s.closing:
			return 0, io.ErrClosedPipe
		case s.dead:
			return 0, s.err
		}
		select {
		case <-st.writeDeadline.Wait():
			return 0, os.ErrDeadlineExceeded
		default:
		}
		// Include the header in the pooled frame capacity.
		const frame = smuxMaxFrame
		if tail := st.flow.Tail(); tail != nil && (*tail)[1] == smuxCmdPSH {
			n := min(len(b), min(cap(*tail), frame)-len(*tail))
			if n > 0 {
				*tail = append(*tail, b[:n]...)
				smuxHeader(*tail, smuxCmdPSH, st.id)
				st.flow.WakeWriter()
				return n, nil
			}
		}
		available := st.flow.Available()
		if available > smuxHeaderSize {
			// Power-of-two pools must fit by capacity, not payload length.
			capacity := min(frame, 1<<(bits.Len(uint(available))-1))
			n := min(len(b), capacity-smuxHeaderSize)
			f := newFrame(smuxHeaderSize+n, min(smuxCoalesce, capacity))
			copy(f[smuxHeaderSize:], b[:n])
			smuxHeader(f, smuxCmdPSH, st.id)
			st.enqueueLocked(f)
			st.flow.WakeWriter()
			return n, nil
		}
		writable := st.flow.Writable()
		s.mu.Unlock()
		select {
		case <-writable:
		case <-st.done:
		case <-s.die:
		case <-st.writeDeadline.Wait():
		}
		s.mu.Lock()
	}
}

// writeDatagram reserves and frames a borrowed datagram under the session
// lock, so rejecting admission never allocates an unaccounted copy. Its
// frames share one buffer and are sent or dropped together.
func (st *smuxStream) writeDatagram(request, prefix, payload []byte) error {
	s := st.session
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case st.closed:
		return io.ErrClosedPipe
	case s.dead:
		return s.err
	case s.closing:
		return io.ErrClosedPipe
	}
	size := len(request) + len(prefix) + len(payload)
	frames := (size + smuxMaxFrame - 1) / smuxMaxFrame
	data := s.fq.AllocateDatagram(&st.flow, time.Now(), size+frames*smuxHeaderSize, request != nil)
	if data == nil {
		return netproxy.ErrPacketDropped
	}
	parts := [...][]byte{request, prefix, payload}
	part, offset := 0, 0
	for rest := data; size > 0; {
		n := min(size, smuxMaxFrame)
		frame := rest[:smuxHeaderSize+n]
		smuxHeader(frame, smuxCmdPSH, st.id)
		for dst := frame[smuxHeaderSize:]; len(dst) > 0; {
			copied := copy(dst, parts[part][offset:])
			dst, offset = dst[copied:], offset+copied
			if offset == len(parts[part]) {
				part, offset = part+1, 0
			}
		}
		size, rest = size-n, rest[len(frame):]
	}
	s.wakeLocked()
	return nil
}

// deliver buffers a payload unless the stream is closed or pushes it.
func (st *smuxStream) deliver(data []byte) bool {
	st.rmu.Lock()
	if st.pushing {
		st.pushLocked(data)
		st.unlockReceive()
		return false
	}
	if st.released {
		st.rmu.Unlock()
		return false
	}
	st.in.Push(data)
	st.rmu.Unlock()
	st.session.budget.Add(-int64(len(data)))
	signal(st.readable)
	return true
}

func (st *smuxStream) finish() {
	st.rmu.Lock()
	st.finished = true
	st.endPushLocked(io.EOF)
	st.unlockReceive()
	signal(st.readable)
}

// setPush hands every later payload to push, on recvLoop, and the reason
// delivery ends to end, once. Payloads that arrived before are pushed first.
func (st *smuxStream) setPush(push func([]byte) error, end func(error)) {
	st.rmu.Lock()
	defer st.unlockReceive()
	st.pushing, st.push, st.pushEnd = true, push, end
	n := 0
	for st.in.Len() > 0 {
		data := st.in.Pop()
		n += len(data) - st.inOff
		st.pushLocked(data[st.inOff:])
		st.inOff = 0
		pool.PutBuffer(data)
	}
	st.session.release(n)
	switch {
	case st.released:
		st.endPushLocked(io.ErrClosedPipe)
	case st.finished:
		st.endPushLocked(io.EOF)
	case st.session.IsClosed():
		st.endPushLocked(st.session.err)
	}
}

func (st *smuxStream) pushLocked(data []byte) {
	if st.push != nil {
		if err := st.push(data); err != nil {
			st.endPushLocked(err)
		}
	}
}

// endPushLocked ends delivery with err, which unlockReceive reports.
func (st *smuxStream) endPushLocked(err error) {
	if end := st.pushEnd; end != nil {
		st.push, st.pushEnd = nil, nil
		st.ended, st.endErr = end, err
	}
}

// unlockReceive unlocks rmu, then reports the end of delivery recorded
// meanwhile: unlocked, so that the callback may use the stream, even close
// it.
func (st *smuxStream) unlockReceive() {
	end, err := st.ended, st.endErr
	st.ended, st.endErr = nil, nil
	st.rmu.Unlock()
	if end != nil {
		end(err)
	}
}

func (st *smuxStream) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	s := st.session
	for {
		st.rmu.Lock()
		n := 0
		for n < len(b) && st.in.Len() > 0 {
			data := st.in.Peek()
			m := copy(b[n:], data[st.inOff:])
			n, st.inOff = n+m, st.inOff+m
			if st.inOff == len(data) {
				pool.PutBuffer(st.in.Pop())
				st.inOff = 0
			}
		}
		released, finished := st.released, st.finished
		st.rmu.Unlock()
		switch {
		case n > 0:
			s.release(n)
			return n, nil
		case released:
			return 0, io.ErrClosedPipe
		case finished:
			return 0, io.EOF
		}
		select {
		case <-s.die:
			return 0, s.err
		default:
		}
		select {
		case <-st.readable:
		case <-st.done:
		case <-s.die:
		case <-st.readDeadline.Wait():
			return 0, os.ErrDeadlineExceeded
		}
	}
}

// Close queues FIN behind the data already written and drops data not read.
func (st *smuxStream) Close() error {
	s := st.session
	s.mu.Lock()
	if st.closed {
		s.mu.Unlock()
		return io.ErrClosedPipe
	}
	st.closed = true
	// After a closing session's flush the carrier is half-closed: a FIN
	// would fail it and end the wait for the peer's EOF. The stream then
	// ends with the session.
	if !s.dead && !s.sealed {
		s.retired++
		st.enqueueLocked(smuxControl(smuxCmdFIN, st.id))
	} else {
		delete(s.streams, st.id)
	}
	s.mu.Unlock()
	close(st.done)
	st.rmu.Lock()
	st.released = true
	n := 0
	for st.in.Len() > 0 {
		data := st.in.Pop()
		n += len(data) - st.inOff
		st.inOff = 0
		pool.PutBuffer(data)
	}
	st.endPushLocked(io.ErrClosedPipe)
	st.unlockReceive()
	s.release(n)
	return nil
}

func (st *smuxStream) LocalAddr() net.Addr  { return st.session.conn.LocalAddr() }
func (st *smuxStream) RemoteAddr() net.Addr { return st.session.conn.RemoteAddr() }

func (st *smuxStream) SetDeadline(t time.Time) error {
	st.readDeadline.Set(t)
	st.writeDeadline.Set(t)
	return nil
}

func (st *smuxStream) SetReadDeadline(t time.Time) error {
	st.readDeadline.Set(t)
	return nil
}

func (st *smuxStream) SetWriteDeadline(t time.Time) error {
	st.writeDeadline.Set(t)
	return nil
}
