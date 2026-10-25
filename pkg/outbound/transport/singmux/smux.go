package singmux

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
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
	// smuxReceiveBuffer is the payload a session holds for its readers
	// before it stops reading the carrier, the server's MaxReceiveBuffer. v1
	// has no per-stream flow control: a stalled reader stalls the session.
	smuxReceiveBuffer = 4 << 20
	// smuxWriteBatch ends a carrier write once its frames reach this size.
	smuxWriteBatch = 64 << 10
	// Write waits while its stream queues smuxStreamQueue bytes of frame
	// buffers or the streams of its session smuxSessionQueue bytes.
	smuxStreamQueue  = 2 * smuxFullFrame
	smuxSessionQueue = 32 * smuxFullFrame
	// smuxCoalesce: a shorter write joins its stream's last queued frame if
	// that has room, and its own frame has room for more, so that small
	// writes behind a busy carrier share frames.
	smuxCoalesce = 2 << 10
	// A datagram is dropped rather than queued beyond smuxDatagramQueue bytes
	// of its stream or smuxSessionDatagramQueue bytes of its session.
	smuxDatagramQueue        = 64 << 10
	smuxSessionDatagramQueue = 256 << 10
)

var (
	errSmuxProtocol  = errors.New("smux: invalid frame")
	errSmuxStreamIDs = errors.New("smux: stream IDs exhausted")
)

// fifo is a slice-backed queue that reuses its storage.
type fifo[T any] struct {
	items []T
	head  int
}

func (q *fifo[T]) len() int { return len(q.items) - q.head }

func (q *fifo[T]) push(v T) {
	if q.head > 0 && len(q.items) == cap(q.items) {
		n := copy(q.items, q.items[q.head:])
		clear(q.items[n:])
		q.items, q.head = q.items[:n], 0
	}
	q.items = append(q.items, v)
}

func (q *fifo[T]) peek() T { return q.items[q.head] }

func (q *fifo[T]) last() *T { return &q.items[len(q.items)-1] }

func (q *fifo[T]) pop() T {
	v := q.items[q.head]
	var zero T
	q.items[q.head] = zero
	if q.head++; q.head == len(q.items) {
		q.items, q.head = q.items[:0], 0
	}
	return v
}

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

// fullFrames holds the buffers of frames beyond 32 KiB, which the shared pool
// would take from its 64 KiB buffers.
var fullFrames = sync.Pool{New: func() any { return new([smuxFullFrame]byte) }}

// newFrame returns a frame buffer of size bytes and at least capacity.
func newFrame(size, capacity int) []byte {
	if size > 32<<10 {
		return fullFrames.Get().(*[smuxFullFrame]byte)[:size]
	}
	return pool.GetBuffer(max(size, capacity))[:size]
}

func putFrame(f []byte) {
	if cap(f) == smuxFullFrame {
		fullFrames.Put((*[smuxFullFrame]byte)(f[:smuxFullFrame]))
		return
	}
	pool.PutBuffer(f)
}

// smuxSession is a client session. It runs two goroutines: recvLoop reads
// frames into per-stream buffers, and sendLoop, woken only when the send
// queue turns non-empty, writes queued frames in batches. Streams queue
// frames in order, so SYN precedes and FIN follows a stream's data, and the
// writer takes one frame per stream in turn. A frame is one pooled buffer,
// its header and payload.
type smuxSession struct {
	conn    *monitoredConn
	buffers netproxy.BuffersWriter // the carrier's vectorised writer, if any

	mu      sync.Mutex
	streams map[uint32]*smuxStream // streams that still receive
	// nextID passes math.MaxUint32 once stream IDs are exhausted.
	nextID uint64
	ready  fifo[*smuxStream] // streams with queued frames
	// queued is the capacity of the streams' queued data frames and the
	// space granted to waiting writers. A writer that does not fit, or comes
	// while others wait, lines up in blocked to be granted space in turn.
	queued  int
	waiting int // streams in blocked whose writer still waits
	blocked fifo[*smuxStream]
	// datagrams counts the queued bytes of datagram streams.
	datagrams int
	writing   bool          // sendLoop is busy; enqueuers wake it otherwise
	closing   bool          // Close is writing the queue; only FIN may join
	flushed   chan struct{} // closed once sendLoop idles while closing
	dead      bool
	err       error // why the session died; set before die closes
	wake      chan struct{}

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
	if s.nextID > math.MaxUint32 {
		return nil, errSmuxStreamIDs
	}
	st := &smuxStream{
		session:       s,
		id:            uint32(s.nextID),
		done:          make(chan struct{}),
		writable:      make(chan struct{}, 1),
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
// before, are written first, for up to netproxy.CloseLinger: Write and Close
// return once queued, and the peer would otherwise see a clean but cut
// stream. Meanwhile streams accept no data and no stream opens.
func (s *smuxSession) Close() error {
	s.mu.Lock()
	if !s.dead && !s.closing {
		s.closing = true
		if s.writing {
			s.flushed = make(chan struct{})
		}
	}
	flushed := s.flushed
	s.mu.Unlock()
	if flushed != nil {
		timer := time.NewTimer(netproxy.CloseLinger)
		select {
		case <-flushed:
		case <-s.die:
		case <-timer.C:
		}
		timer.Stop()
	}
	if !s.shutdown(io.ErrClosedPipe) {
		return io.ErrClosedPipe
	}
	return s.carrierCloseErr
}

// The carrier monitor records why the session failed.
func (*smuxSession) closeErr() error { return nil }

// smux v1 has no per-stream window to grow.
func (*smuxSession) saturated() bool { return false }

// shutdown kills the session with err once, dropping queued frames and closing
// the carrier, which stops both loops. It reports whether this call did so.
func (s *smuxSession) shutdown(err error) bool {
	first := false
	s.dieOnce.Do(func() {
		first = true
		s.mu.Lock()
		s.dead, s.err = true, err
		for s.ready.len() > 0 {
			st := s.ready.pop()
			for st.out.len() > 0 {
				putFrame(st.out.pop())
			}
			st.queued, st.scheduled = 0, false
		}
		s.blocked, s.datagrams = fifo[*smuxStream]{}, 0
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
			batch = s.takeLocked(batch[:0])
			if len(batch) == 0 {
				s.writing = false
				if s.flushed != nil {
					close(s.flushed)
					s.flushed = nil
				}
				s.mu.Unlock()
				break
			}
			s.mu.Unlock()
			err := s.write(batch)
			for i, f := range batch {
				putFrame(f)
				batch[i] = nil
			}
			if err != nil {
				// The carrier monitor has reported err.
				s.shutdown(err)
				return
			}
		}
	}
}

// takeLocked dequeues up to smuxWriteBatch bytes of frames, one frame per
// stream in turn, and lets writers waiting for queue space retry.
func (s *smuxSession) takeLocked(batch [][]byte) [][]byte {
	size := 0
	for size < smuxWriteBatch && s.ready.len() > 0 {
		st := s.ready.pop()
		f := st.out.pop()
		batch = append(batch, f)
		size += len(f)
		switch {
		case f[1] != smuxCmdPSH:
		case st.datagram:
			st.queued -= len(f)
			s.datagrams -= len(f)
		default:
			st.queued -= cap(f)
			s.queued -= cap(f)
			if st.need == 0 {
				// A writer waiting for the session is woken in turn.
				signal(st.writable)
			}
		}
		if st.out.len() > 0 {
			s.ready.push(st)
		} else {
			st.scheduled = false
		}
	}
	s.grantLocked()
	return batch
}

// grantLocked grants waiting writers the space they wait for in the session
// queue, in turn, as far as it lasts.
func (s *smuxSession) grantLocked() {
	for s.blocked.len() > 0 {
		st := s.blocked.peek()
		if st.need > 0 && s.queued > 0 && s.queued+st.need > smuxSessionQueue {
			return
		}
		s.blocked.pop()
		if st.need > 0 {
			s.queued += st.need
			st.reserved, st.need = st.need, 0
			s.waiting--
			signal(st.writable)
		}
	}
}

// write sends a batch with one carrier write, joining it into a pooled
// buffer only if the carrier cannot write vectors.
func (s *smuxSession) write(batch [][]byte) error {
	if s.buffers != nil {
		_, err := s.buffers.WriteBuffers(batch)
		s.conn.report(err)
		return err
	}
	size := 0
	for _, f := range batch {
		size += len(f)
	}
	buf := pool.GetBuffer(size)
	defer pool.PutBuffer(buf)
	joined := buf[:0]
	for _, f := range batch {
		joined = append(joined, f...)
	}
	_, err := s.conn.Write(joined)
	return err
}

// smuxStream is a client stream. Write queues frames, waiting only while the
// queue of the stream or the session is full; Read drains buffered frames and
// then reports the peer's FIN as io.EOF. A dead session fails both with its
// cause.
type smuxStream struct {
	session *smuxSession
	id      uint32
	done    chan struct{} // closed by Close

	// Send state, guarded by session.mu.
	out       fifo[[]byte]
	queued    int  // capacity of the data frames in out
	scheduled bool // in session.ready
	need      int  // the space its writer waits for in session.blocked
	reserved  int  // the space the session granted its writer
	closed    bool
	datagram  bool // queues datagrams: writes never wait but drop
	writable  chan struct{}

	// Receive state, guarded by rmu.
	rmu      sync.Mutex
	in       fifo[[]byte] // pooled frame payloads; in.peek()[inOff:] is next
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
	s := st.session
	st.out.push(f)
	if !st.scheduled {
		st.scheduled = true
		s.ready.push(st)
	}
	if !s.writing {
		s.writing = true
		signal(s.wake)
	}
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
		n := min(len(b), smuxMaxFrame)
		if err := st.writeFrame(b[:n]); err != nil {
			return written, err
		}
		written += n
		b = b[n:]
	}
	return written, nil
}

// writeFrame queues b as a frame, or appends it to the stream's last queued
// frame if b is short. It waits while the queue of the stream or the session
// is full, as counted in frame buffers; writers waiting for the session are
// granted space in turn.
func (st *smuxStream) writeFrame(b []byte) error {
	s := st.session
	f := newFrame(smuxHeaderSize+len(b), smuxCoalesce)
	copy(f[smuxHeaderSize:], b)
	smuxHeader(f, smuxCmdPSH, st.id)
	size := cap(f)
	var err error
	s.mu.Lock()
	for {
		wait := false
		switch {
		case st.closed:
			err = io.ErrClosedPipe
		case s.dead:
			err = s.err
		case s.closing:
			err = io.ErrClosedPipe
		case len(b) < smuxCoalesce && st.appendLocked(b):
		case st.queued > 0 && st.queued+size > smuxStreamQueue:
			wait = true
		case st.reserved == 0 && (st.need > 0 || s.waiting > 0 || s.queued > 0 && s.queued+size > smuxSessionQueue):
			wait = true
			if st.need == 0 {
				st.need = size
				s.waiting++
				s.blocked.push(st)
			}
		default:
			s.queued += size - st.reserved
			st.queued, st.reserved = st.queued+size, 0
			st.enqueueLocked(f)
			f = nil
			if st.queued < smuxStreamQueue {
				// Pass the turn on to another waiting writer.
				signal(st.writable)
			}
		}
		if !wait {
			break
		}
		s.mu.Unlock()
		select {
		case <-st.writable:
		case <-st.done:
		case <-s.die:
		case <-st.writeDeadline.Wait():
			err = os.ErrDeadlineExceeded
		}
		s.mu.Lock()
		if err != nil {
			break
		}
	}
	if st.need > 0 {
		// Leave the line; another writer of the stream may wait in it.
		st.need = 0
		s.waiting--
		signal(st.writable)
	}
	// Return space granted but not used.
	s.queued -= st.reserved
	st.reserved = 0
	s.grantLocked()
	s.mu.Unlock()
	if f != nil {
		putFrame(f)
	}
	return err
}

// appendLocked appends b to the stream's last queued frame if that carries
// data and has room, which its counted buffer holds already.
func (st *smuxStream) appendLocked(b []byte) bool {
	if st.out.len() == 0 {
		return false
	}
	tail := st.out.last()
	if (*tail)[1] != smuxCmdPSH || len(*tail)+len(b) > cap(*tail) {
		return false
	}
	*tail = append(*tail, b...)
	smuxHeader(*tail, smuxCmdPSH, st.id)
	return true
}

// writeDatagram queues data, a pooled buffer it takes over that starts with
// room for a frame header, unless it would exceed the datagram queues of the
// stream or the session; then it drops data with netproxy.ErrPacketDropped.
// It never waits. Data larger than a frame is split into frames that are
// queued or dropped together. A forced write is never dropped. Datagrams are
// counted in frame bytes.
func (st *smuxStream) writeDatagram(data []byte, force bool) error {
	var frames [3][]byte // a datagram's encoding never exceeds 3 frames
	parts := frames[:0]
	if len(data) <= smuxFullFrame {
		parts = append(parts, data)
	} else {
		for rest := data[smuxHeaderSize:]; len(rest) > 0; {
			part := newFrame(smuxHeaderSize+min(len(rest), smuxMaxFrame), 0)
			rest = rest[copy(part[smuxHeaderSize:], rest):]
			parts = append(parts, part)
		}
		pool.PutBuffer(data)
	}
	n := 0
	for _, part := range parts {
		smuxHeader(part, smuxCmdPSH, st.id)
		n += len(part)
	}
	s := st.session
	s.mu.Lock()
	var err error
	switch {
	case st.closed:
		err = io.ErrClosedPipe
	case s.dead:
		err = s.err
	case s.closing:
		err = io.ErrClosedPipe
	case !force && (st.queued > 0 && st.queued+n > smuxDatagramQueue || s.datagrams > 0 && s.datagrams+n > smuxSessionDatagramQueue):
		err = netproxy.ErrPacketDropped
	default:
		st.queued += n
		s.datagrams += n
		for _, part := range parts {
			st.enqueueLocked(part)
		}
	}
	s.mu.Unlock()
	if err != nil {
		for _, part := range parts {
			putFrame(part)
		}
	}
	return err
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
	st.in.push(data)
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
	for st.in.len() > 0 {
		data := st.in.pop()
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
		for n < len(b) && st.in.len() > 0 {
			data := st.in.peek()
			m := copy(b[n:], data[st.inOff:])
			n, st.inOff = n+m, st.inOff+m
			if st.inOff == len(data) {
				pool.PutBuffer(st.in.pop())
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
	delete(s.streams, st.id)
	if !s.dead {
		st.enqueueLocked(smuxControl(smuxCmdFIN, st.id))
	}
	s.mu.Unlock()
	close(st.done)
	st.rmu.Lock()
	st.released = true
	n := 0
	for st.in.len() > 0 {
		data := st.in.pop()
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
