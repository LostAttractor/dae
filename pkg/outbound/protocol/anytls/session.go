package anytls

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/infra/socks"
)

type session struct {
	lease      *netproxy.Lease
	failureMu  sync.Mutex
	rootCause  error
	conn       net.Conn
	writeGate  chan struct{}
	pendingFIN chan uint32
	// finsWritten is closed once flushFIN reached the marker Close queues
	// behind the FINs of streams closed before it.
	finsWritten chan struct{}

	streams    map[uint32]*stream
	streamLock sync.RWMutex
	// draining holds locally closed streams whose writer has yet to queue
	// their FIN; guarded by streamLock.
	draining map[*stream]struct{}

	padding      *atomic.Pointer[paddingFactory]
	sendPadding  bool
	pktCounter   uint32
	settingsSent bool

	sid       atomic.Uint32
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
	onIdle    func(*session)
}

func newSession(conn net.Conn, onIdle func(*session), dependency *netproxy.Lease) *session {
	s := &session{
		lease: netproxy.NewLease(netproxy.NewResourceRef(), dependency),
		conn:  conn, writeGate: make(chan struct{}, 1), pendingFIN: make(chan uint32, 256), finsWritten: make(chan struct{}),
		streams:     map[uint32]*stream{},
		draining:    map[*stream]struct{}{},
		onIdle:      onIdle,
		sendPadding: true,
	}
	s.padding = new(atomic.Pointer[paddingFactory])
	s.padding.Store(defaultPadding)
	s.writeGate <- struct{}{}
	go s.flushFIN()
	return s
}

func (s *session) newStreamContext(ctx context.Context, addr string) (*stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tgtAddr, err := socks.ParseAddr(addr)
	if err != nil {
		return nil, err
	}
	sid := s.sid.Add(1)
	stream := newStream(s, sid)
	s.streamLock.Lock()
	if s.closed.Load() || !s.lease.Valid() {
		s.streamLock.Unlock()
		stream.sessionClose()
		return nil, net.ErrClosed
	}
	s.streams[sid] = stream
	s.streamLock.Unlock()
	cleanup := func() { _ = stream.Close() }
	operationError := func(err error) error {
		if canceled := ctx.Err(); canceled != nil {
			failure := netproxy.ClassifyFailure(err)
			if failure.Scope == netproxy.ScopeSharedResource && failure.Origin != netproxy.OriginLocalCleanup {
				return errors.Join(err, canceled)
			}
			return canceled
		}
		return err
	}

	if _, err := s.writeFrame(cmdSYN, sid, tgtAddr, stream.writeStop, ctx.Done()); err != nil {
		cleanup()
		return nil, operationError(err)
	}

	if s.closed.Load() || stream.closed.Load() || !stream.lease.Valid() {
		cleanup()
		return nil, net.ErrClosed
	}

	if err := ctx.Err(); err != nil {
		cleanup()
		return nil, err
	}
	return stream, nil
}

func (s *session) removeStream(sid uint32) {
	s.streamLock.Lock()
	delete(s.streams, sid)
	idle := len(s.streams) == 0
	s.streamLock.Unlock()
	if idle && s.onIdle != nil {
		s.onIdle(s)
	}
}

func (s *session) run() (err error) {
	defer func() {
		if err != nil {
			err = s.fail(err, netproxy.OpRead)
		}
		_ = s.Close()
	}()
	// A single reusable buffer owns the current frame until dispatch finishes.
	// Reading every advertised body before dispatch also keeps control frames
	// from accidentally becoming the next frame header.
	body := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(body)
	var header [headerOverHeadSize]byte
	for {
		if _, err := io.ReadFull(s.conn, header[:]); err != nil {
			return err
		}
		command, id, length := header[0], binary.BigEndian.Uint32(header[1:]), int(binary.BigEndian.Uint16(header[5:]))
		body.Reset()
		body.Grow(length)
		if _, err := io.CopyN(body, s.conn, int64(length)); err != nil {
			return err
		}
		data := body.Bytes()
		s.streamLock.RLock()
		stream := s.streams[id]
		s.streamLock.RUnlock()
		switch command {
		case cmdWaste:
		case cmdPSH:
			if stream != nil && length != 0 {
				stream.receive(data)
			}
		case cmdFIN, cmdHeartRequest, cmdHeartResponse:
			if length != 0 {
				return protocolError(fmt.Sprintf("command %d cannot carry data", command))
			}
			if command == cmdFIN && stream != nil {
				_ = stream.remoteClose()
			}
			if command == cmdHeartRequest {
				if _, err := s.writeFrame(cmdHeartResponse, id, nil, nil, nil); err != nil {
					return err
				}
			}
		case cmdSYNACK:
			if length != 0 && stream != nil {
				stream.reject(fmt.Errorf("target rejected connection: %s", data))
			}
		case cmdAlert:
			return netproxy.WrapFailure(fmt.Errorf("AnyTLS peer alert: %s", data), netproxy.Failure{Layer: netproxy.LayerAnyTLS, Scope: netproxy.ScopeSharedResource, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonRejected})
		case cmdUpdatePaddingScheme:
			if padding := NewPaddingFactory(data); padding != nil {
				s.padding.Store(padding)
			}
		case cmdServerSettings:
			// Version 2 adds optional acknowledgements; opening remains optimistic.
		default:
			return protocolError(fmt.Sprintf("invalid server command %d", command))
		}
	}
}
func protocolError(detail string) error {
	return netproxy.WrapFailure(errors.New(detail), netproxy.Failure{Layer: netproxy.LayerAnyTLS, Scope: netproxy.ScopeSharedResource, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonProtocol})
}

// Close ends the session. A local Close, not one after a failure, first
// writes the FINs of streams closed before it, for up to netproxy.CloseLinger:
// the peer would otherwise see those streams end only with the session.
func (s *session) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		if s.lease.Valid() {
			s.writeFINs()
		}
		if s.lease != nil {
			cause := s.failure(net.ErrClosed, netproxy.OpClose)
			if netproxy.ClassifyFailure(cause).Scope != netproxy.ScopeSharedResource {
				cause = netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Resource: s.lease.Resource(), Scope: netproxy.ScopeSharedResource, Layer: netproxy.LayerAnyTLS, Phase: netproxy.OpClose, Origin: netproxy.OriginLocalCleanup})
			}
			s.lease.Invalidate(cause)
		}
		s.streamLock.Lock()
		streams := make([]*stream, 0, len(s.streams))
		for _, stream := range s.streams {
			streams = append(streams, stream)
		}
		s.streams = make(map[uint32]*stream)
		s.streamLock.Unlock()
		for _, stream := range streams {
			stream.sessionClose()
		}
		s.closeErr = s.conn.Close()
	})
	return s.closeErr
}

func (s *session) lockWrite(streamStop, operationStop <-chan struct{}) error {
	canceled := func() error {
		return netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Scope: netproxy.ScopeOperation, Layer: netproxy.LayerAnyTLS, Origin: netproxy.OriginLocalCleanup, Phase: netproxy.OpWrite})
	}
	select {
	case <-streamStop:
		return canceled()
	case <-operationStop:
		return canceled()
	case <-s.lease.Done():
		return s.failure(net.ErrClosed, netproxy.OpWrite)
	case <-s.writeGate:
	}
	select {
	case <-streamStop:
		s.writeGate <- struct{}{}
		return canceled()
	case <-operationStop:
		s.writeGate <- struct{}{}
		return canceled()
	case <-s.lease.Done():
		s.writeGate <- struct{}{}
		return s.failure(net.ErrClosed, netproxy.OpWrite)
	default:
	}
	return nil
}
func (s *session) writeLocked(b []byte) (n int, err error) {
	defer func() {
		if err != nil {
			err = s.fail(err, netproxy.OpWrite)
			_ = s.Close()
		}
	}()

	total := len(b)
	write := func(data []byte) error {
		n, err := s.conn.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		return err
	}
	if s.sendPadding {
		s.pktCounter++
		padding := s.padding.Load()
		if s.pktCounter >= padding.Stop {
			s.sendPadding = false
		} else {
			record := pool.GetBytesBuffer()
			defer pool.PutBytesBuffer(record)
			for _, size := range padding.GenerateRecordPayloadSizes(s.pktCounter) {
				if size == CheckMark {
					if len(b) == 0 {
						break
					}
					continue
				}
				record.Reset()
				count := min(size, len(b))
				_, _ = record.Write(b[:count])
				b = b[count:]
				if waste := size - count - headerOverHeadSize; waste >= 0 {
					// Every byte exposed by a pooled buffer is initialized before sending.
					appendFrame(record, cmdWaste, 0, make([]byte, waste))
				}
				if err := write(record.Bytes()); err != nil {
					return 0, err
				}
			}
		}
	}
	if len(b) != 0 {
		if err := write(b); err != nil {
			return 0, err
		}
	}
	return total, nil
}

func (s *session) fail(err error, phase netproxy.Operation) error {
	if err == nil {
		return nil
	}
	s.failureMu.Lock()
	defer s.failureMu.Unlock()
	if s.rootCause != nil {
		return s.rootCause
	}
	if parentCause := s.lease.Cause(); parentCause != nil && netproxy.ClassifyFailure(parentCause).Origin != netproxy.OriginLocalCleanup {
		err = parentCause
	}
	fact := netproxy.ClassifyFailure(err)
	fact.Resource = s.lease.Resource()
	fact.Scope, fact.Phase = netproxy.ScopeSharedResource, phase
	if fact.Layer == netproxy.LayerUnknown {
		fact.Layer = netproxy.LayerAnyTLS
	}
	if err == io.EOF {
		fact.Reason = netproxy.ReasonClosed
	}
	s.rootCause = netproxy.WrapFailure(err, fact)
	s.lease.Abort(s.rootCause)
	return s.rootCause
}
func (s *session) failure(err error, phase netproxy.Operation) error {
	s.failureMu.Lock()
	cause := s.rootCause
	s.failureMu.Unlock()
	if cause != nil {
		return cause
	}
	if parentCause := s.lease.Cause(); parentCause != nil && netproxy.ClassifyFailure(parentCause).Origin != netproxy.OriginLocalCleanup {
		fact := netproxy.ClassifyFailure(parentCause)
		fact.Resource, fact.Scope = s.lease.Resource(), netproxy.ScopeSharedResource
		if fact.Layer == netproxy.LayerUnknown {
			fact.Layer = netproxy.LayerAnyTLS
		}
		return netproxy.WrapFailure(parentCause, fact)
	}
	fact := netproxy.ClassifyFailure(err)
	fact.Resource, fact.Phase = s.lease.Resource(), phase
	if fact.Scope == netproxy.ScopeUnknown {
		fact.Scope = netproxy.ScopeStream
	}
	if fact.Layer == netproxy.LayerUnknown {
		fact.Layer = netproxy.LayerAnyTLS
	}
	return netproxy.WrapFailure(err, fact)
}

// writeFINs waits until the writers of locally closed streams have queued
// their FINs, then queues a marker (stream 0) behind them and waits until
// flushFIN reaches it, all within netproxy.CloseLinger.
func (s *session) writeFINs() {
	timer := time.NewTimer(netproxy.CloseLinger)
	defer timer.Stop()
	s.streamLock.RLock()
	writers := make([]<-chan struct{}, 0, len(s.draining))
	for stream := range s.draining {
		writers = append(writers, stream.writeDone)
	}
	s.streamLock.RUnlock()
	for _, done := range writers {
		select {
		case <-done:
		case <-s.lease.Done():
			return
		case <-timer.C:
			return
		}
	}
	select {
	case s.pendingFIN <- 0:
	case <-s.lease.Done():
		return
	case <-timer.C:
		return
	}
	select {
	case <-s.finsWritten:
	case <-s.lease.Done():
	case <-timer.C:
	}
}

// A single bounded control queue prevents closed streams from leaving one
// goroutine each waiting behind a blocked shared write. A closing session
// still queues FINs until Close invalidates its lease.
func (s *session) scheduleFIN(id uint32) {
	if !s.lease.Valid() {
		return
	}
	select {
	case s.pendingFIN <- id:
		return
	case <-s.lease.Done():
		return
	default:
	}
	_ = s.fail(netproxy.WrapFailure(errors.New("AnyTLS close-frame queue exhausted"), netproxy.Failure{Scope: netproxy.ScopeSharedResource, Layer: netproxy.LayerAnyTLS, Origin: netproxy.OriginLocalProtocol, Reason: netproxy.ReasonCapacity}), netproxy.OpClose)
	_ = s.Close()
}
func (s *session) flushFIN() {
	for {
		select {
		case <-s.lease.Done():
			return
		case id := <-s.pendingFIN:
			if id == 0 { // Close's marker: the FINs queued before it are written
				close(s.finsWritten)
				return
			}
			if _, err := s.writeFrame(cmdFIN, id, nil, s.lease.Done(), nil); err != nil {
				return
			}
		}
	}
}
