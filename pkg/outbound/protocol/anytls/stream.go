package anytls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/infra/socks"
)

type stream struct {
	*session
	receiveMu    sync.Mutex
	received     *bytes.Buffer
	receiveErr   error
	receiveReady chan struct{}
	readDeadline protocol.Deadline

	writeRequests   chan streamWriteRequest
	writeAdmission  chan struct{}
	writeStop       chan struct{}
	writeDone       chan struct{}
	writeStopOnce   sync.Once
	sendFIN         atomic.Bool
	deadlineMu      sync.Mutex
	writeDeadline   time.Time
	deadlineChanged chan struct{}
	readMutex       sync.Mutex

	closed        atomic.Bool
	lease         *netproxy.Lease
	failureMu     sync.Mutex
	terminalCause error

	localClosed atomic.Bool
	id          uint32
}

type streamWriteResult struct {
	n   int
	err error
}
type streamWriteRequest struct {
	payload *bytes.Buffer
	write   func([]byte, <-chan struct{}) (int, error)
	stop    <-chan struct{}
	done    chan streamWriteResult
}

func newStream(session *session, id uint32) *stream {
	c := &stream{lease: session.lease.NewStream(), session: session, id: id,
		receiveReady: make(chan struct{}, 1), readDeadline: protocol.MakeDeadline(),
		writeRequests: make(chan streamWriteRequest), writeAdmission: make(chan struct{}, 1), writeStop: make(chan struct{}), writeDone: make(chan struct{}), deadlineChanged: make(chan struct{})}
	c.writeAdmission <- struct{}{}
	go c.writeLoop()
	return c
}
func (c *stream) Write(b []byte) (n int, err error) {
	defer func() { err = c.streamFailure(err, netproxy.OpWrite) }()
	return c.writeOperation(b, func(payload []byte, stop <-chan struct{}) (int, error) {
		return c.session.writeFrame(cmdPSH, c.id, payload, c.writeStop, stop)
	})
}

// One worker per stream owns all writes, including FIN. A timed-out caller
// never starts a second blocked writer or retains ownership of its input bytes.
func (c *stream) writeLoop() {
	defer close(c.writeDone)
	finish := func() {
		if c.sendFIN.Load() && !c.session.closed.Load() && c.session.lease.Valid() {
			c.session.scheduleFIN(c.id)
		}
	}
	for {
		if c.closed.Load() {
			finish()
			return
		}
		select {
		case <-c.writeStop:
			finish()
			return
		case request := <-c.writeRequests:
			canceled := c.closed.Load()
			select {
			case <-request.stop:
				canceled = true
			default:
			}
			if canceled {
				pool.PutBytesBuffer(request.payload)
				request.done <- streamWriteResult{err: net.ErrClosed}
				c.writeAdmission <- struct{}{}
				continue
			}
			n, err := request.write(request.payload.Bytes(), request.stop)
			pool.PutBytesBuffer(request.payload)
			request.done <- streamWriteResult{n: n, err: err}
			c.writeAdmission <- struct{}{}
		}
	}
}
func (c *stream) stopWrites() { c.writeStopOnce.Do(func() { close(c.writeStop) }) }
func (c *stream) writeOperation(p []byte, write func([]byte, <-chan struct{}) (int, error)) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	operationStop := make(chan struct{})
	defer close(operationStop)
	request := streamWriteRequest{write: write, done: make(chan streamWriteResult, 1), stop: operationStop}
	admitted, sent := false, false
	defer func() {
		if admitted && !sent {
			pool.PutBytesBuffer(request.payload)
			c.writeAdmission <- struct{}{}
		}
	}()
	for {
		c.deadlineMu.Lock()
		deadline, changed := c.writeDeadline, c.deadlineChanged
		c.deadlineMu.Unlock()
		if !deadline.IsZero() && !deadline.After(time.Now()) {
			return 0, os.ErrDeadlineExceeded
		}
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		var send chan streamWriteRequest
		var admission <-chan struct{}
		if !admitted {
			admission = c.writeAdmission
		} else if !sent {
			send = c.writeRequests
		}
		select {
		case <-admission:
			admitted = true
			// Only an admitted operation owns a copy. Other concurrent callers wait
			// on their own stack; a timed-out in-flight write retains this one token.
			request.payload = pool.GetBytesBuffer()
			_, _ = request.payload.Write(p)
		case send <- request:
			sent = true
		case result := <-request.done:
			if timer != nil {
				timer.Stop()
			}
			return result.n, result.err
		case <-c.writeStop:
			if timer != nil {
				timer.Stop()
			}
			return 0, net.ErrClosed
		case <-changed:
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (c *stream) Read(b []byte) (n int, err error) {
	defer func() { err = c.streamFailure(err, netproxy.OpRead) }()
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	return c.read(b)
}

func (c *stream) remoteClose() error {
	c.stopWrites()
	c.lease.Invalidate(netproxy.WrapFailure(io.EOF, netproxy.Failure{Resource: c.lease.Resource(), Stream: c.lease.Stream(), Scope: netproxy.ScopeStream, Layer: netproxy.LayerAnyTLS, Reason: netproxy.ReasonClosed}))
	if c.closed.CompareAndSwap(false, true) {
		c.session.removeStream(c.id)
		c.stopReads(io.EOF, false)
	}
	return nil
}

func (c *stream) Close() error {
	c.localClosed.Store(true)
	c.stopReads(net.ErrClosed, true)
	c.sendFIN.Store(true)
	c.lease.Invalidate(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Resource: c.lease.Resource(), Stream: c.lease.Stream(), Scope: netproxy.ScopeStream, Layer: netproxy.LayerAnyTLS, Origin: netproxy.OriginLocalCleanup}))
	if c.closed.CompareAndSwap(false, true) {
		c.session.removeStream(c.id)
	}
	c.stopWrites()
	return nil
}
func (c *stream) sessionClose() {
	cause := netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Resource: c.lease.Resource(), Stream: c.lease.Stream(), Scope: netproxy.ScopeStream, Layer: netproxy.LayerAnyTLS, Origin: netproxy.OriginLocalCleanup})
	cause = c.session.failure(cause, netproxy.OpRead)
	// A peer failure follows frames already accepted by the reader. Preserve
	// those bytes until consumed; explicit local cleanup releases them at once.
	c.stopReads(cause, netproxy.ClassifyFailure(cause).Origin == netproxy.OriginLocalCleanup)
	c.lease.Invalidate(cause)
	c.closed.Store(true)
	c.stopWrites()
}

func (c *stream) LocalAddr() net.Addr {
	return c.session.conn.LocalAddr()
}

func (c *stream) RemoteAddr() net.Addr {
	return c.session.conn.RemoteAddr()
}

func (c *stream) SetDeadline(t time.Time) error {
	_ = c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}
func (c *stream) SetReadDeadline(t time.Time) error { c.readDeadline.Set(t); return nil }
func (c *stream) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	close(c.deadlineChanged)
	c.deadlineChanged = make(chan struct{})
	c.deadlineMu.Unlock()
	return nil
}

// UDP-over-TCP v2 connected mode: one SOCKS destination followed by
// uint16-length datagrams. Partial reads retain their framing across deadlines.
type packetStream struct {
	*stream
	addr         string
	udpWriteAddr bool // stream writer owns this flag
	header       [2]byte
	headerRead   int
	packet       *bytes.Buffer // readMutex owns the partially received packet
}

func (ps *packetStream) ReadFrom(p []byte) (n int, from net.Addr, err error) {
	defer func() { err = ps.streamFailure(err, netproxy.OpRead) }()
	ps.readMutex.Lock()
	defer ps.readMutex.Unlock()
	for ps.headerRead < len(ps.header) {
		count, e := ps.read(ps.header[ps.headerRead:])
		ps.headerRead += count
		if e != nil {
			return 0, nil, e
		}
	}
	length := int(binary.BigEndian.Uint16(ps.header[:]))
	if ps.packet == nil {
		ps.packet = pool.GetBytesBuffer()
		ps.packet.Grow(length)
	}
	for ps.packet.Len() < length {
		data := ps.packet.AvailableBuffer()[:length-ps.packet.Len()]
		count, e := ps.read(data)
		_, _ = ps.packet.Write(data[:count])
		if e != nil {
			return 0, nil, e
		}
	}
	n = copy(p, ps.packet.Bytes())
	pool.PutBytesBuffer(ps.packet)
	ps.packet = nil
	ps.headerRead = 0
	if n < length {
		return n, nil, io.ErrShortBuffer
	}
	return n, netproxy.NewAddr("udp", ps.addr), nil
}
func (ps *packetStream) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	defer func() { err = ps.streamFailure(err, netproxy.OpWrite) }()
	if len(p) > 65535 {
		return 0, netproxy.WrapFailure(io.ErrShortBuffer, netproxy.Failure{Scope: netproxy.ScopeOperation, Origin: netproxy.OriginCaller, Reason: netproxy.ReasonCapacity})
	}
	if addr == nil || addr.String() != ps.addr {
		return 0, netproxy.WrapFailure(fmt.Errorf("AnyTLS UDP connection targets %s", ps.addr), netproxy.Failure{Scope: netproxy.ScopeOperation, Origin: netproxy.OriginCaller, Reason: netproxy.ReasonRejected})
	}
	return ps.writeOperation(p, ps.writePacket)
}
func (ps *packetStream) writePacket(p []byte, stop <-chan struct{}) (int, error) {
	data := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(data)
	if !ps.udpWriteAddr {
		target, err := socks.ParseAddr(ps.addr)
		if err != nil {
			return 0, err
		}
		_ = data.WriteByte(1)
		_, _ = data.Write(target)
	}
	_ = data.WriteByte(byte(len(p) >> 8))
	_ = data.WriteByte(byte(len(p)))
	_, _ = data.Write(p)
	if _, err := ps.session.writeFrame(cmdPSH, ps.id, data.Bytes(), ps.writeStop, stop); err != nil {
		return 0, err
	}
	ps.udpWriteAddr = true
	return len(p), nil
}
func (ps *packetStream) Close() error {
	err := ps.stream.Close()
	ps.readMutex.Lock()
	if ps.packet != nil {
		pool.PutBytesBuffer(ps.packet)
		ps.packet = nil
	}
	ps.readMutex.Unlock()
	return err
}

func (c *stream) DependencyLease() *netproxy.Lease { return c.lease }
func (c *stream) streamFailure(err error, phase netproxy.Operation) error {
	if err == nil || phase == netproxy.OpRead && err == io.EOF {
		return err
	}
	c.failureMu.Lock()
	terminal := c.terminalCause
	c.failureMu.Unlock()
	if terminal != nil {
		return terminal
	}
	if c.localClosed.Load() && (err == net.ErrClosed || err == io.ErrClosedPipe) {
		return netproxy.WrapFailure(err, netproxy.Failure{Resource: c.lease.Resource(), Stream: c.lease.Stream(), Scope: netproxy.ScopeStream, Layer: netproxy.LayerAnyTLS, Phase: phase, Origin: netproxy.OriginLocalCleanup})
	}
	err = c.session.failure(err, phase)
	fact := netproxy.ClassifyFailure(err)
	fact.Stream, fact.Phase = c.lease.Stream(), phase
	wrapped := netproxy.WrapFailure(err, fact)
	if fact.Scope != netproxy.ScopeOperation {
		c.lease.Invalidate(wrapped)
	}
	return wrapped
}

func (c *stream) reject(cause error) {
	failure := netproxy.WrapFailure(cause, netproxy.Failure{Resource: c.lease.Resource(), Stream: c.lease.Stream(), Scope: netproxy.ScopeStream, Layer: netproxy.LayerAnyTLS, Origin: netproxy.OriginTarget, Reason: netproxy.ReasonRejected, Phase: netproxy.OpDial})
	c.failStream(failure)
}

func (c *stream) failStream(failure error) {
	c.failureMu.Lock()
	c.terminalCause = failure
	c.failureMu.Unlock()
	c.lease.Invalidate(failure)
	c.stopReads(failure, true)
	c.stopWrites()
	if c.closed.CompareAndSwap(false, true) {
		c.session.removeStream(c.id)
	}
}
