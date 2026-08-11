package control

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
)

// dnsPendingQuery tracks an in-flight query on a DnsManager connection.
// It carries the original question so feed() can drop late/stray responses
// whose transaction ID happens to collide with a reused slot.
type dnsPendingQuery struct {
	ch    chan *dnsmessage.Msg
	query *dnsmessage.Msg
}

var (
	errDnsManagerUnavailable  = errors.New("DNS manager unavailable before sending")
	errDnsExchangeInterrupted = errors.New("DNS exchange interrupted after admission")
)

type dnsManagerTerminalError struct{ err error }

type dnsManagerPhase uint8

const (
	dnsManagerOpen dnsManagerPhase = iota
	dnsManagerDraining
	dnsManagerClosed
)

type DnsManager struct {
	conn        net.Conn
	terminalErr atomic.Pointer[dnsManagerTerminalError]
	writeMu     sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc

	done        chan struct{}
	runDone     chan struct{}
	writersDone chan struct{}
	closeErr    error

	stateMu        sync.Mutex
	pending        map[uint16]*dnsPendingQuery
	lastResponse   time.Time
	phase          dnsManagerPhase
	writers        int
	idleTimer      *time.Timer
	allowIdleClose func() bool

	timeout time.Duration
	// idleTimeout bounds how long the connection may go without delivering
	// a response before the recv loop closes it.
	idleTimeout time.Duration
}

func NewDnsManager(conn net.Conn) *DnsManager {
	return newDnsManager(conn, consts.DefaultDNSTimeout, 2*consts.DefaultDNSTimeout)
}

func newDnsManager(conn net.Conn, timeout, idleTimeout time.Duration) *DnsManager {
	return newDnsManagerWithIdlePolicy(conn, timeout, idleTimeout, nil)
}

func newDnsManagerWithIdlePolicy(
	conn net.Conn,
	timeout, idleTimeout time.Duration,
	allowIdleClose func() bool,
) *DnsManager {
	ctx, cancel := context.WithCancel(context.TODO())
	m := &DnsManager{
		conn:           conn,
		ctx:            ctx,
		cancel:         cancel,
		timeout:        timeout,
		idleTimeout:    idleTimeout,
		pending:        make(map[uint16]*dnsPendingQuery),
		lastResponse:   time.Now(),
		done:           make(chan struct{}),
		runDone:        make(chan struct{}),
		writersDone:    make(chan struct{}),
		allowIdleClose: allowIdleClose,
	}
	m.stateMu.Lock()
	m.idleTimer = time.AfterFunc(idleTimeout, m.reapIdle)
	m.stateMu.Unlock()
	go func() {
		defer close(m.runDone)
		if err := m.run(); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				// Idle reaping is routine, not an error.
				log.WithError(err).Debug("DNS manager closed a silent connection")
				return
			}
			if errors.Is(err, net.ErrClosed) {
				log.WithError(err).Debug("DNS manager connection closed")
				return
			}
			log.WithError(err).Error("DNS manager recv loop exited")
		}
	}()
	return m
}

func (m *DnsManager) reapIdle() {
	m.stateMu.Lock()
	if m.phase != dnsManagerOpen || len(m.pending) != 0 {
		m.stateMu.Unlock()
		return
	}
	remaining := m.idleTimeout - time.Since(m.lastResponse)
	if remaining > 0 {
		// Stop can lose a race with an already queued callback. In that case,
		// preserve the newer activity and re-arm from its timestamp.
		m.idleTimer.Reset(remaining)
		m.stateMu.Unlock()
		return
	}
	m.stateMu.Unlock()

	// The policy can take the owning forwarder's lock. Do not call it while
	// holding stateMu, because manager admission takes the locks in reverse.
	if m.allowIdleClose != nil && !m.allowIdleClose() {
		m.stateMu.Lock()
		if m.phase == dnsManagerOpen && len(m.pending) == 0 {
			m.idleTimer.Reset(m.idleTimeout)
		}
		m.stateMu.Unlock()
		return
	}

	m.stateMu.Lock()
	if m.phase == dnsManagerOpen && len(m.pending) == 0 {
		remaining = m.idleTimeout - time.Since(m.lastResponse)
		if remaining <= 0 {
			m.markClosedLocked()
		} else {
			m.idleTimer.Reset(remaining)
		}
	}
	m.stateMu.Unlock()
}

func (m *DnsManager) markClosedLocked() {
	if m.phase == dnsManagerClosed {
		return
	}
	m.phase = dnsManagerClosed
	m.cancel()
	m.idleTimer.Stop()
	m.finishWritersLocked()
	go func() {
		m.closeErr = m.conn.Close()
		if errors.Is(m.closeErr, net.ErrClosed) {
			m.closeErr = nil
		}
		<-m.runDone
		<-m.writersDone
		close(m.done)
	}()
}

func (m *DnsManager) finishWritersLocked() {
	if m.phase == dnsManagerClosed && m.writers == 0 {
		close(m.writersDone)
	}
}

func (m *DnsManager) beginWrite() bool {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	if m.phase == dnsManagerClosed {
		return false
	}
	m.writers++
	return true
}

func (m *DnsManager) endWrite() {
	m.stateMu.Lock()
	m.writers--
	m.finishWritersLocked()
	m.stateMu.Unlock()
}

func (m *DnsManager) startClose() {
	m.stateMu.Lock()
	m.markClosedLocked()
	m.stateMu.Unlock()
}

func (m *DnsManager) reserveQuery(pending *dnsPendingQuery, startId uint16) (uint16, error) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	if m.phase != dnsManagerOpen {
		return 0, m.unavailableError()
	}
	for offset := 0; offset < 1<<16; offset++ {
		wireId := startId + uint16(offset)
		if _, loaded := m.pending[wireId]; loaded {
			continue
		}
		pending.query.Id = wireId
		if len(m.pending) == 0 {
			m.idleTimer.Stop()
		}
		m.pending[wireId] = pending
		return wireId, nil
	}
	return 0, oops.Errorf("DNSManager: no free DNS transaction ID")
}

func (m *DnsManager) endQuery(wireId uint16) {
	m.stateMu.Lock()
	delete(m.pending, wireId)
	if len(m.pending) == 0 && m.phase != dnsManagerClosed {
		remaining := m.idleTimeout - time.Since(m.lastResponse)
		if m.phase == dnsManagerDraining || remaining <= 0 {
			m.markClosedLocked()
		} else {
			m.idleTimer.Reset(remaining)
		}
	}
	m.stateMu.Unlock()
}

func (m *DnsManager) recordResponse() {
	m.stateMu.Lock()
	m.lastResponse = time.Now()
	m.stateMu.Unlock()
}

func (m *DnsManager) retire() {
	m.stateMu.Lock()
	if m.phase == dnsManagerOpen {
		m.phase = dnsManagerDraining
	}
	if m.phase == dnsManagerDraining && len(m.pending) == 0 {
		m.markClosedLocked()
	}
	m.stateMu.Unlock()
}

func (m *DnsManager) run() error {
	for {
		data, err := m.read()
		if err != nil {
			if m.ctx.Err() != nil {
				return nil
			}
			m.terminalErr.CompareAndSwap(nil, &dnsManagerTerminalError{err: err})
			m.startClose()
			return err
		}
		var msg dnsmessage.Msg
		err = netutils.UnpackDnsMessage(data, &msg)
		pool.PutBuffer(data)
		if err != nil {
			// Invalid messages do not extend the lifetime of a silent upstream.
			continue
		}
		m.feed(&msg)
	}
}

func (m *DnsManager) read() (data []byte, err error) {
	lenBuf := pool.GetBuffer(2)
	defer pool.PutBuffer(lenBuf)
	if _, err = io.ReadFull(m.conn, lenBuf); err != nil {
		return nil, oops.Wrapf(err, "failed to read DNS resp payload length")
	}
	data = pool.GetBuffer(int(binary.BigEndian.Uint16(lenBuf)))
	if _, err = io.ReadFull(m.conn, data); err != nil {
		pool.PutBuffer(data)
		return nil, oops.Wrapf(err, "failed to read DNS resp payload")
	}
	return data, nil
}

func (m *DnsManager) feed(msg *dnsmessage.Msg) {
	m.stateMu.Lock()
	pending, ok := m.pending[msg.Id]
	m.stateMu.Unlock()
	if !ok {
		// Ignore messages from unknown sessions.
		return
	}
	if err := netutils.ValidateDnsResponseAllowEmptyQuestion(pending.query, msg, pending.query.Id); err != nil {
		log.Debugf("DNSManager: drop invalid response: %v", err)
		return
	}
	m.recordResponse()

	select {
	case pending.ch <- msg:
	default:
		// Channel full, drop the message.
	}
}

func (m *DnsManager) Close() error {
	m.startClose()
	return m.waitClosed(context.Background())
}

func (m *DnsManager) IsClosed() bool {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	return m.phase != dnsManagerOpen
}

func (m *DnsManager) canReplace() bool {
	select {
	case <-m.writersDone:
		return true
	default:
		return false
	}
}

func (m *DnsManager) closeComplete() bool {
	select {
	case <-m.done:
		return true
	default:
		return false
	}
}

func (m *DnsManager) waitClosed(ctx context.Context) error {
	if m.closeComplete() {
		return m.closeErr
	}
	select {
	case <-m.done:
		return m.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *DnsManager) managerError(class error) error {
	if terminal := m.terminalErr.Load(); terminal != nil {
		return fmt.Errorf("%w: %w", class, terminal.err)
	}
	return fmt.Errorf("%w: %w", class, net.ErrClosed)
}

func (m *DnsManager) unavailableError() error { return m.managerError(errDnsManagerUnavailable) }
func (m *DnsManager) interruptedError() error { return m.managerError(errDnsExchangeInterrupted) }

func (m *DnsManager) Resolve(msg *dnsmessage.Msg) error {
	return m.ResolveContext(context.Background(), msg)
}

func (m *DnsManager) ResolveContext(ctx context.Context, msg *dnsmessage.Msg) error {
	if msg.Response {
		panic("DNSManager: DNS request expected but DNS response received")
	}
	if len(msg.Question) == 0 {
		panic("DNSManager: no question in dns message")
	}
	if log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("DNSManager: Resolve %v %v", msg.Question[0].Name, msg.Question[0].Qtype)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.IsClosed() {
		return m.unavailableError()
	}

	originalId := msg.Id
	wireQuery := msg.Copy()
	pending := &dnsPendingQuery{
		ch:    make(chan *dnsmessage.Msg, 1),
		query: wireQuery,
	}
	var randomId [2]byte
	if _, err := rand.Read(randomId[:]); err != nil {
		return fmt.Errorf("generate DNS transaction ID: %w", err)
	}
	newId, err := m.reserveQuery(pending, binary.BigEndian.Uint16(randomId[:]))
	if err != nil {
		return err
	}
	defer m.endQuery(newId)

	data, err := wireQuery.Pack()
	if err != nil {
		return oops.Wrapf(err, "pack DNS packet")
	}
	if err := netutils.CheckDnsMessageSize(len(data)); err != nil {
		return err
	}

	parentCtx := ctx
	ctx, cancel := context.WithTimeout(parentCtx, m.timeout)
	defer cancel()

	// DNS over TCP frames each message with a two-byte length prefix. Writes
	// are never retransmitted on a live stream (RFC 7766 section 6.2.1).
	payload := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(payload[:2], uint16(len(data)))
	copy(payload[2:], data)
	type writeResult struct {
		n   int
		err error
	}
	writeCh := make(chan writeResult, 1)
	var writeFinished atomic.Bool
	var writeStarted atomic.Bool
	var writeBytes atomic.Int64
	if !m.beginWrite() {
		return m.unavailableError()
	}
	go func() {
		m.writeMu.Lock()
		var n int
		var writeErr error
		if err := ctx.Err(); err != nil {
			writeErr = err
		} else if m.ctx.Err() != nil {
			writeErr = m.unavailableError()
		} else {
			writeStarted.Store(true)
			n, writeErr = m.conn.Write(payload)
			if writeErr == nil && n != len(payload) {
				writeErr = io.ErrShortWrite
			}
		}
		m.writeMu.Unlock()
		writeBytes.Store(int64(n))
		writeFinished.Store(true)
		m.endWrite()
		if writeErr != nil {
			if !errors.Is(writeErr, context.Canceled) && !errors.Is(writeErr, context.DeadlineExceeded) &&
				!errors.Is(writeErr, errDnsManagerUnavailable) && !errors.Is(writeErr, errDnsExchangeInterrupted) {
				writeErr = oops.Wrapf(writeErr, "failed to write DNS req")
				m.terminalErr.CompareAndSwap(nil, &dnsManagerTerminalError{err: writeErr})
				m.startClose()
			}
		}
		writeCh <- writeResult{n: n, err: writeErr}
	}()

	for {
		select {
		case <-m.ctx.Done():
			if err := parentCtx.Err(); err != nil {
				return err
			}
			if !writeStarted.Load() || (writeFinished.Load() && writeBytes.Load() == 0) {
				return m.unavailableError()
			}
			return m.interruptedError()
		case <-ctx.Done():
			if writeFinished.Load() {
				m.retire()
			} else {
				// A timed-out stream write may have emitted a partial frame.
				m.startClose()
			}
			if err := parentCtx.Err(); err != nil {
				return err
			}
			if terminal := m.terminalErr.Load(); terminal != nil {
				return m.interruptedError()
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return oops.Wrapf(context.DeadlineExceeded, "dns query timeout")
			}
			return ctx.Err()
		case result := <-writeCh:
			if result.err == nil {
				continue
			}
			if err := parentCtx.Err(); err != nil {
				m.retire()
				return err
			}
			if ctx.Err() != nil {
				m.startClose()
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					return oops.Wrapf(context.DeadlineExceeded, "dns query timeout")
				}
				return ctx.Err()
			}
			m.startClose()
			if result.n == 0 {
				return m.unavailableError()
			}
			return m.interruptedError()
		case recvMsg := <-pending.ch:
			if err := parentCtx.Err(); err != nil {
				if writeFinished.Load() {
					m.retire()
				} else {
					m.startClose()
				}
				return err
			}
			*msg = *recvMsg
			msg.Id = originalId
			return nil
		}
	}
}
