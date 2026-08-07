package control

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
)

// dnsPendingQuery tracks an in-flight query on a DnsManager connection.
// It carries the original question so feed() can drop late/stray responses
// whose transaction ID happens to collide with a reused slot.
type dnsPendingQuery struct {
	ch     chan *dnsmessage.Msg
	query  *dnsmessage.Msg
	wireId uint16
}

type DnsManager struct {
	conn          net.Conn
	recvMap       sync.Map // map[uint16]*dnsPendingQuery
	nextId        atomic.Uint32
	ctx           context.Context
	cancel        context.CancelFunc
	closeDone     chan struct{}
	closeDoneOnce sync.Once

	stateMu      sync.Mutex
	pending      int
	lastResponse time.Time
	stale        bool
	closed       bool
	idleTimer    *time.Timer

	stream  bool
	timeout time.Duration
	// idleTimeout bounds how long the connection may go without delivering
	// a response before the recv loop closes it.
	idleTimeout time.Duration
}

func NewDnsManager(conn net.Conn, stream bool) *DnsManager {
	return newDnsManager(conn, stream, consts.DefaultDNSTimeout, 2*consts.DefaultDNSTimeout)
}

func newDnsManager(conn net.Conn, stream bool, timeout, idleTimeout time.Duration) *DnsManager {
	ctx, cancel := context.WithCancel(context.TODO())
	m := &DnsManager{
		conn:         conn,
		ctx:          ctx,
		cancel:       cancel,
		stream:       stream,
		timeout:      timeout,
		idleTimeout:  idleTimeout,
		lastResponse: time.Now(),
		closeDone:    make(chan struct{}),
	}
	m.idleTimer = time.AfterFunc(idleTimeout, m.reapIdle)
	// Start the transaction ID counter at a random offset: sequential IDs
	// from zero are trivially predictable to an off-path spoofer.
	m.nextId.Store(fastrand.Uint32())
	go func() {
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
	closeNow := false
	if !m.closed && m.pending == 0 {
		remaining := m.idleTimeout - time.Since(m.lastResponse)
		if remaining <= 0 {
			closeNow = m.markClosedLocked()
		} else {
			// Stop can lose a race with an already queued callback. In that
			// case, preserve the newer activity and re-arm from its timestamp.
			m.idleTimer.Reset(remaining)
		}
	}
	m.stateMu.Unlock()
	if closeNow {
		_ = m.closeConn()
	}
}

func (m *DnsManager) markClosedLocked() bool {
	if m.closed {
		return false
	}
	m.closed = true
	m.cancel()
	m.idleTimer.Stop()
	return true
}

func (m *DnsManager) closeConn() error {
	err := m.conn.Close()
	m.closeDoneOnce.Do(func() { close(m.closeDone) })
	return err
}

func (m *DnsManager) beginQuery() bool {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	if m.closed || m.stale {
		return false
	}
	if m.pending == 0 {
		m.idleTimer.Stop()
	}
	m.pending++
	return true
}

func (m *DnsManager) endQuery() {
	m.stateMu.Lock()
	m.pending--
	closeNow := false
	if m.pending == 0 && !m.closed {
		remaining := m.idleTimeout - time.Since(m.lastResponse)
		if m.stale || remaining <= 0 {
			closeNow = m.markClosedLocked()
		} else {
			m.idleTimer.Reset(remaining)
		}
	}
	m.stateMu.Unlock()
	if closeNow {
		_ = m.closeConn()
	}
}

func (m *DnsManager) recordResponse() {
	m.stateMu.Lock()
	m.lastResponse = time.Now()
	m.stale = false
	m.stateMu.Unlock()
}

func (m *DnsManager) markStale() {
	m.stateMu.Lock()
	m.stale = true
	closeNow := m.pending <= 1 && m.markClosedLocked()
	m.stateMu.Unlock()
	if closeNow {
		_ = m.closeConn()
	}
}

func (m *DnsManager) run() error {
	for {
		data, err := m.read()
		if err != nil {
			m.Close()
			return err
		}
		var msg dnsmessage.Msg
		err = msg.Unpack(data)
		pool.PutBuffer(data)
		if err != nil {
			// Invalid message, this is fine - just wait for the next
			continue
		}
		m.feed(&msg)
	}
}

func (m *DnsManager) read() (data []byte, err error) {
	if m.stream {
		lenBuf := pool.GetBuffer(2)
		defer pool.PutBuffer(lenBuf)
		// Read two byte length.
		if _, err = io.ReadFull(m.conn, lenBuf); err != nil {
			return nil, oops.Wrapf(err, "failed to read DNS resp payload length")
		}
		data = pool.GetBuffer(int(binary.BigEndian.Uint16(lenBuf)))
		if _, err = io.ReadFull(m.conn, data); err != nil {
			pool.PutBuffer(data)
			return nil, oops.Wrapf(err, "failed to read DNS resp payload")
		}
	} else {
		data = pool.GetBuffer(consts.MaxDnsMessageSize + 1)
		for {
			var n int
			if n, err = m.conn.Read(data); err != nil {
				pool.PutBuffer(data)
				return nil, oops.Wrapf(err, "failed to read DNS resp payload")
			}
			if n <= consts.MaxDnsMessageSize {
				data = data[:n]
				break
			}
		}
	}
	return
}

func (m *DnsManager) feed(msg *dnsmessage.Msg) bool {
	v, ok := m.recvMap.Load(msg.Id)
	if !ok {
		// Ignore message from unknown session
		return false
	}
	pending := v.(*dnsPendingQuery)
	if err := netutils.ValidateDnsResponse(pending.query, msg, pending.wireId); err != nil {
		log.Debugf("DNSManager: drop invalid response: %v", err)
		return false
	}
	m.recordResponse()

	select {
	case pending.ch <- msg:
		return true
	default:
		// Channel full, drop the message
		return false
	}
}

func (m *DnsManager) Close() error {
	m.stateMu.Lock()
	closeNow := m.markClosedLocked()
	m.stateMu.Unlock()
	if closeNow {
		return m.closeConn()
	}
	<-m.closeDone
	return nil
}

func (m *DnsManager) IsClosed() bool {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	return m.closed || m.stale
}

func (m *DnsManager) Resolve(msg *dnsmessage.Msg) error {
	return m.ResolveContext(context.Background(), msg)
}

func (m *DnsManager) ResolveContext(ctx context.Context, msg *dnsmessage.Msg) error {
	if log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("DNSManager: Resolve %v %v", msg.Question[0].Name, msg.Question[0].Qtype)
	}
	if msg.Response {
		panic("DNSManager: DNS request expected but DNS response received")
	}
	if len(msg.Question) == 0 {
		panic("DNSManager: no question in dns message")
	}
	if !m.beginQuery() {
		return net.ErrClosed
	}
	defer m.endQuery()

	// The caller-supplied msg.Id may collide with another in-flight query on
	// this same upstream connection (clients often pick small / repeating IDs).
	// Allocate a transaction ID that is unique across this connection, rewrite
	// msg.Id before packing, and restore the original ID before returning so
	// the response forwarded to the client keeps its original ID.
	originalId := msg.Id
	defer func() { msg.Id = originalId }()

	pending := &dnsPendingQuery{
		ch:    make(chan *dnsmessage.Msg, 1),
		query: msg.Copy(),
	}
	// Allocate a unique transaction ID via a monotonic counter. After 65536
	// queries the counter wraps around and may collide with a still-pending
	// slot; in that rare case we keep advancing until a free slot is found.
	const maxIdAllocTries = 65536
	var newId uint16
	for tries := 0; ; tries++ {
		newId = uint16(m.nextId.Add(1))
		pending.wireId = newId
		if _, loaded := m.recvMap.LoadOrStore(newId, pending); !loaded {
			break
		}
		if tries >= maxIdAllocTries {
			return oops.Errorf("DNSManager: failed to allocate a unique DNS transaction ID after %d tries", maxIdAllocTries)
		}
	}
	defer m.recvMap.Delete(newId)
	msg.Id = newId

	data, err := msg.Pack()
	if err != nil {
		return oops.Wrapf(err, "pack DNS packet")
	}
	if err := netutils.CheckDnsMessageSize(len(data)); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	errCh := make(chan error, 1)
	var streamWriteCh chan error
	if m.stream {
		// A stream write either lands or the connection is broken; there is
		// nothing to retransmit (and re-sending the same transaction ID on a
		// live stream is not legal pipelining anyway, RFC 7766 section 6.2.1).
		payload := make([]byte, 2+len(data))
		binary.BigEndian.PutUint16(payload[:2], uint16(len(data)))
		copy(payload[2:], data)
		streamWriteCh = make(chan error, 1)
		go func() {
			n, err := m.conn.Write(payload)
			if err == nil && n != len(payload) {
				err = io.ErrShortWrite
			}
			streamWriteCh <- err
		}()
	} else {
		// The retry goroutine owns the packed payload for its whole lifetime;
		// a plain allocation cannot race a pooled buffer handed out again
		// while a retry is still writing.
		go func() {
			for i := 0; i < consts.DefaultDNSRetryCount; i++ {
				if _, err := m.conn.Write(data); err != nil {
					errCh <- err
					return
				}
				if i+1 == consts.DefaultDNSRetryCount {
					return
				}
				select {
				case <-m.ctx.Done():
					return
				case <-ctx.Done():
					// Success received
					return
				case <-time.After(consts.DefaultDNSRetryInterval):
				}
			}
		}()
	}

	for {
		select {
		case <-m.ctx.Done():
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return net.ErrClosed
		case <-ctx.Done():
			if streamWriteCh != nil {
				_ = m.Close()
			} else {
				m.markStale()
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return oops.Wrapf(context.DeadlineExceeded, "dns query timeout")
			}
			return ctx.Err()
		case err := <-streamWriteCh:
			streamWriteCh = nil
			if err != nil {
				_ = m.Close()
				return oops.Wrapf(err, "failed to write DNS req")
			}
		case err := <-errCh:
			return err
		case recvMsg := <-pending.ch:
			*msg = *recvMsg
			return nil
		}
	}
}
