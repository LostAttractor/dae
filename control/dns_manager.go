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

type DnsManager struct {
	conn          net.Conn
	recvMap       sync.Map // map[uint16]*dnsPendingQuery
	ctx           context.Context
	cancel        context.CancelFunc
	closeDone     chan struct{}
	closeDoneOnce sync.Once
	writeMu       sync.Mutex

	stateMu      sync.Mutex
	pending      int
	lastResponse time.Time
	retired      bool
	closed       bool
	idleTimer    *time.Timer

	timeout time.Duration
	// idleTimeout bounds how long the connection may go without delivering
	// a response before the recv loop closes it.
	idleTimeout time.Duration
}

func NewDnsManager(conn net.Conn) *DnsManager {
	return newDnsManager(conn, consts.DefaultDNSTimeout, 2*consts.DefaultDNSTimeout)
}

func newDnsManager(conn net.Conn, timeout, idleTimeout time.Duration) *DnsManager {
	ctx, cancel := context.WithCancel(context.TODO())
	m := &DnsManager{
		conn:         conn,
		ctx:          ctx,
		cancel:       cancel,
		timeout:      timeout,
		idleTimeout:  idleTimeout,
		lastResponse: time.Now(),
		closeDone:    make(chan struct{}),
	}
	m.idleTimer = time.AfterFunc(idleTimeout, m.reapIdle)
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
	if m.closed || m.retired {
		return false
	}
	if m.pending == 0 {
		m.idleTimer.Stop()
	}
	m.pending++
	return true
}

func (m *DnsManager) reserveQuery(pending *dnsPendingQuery, startId uint16) (uint16, error) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	if m.closed || m.retired {
		return 0, errDnsManagerUnavailable
	}
	for offset := 0; offset < 1<<16; offset++ {
		wireId := startId + uint16(offset)
		pending.query.Id = wireId
		if _, loaded := m.recvMap.LoadOrStore(wireId, pending); loaded {
			continue
		}
		if m.pending == 0 {
			m.idleTimer.Stop()
		}
		m.pending++
		return wireId, nil
	}
	return 0, oops.Errorf("DNSManager: no free DNS transaction ID")
}

func (m *DnsManager) endQuery() {
	m.stateMu.Lock()
	m.pending--
	closeNow := false
	if m.pending == 0 && !m.closed {
		remaining := m.idleTimeout - time.Since(m.lastResponse)
		if m.retired || remaining <= 0 {
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
	m.stateMu.Unlock()
}

func (m *DnsManager) retire() {
	m.stateMu.Lock()
	m.retired = true
	closeNow := m.pending == 0 && m.markClosedLocked()
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
		err = netutils.UnpackDnsMessage(data, &msg)
		pool.PutBuffer(data)
		if err != nil {
			// Invalid message, this is fine - just wait for the next
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
	return
}

func (m *DnsManager) feed(msg *dnsmessage.Msg) bool {
	v, ok := m.recvMap.Load(msg.Id)
	if !ok {
		// Ignore message from unknown session
		return false
	}
	pending := v.(*dnsPendingQuery)
	if err := netutils.ValidateDnsResponseAllowEmptyQuestion(pending.query, msg, pending.query.Id); err != nil {
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
	return m.closed || m.retired
}

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
	startId := binary.BigEndian.Uint16(randomId[:])
	newId, err := m.reserveQuery(pending, startId)
	if err != nil {
		return err
	}
	defer m.endQuery()
	defer m.recvMap.Delete(newId)

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
	writeCh := make(chan error, 1)
	go func() {
		m.writeMu.Lock()
		defer m.writeMu.Unlock()
		if ctx.Err() != nil {
			writeCh <- ctx.Err()
			return
		}
		n, err := m.conn.Write(payload)
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}
		writeCh <- err
	}()

	for {
		select {
		case <-m.ctx.Done():
			if parentCtx.Err() != nil {
				return parentCtx.Err()
			}
			return fmt.Errorf("%w: %w", errDnsExchangeInterrupted, net.ErrClosed)
		case <-ctx.Done():
			if writeCh != nil {
				_ = m.Close()
			} else {
				m.retire()
			}
			if parentCtx.Err() != nil {
				return parentCtx.Err()
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return oops.Wrapf(context.DeadlineExceeded, "dns query timeout")
			}
			return ctx.Err()
		case err := <-writeCh:
			writeCh = nil
			if err != nil {
				_ = m.Close()
				return fmt.Errorf("%w: %w", errDnsExchangeInterrupted, oops.Wrapf(err, "failed to write DNS req"))
			}
		case recvMsg := <-pending.ch:
			*msg = *recvMsg
			msg.Id = originalId
			return nil
		}
	}
}
