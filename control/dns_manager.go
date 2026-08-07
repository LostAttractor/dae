package control

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
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
	qname string
	qtype uint16
}

type DnsManager struct {
	conn    net.Conn
	recvMap sync.Map // map[uint16]*dnsPendingQuery
	nextId  atomic.Uint32
	ctx     context.Context
	cancel  context.CancelFunc

	stream bool
}

func NewDnsManager(conn net.Conn, stream bool) *DnsManager {
	ctx, cancel := context.WithCancel(context.TODO())
	m := &DnsManager{
		conn:   conn,
		ctx:    ctx,
		cancel: cancel,
		stream: stream,
	}
	go func() {
		if err := m.run(); err != nil {
			log.WithError(err).Error("DNS manager recv loop exited")
		}
	}()
	return m
}

func (m *DnsManager) run() error {
	data := pool.GetBuffer(consts.EthernetMtu)
	defer pool.PutBuffer(data)
	for {
		var err error
		if data, err = m.read(); err != nil {
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
		data = pool.GetBuffer(consts.MaxDnsMessageSize)
		var n int
		if n, err = m.conn.Read(data); err != nil {
			pool.PutBuffer(data)
			return nil, oops.Wrapf(err, "failed to read DNS resp payload")
		}
		data = data[:n]
	}
	return
}

func (m *DnsManager) feed(msg *dnsmessage.Msg) {
	v, ok := m.recvMap.Load(msg.Id)
	if !ok {
		// Ignore message from unknown session
		return
	}
	pending := v.(*dnsPendingQuery)

	// Drop late/stray responses whose question doesn't match the pending query
	// (e.g. an old response arriving after the transaction ID has been reused).
	if len(msg.Question) == 0 ||
		msg.Question[0].Name != pending.qname ||
		msg.Question[0].Qtype != pending.qtype {
		log.Errorf("DNSManager: received message with mismatched question: got %v, expected %v %v",
			msg.Question, pending.qname, pending.qtype)
		return
	}

	select {
	case pending.ch <- msg:
		// OK
	default:
		// Channel full, drop the message
	}
}

func (m *DnsManager) Close() error {
	m.cancel()
	return m.conn.Close()
}

func (m *DnsManager) IsClosed() bool {
	return m.ctx.Err() != nil
}

func (m *DnsManager) Resolve(msg *dnsmessage.Msg) error {
	if log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("DNSManager: Resolve %v %v", msg.Question[0].Name, msg.Question[0].Qtype)
	}
	if msg.Response {
		panic("DNSManager: DNS request expected but DNS response received")
	}
	if len(msg.Question) == 0 {
		panic("DNSManager: no question in dns message")
	}

	// The caller-supplied msg.Id may collide with another in-flight query on
	// this same upstream connection (clients often pick small / repeating IDs).
	// Allocate a transaction ID that is unique across this connection, rewrite
	// msg.Id before packing, and restore the original ID before returning so
	// the response forwarded to the client keeps its original ID.
	originalId := msg.Id
	defer func() { msg.Id = originalId }()

	pending := &dnsPendingQuery{
		ch:    make(chan *dnsmessage.Msg, 1),
		qname: msg.Question[0].Name,
		qtype: msg.Question[0].Qtype,
	}
	// Allocate a unique transaction ID via a monotonic counter. After 65536
	// queries the counter wraps around and may collide with a still-pending
	// slot; in that rare case we keep advancing until a free slot is found.
	const maxIdAllocTries = 65536
	var newId uint16
	for tries := 0; ; tries++ {
		newId = uint16(m.nextId.Add(1))
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

	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if m.stream {
		binary.Write(buf, binary.BigEndian, uint16(len(data)))
	}
	buf.Write(data)

	ctx, cancel := context.WithTimeout(context.Background(), consts.DefaultDNSTimeout)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		for i := 0; i < consts.DefaultDNSRetryCount; i++ {
			_, err := m.conn.Write(buf.Bytes())
			if err != nil {
				errCh <- err
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

	select {
	case <-m.ctx.Done():
		return net.ErrClosed
	case <-ctx.Done():
		return net.ErrClosed
	case err := <-errCh:
		return err
	case recvMsg := <-pending.ch:
		// feed() already guarantees the question matches; reaching this branch
		// with a mismatched question would indicate a bug in DnsManager itself.
		if len(recvMsg.Question) == 0 ||
			msg.Question[0].Name != recvMsg.Question[0].Name ||
			msg.Question[0].Qtype != recvMsg.Question[0].Qtype {
			panic(fmt.Sprintf("DNSManager: feed delivered a mismatched response: got %v, expected %v %v",
				recvMsg.Question, msg.Question[0].Name, msg.Question[0].Qtype))
		}
		*msg = *recvMsg
		return nil
	}
}
