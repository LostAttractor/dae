package control

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
)

type DnsManager struct {
	conn    net.Conn
	recvMap sync.Map // map[uint32]chan *dnsmessage.Msg
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
		data = pool.GetBuffer(consts.EthernetMtu)
		if _, err = m.conn.Read(data); err != nil {
			pool.PutBuffer(data)
			return nil, oops.Wrapf(err, "failed to read DNS resp payload")
		}
	}
	return
}

func (m *DnsManager) feed(msg *dnsmessage.Msg) {
	conn, ok := m.recvMap.Load(msg.Id)
	if !ok {
		// Ignore message from unknown session
		return
	}

	select {
	case conn.(chan *dnsmessage.Msg) <- msg:
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

	recvCh := make(chan *dnsmessage.Msg, 1)
	m.recvMap.Store(msg.Id, recvCh)
	defer m.recvMap.Delete(msg.Id)

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
	case recvMsg := <-recvCh:
		*msg = *recvMsg
		return nil
	}
}
