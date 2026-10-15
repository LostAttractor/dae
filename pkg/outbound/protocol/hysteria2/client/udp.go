package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	rand "github.com/daeuniverse/dae/pkg/outbound/pkg/fastrand"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	tuiccommon "github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"

	"github.com/daeuniverse/quic-go"

	P "github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/internal/frag"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/internal/protocol"
)

const (
	udpMessageChanSize = 1024
	defraggerTimeout   = 5 * time.Second
)

type udpConn struct {
	ID        uint32
	ReceiveCh chan *protocol.UDPMessage

	conn *quic.Conn

	ctx    context.Context
	cancel context.CancelCauseFunc

	closeCallback func()
	lease         *netproxy.Lease
	fail          func(error)
	closeOnce     sync.Once

	receiveMu  sync.Mutex
	defraggers map[uint16]*defragEntry
	lastSweep  time.Time

	deadlineMu    sync.Mutex
	readDeadline  P.Deadline
	writeDeadline time.Time
}

type defragEntry struct {
	defragger *frag.Defragger
	expiresAt time.Time
}

func (u *udpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		select {
		case <-u.ctx.Done():
			return 0, nil, u.terminalError(netproxy.OpRead)
		case <-u.lease.Done():
			return 0, nil, u.terminalError(netproxy.OpRead)
		case <-u.readDeadline.Wait():
			return 0, nil, tuiccommon.WrapQUICError(os.ErrDeadlineExceeded, u.lease.Resource(), u.lease, netproxy.OpRead, u.fail)
		case msg, ok := <-u.ReceiveCh:
			if !ok {
				return 0, nil, io.EOF
			}
			dfMsg := u.feedDefrag(msg)
			if dfMsg == nil {
				// Incomplete message, wait for more
				continue
			}
			// TODO: 避免copy
			addr, parseErr := netip.ParseAddrPort(dfMsg.Addr)
			if parseErr != nil {
				return copy(p, dfMsg.Data), netproxy.NewAddr("udp", dfMsg.Addr), nil
			}
			return copy(p, dfMsg.Data), net.UDPAddrFromAddrPort(addr), nil
		}
	}
}

func (u *udpConn) feedDefrag(msg *protocol.UDPMessage) *protocol.UDPMessage {
	now := time.Now()
	u.receiveMu.Lock()
	defer u.receiveMu.Unlock()

	if now.Sub(u.lastSweep) >= defraggerTimeout {
		u.lastSweep = now
		for packetID, entry := range u.defraggers {
			if !now.Before(entry.expiresAt) {
				delete(u.defraggers, packetID)
			}
		}
	}
	if msg.FragCount <= 1 {
		return msg
	}

	entry := u.defraggers[msg.PacketID]
	if entry == nil || !now.Before(entry.expiresAt) {
		if len(u.defraggers) >= udpMessageChanSize {
			return nil
		}
		if u.defraggers == nil {
			u.defraggers = make(map[uint16]*defragEntry, 2)
		}
		entry = &defragEntry{
			defragger: &frag.Defragger{},
			expiresAt: now.Add(defraggerTimeout),
		}
		u.defraggers[msg.PacketID] = entry
	}
	dfMsg := entry.defragger.Feed(msg)
	if dfMsg != nil {
		delete(u.defraggers, msg.PacketID)
	}
	return dfMsg
}

func (u *udpConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if addr == nil {
		return 0, errors.New("nil UDP destination")
	}
	if len(b) > 65535 {
		return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 65535}
	}
	u.deadlineMu.Lock()
	deadline := u.writeDeadline
	u.deadlineMu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, tuiccommon.WrapQUICError(os.ErrDeadlineExceeded, u.lease.Resource(), u.lease, netproxy.OpWrite, u.fail)
	}

	if !u.lease.Valid() {
		return 0, u.terminalError(netproxy.OpWrite)
	}
	select {
	case <-u.ctx.Done():
		return 0, u.terminalError(netproxy.OpWrite)
	default:
	}
	// Try no frag first
	msg := &protocol.UDPMessage{
		SessionID: u.ID,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      addr.String(),
		Data:      b,
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	err = u.WritePacket(buf, msg)
	if errTooLarge, ok := errors.AsType[*quic.DatagramTooLargeError](err); ok {
		// Message too large, try fragmentation
		msg.PacketID = uint16(rand.Intn(0xFFFF)) + 1
		fMsgs := frag.FragUDPMessage(msg, int(errTooLarge.MaxDatagramPayloadSize))
		if len(fMsgs) == 0 {
			return 0, err
		}
		for _, fMsg := range fMsgs {
			err := u.WritePacket(buf, &fMsg)
			if err != nil {
				return 0, err
			}
		}
		return len(b), nil
	}
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (u *udpConn) WritePacket(buf *bytes.Buffer, msg *protocol.UDPMessage) error {
	buf.Reset()
	msg.AppendTo(buf)
	err := u.conn.SendDatagram(buf.Bytes())
	return tuiccommon.WrapQUICError(err, u.lease.Resource(), u.lease, netproxy.OpWrite, u.fail)
}

func (u *udpConn) Close() error {
	u.closeOnce.Do(func() {
		cause := netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Resource: u.lease.Resource(), Stream: u.lease.Stream(), Scope: netproxy.ScopeStream, Layer: netproxy.LayerQUIC, Origin: netproxy.OriginLocalCleanup, Reason: netproxy.ReasonClosed})
		u.lease.Invalidate(cause)
		u.cancel(cause)
		u.deadlineMu.Lock()
		u.readDeadline.Set(time.Time{})
		u.writeDeadline = time.Time{}
		u.deadlineMu.Unlock()
		u.closeCallback()
	})
	return nil
}

func (u *udpConn) SetDeadline(t time.Time) error {
	return errors.Join(u.SetReadDeadline(t), u.SetWriteDeadline(t))
}

func (u *udpConn) SetReadDeadline(t time.Time) error {
	u.deadlineMu.Lock()
	defer u.deadlineMu.Unlock()
	if u.ctx.Err() != nil {
		return net.ErrClosed
	}
	u.readDeadline.Set(t)
	return nil
}

// Datagram sends do not block; an expired write deadline still rejects the operation.
func (u *udpConn) SetWriteDeadline(t time.Time) error {
	u.deadlineMu.Lock()
	defer u.deadlineMu.Unlock()
	if u.ctx.Err() != nil {
		return net.ErrClosed
	}
	u.writeDeadline = t
	return nil
}

func (u *udpConn) LocalAddr() net.Addr {
	return u.conn.LocalAddr()
}

type udpSessionManager struct {
	done chan struct{}
	conn *quic.Conn

	connMap sync.Map // map[uint32]*udpConn
	nextID  atomic.Uint32

	ctx    context.Context
	cancel context.CancelCauseFunc
}

func newUDPSessionManager(parent context.Context, conn *quic.Conn) *udpSessionManager {
	ctx, cancel := context.WithCancelCause(parent)
	m := &udpSessionManager{
		conn:   conn,
		done:   make(chan struct{}),
		ctx:    ctx,
		cancel: cancel,
	}
	m.nextID.Store(1)
	go m.run()
	return m
}

func (m *udpSessionManager) run() error {
	defer func() {
		m.connMap.Range(func(key, value any) bool {
			u := value.(*udpConn)
			u.deadlineMu.Lock()
			u.readDeadline.Set(time.Time{})
			u.writeDeadline = time.Time{}
			u.deadlineMu.Unlock()
			m.connMap.Delete(key)
			return true
		})
		close(m.done)
	}()
	for {
		datagram, err := m.conn.ReceiveDatagram(m.ctx)
		if err != nil {
			m.cancel(err)
			return err
		}
		msg, err := protocol.ParseUDPMessage(datagram)
		if err != nil {
			// Invalid message, this is fine - just wait for the next
			continue
		}
		m.feed(msg)
	}
}

func (m *udpSessionManager) feed(msg *protocol.UDPMessage) {
	conn, ok := m.connMap.Load(msg.SessionID)
	if !ok {
		// Ignore message from unknown session
		return
	}

	select {
	case conn.(*udpConn).ReceiveCh <- msg:
		// OK
	default:
		// Channel full, drop the message
	}
}

// NewUDP creates a new UDP session.
func (m *udpSessionManager) NewUDP(lease *netproxy.Lease, fail func(error)) (net.PacketConn, error) {
	if m.ctx.Err() != nil {
		return nil, tuiccommon.WrapQUICError(context.Cause(m.ctx), lease.Resource(), lease, netproxy.OpOpenStream, fail)
	}
	id := m.nextID.Add(1) - 1

	ctx, cancel := context.WithCancelCause(m.ctx)
	conn := &udpConn{
		ID:           id,
		lease:        lease,
		fail:         fail,
		ReceiveCh:    make(chan *protocol.UDPMessage, udpMessageChanSize),
		conn:         m.conn,
		ctx:          ctx,
		cancel:       cancel,
		readDeadline: P.MakeDeadline(),
	}
	conn.closeCallback = func() {
		m.connMap.Delete(conn.ID)
	}
	m.connMap.Store(id, conn)
	if m.ctx.Err() != nil || !lease.Valid() {
		cause := conn.terminalError(netproxy.OpOpenStream)
		conn.Close()
		return nil, cause
	}

	return conn, nil
}

func (u *udpConn) DependencyLease() *netproxy.Lease { return u.lease }
func (u *udpConn) terminalError(op netproxy.Operation) error {
	cause := context.Cause(u.ctx)
	if !u.lease.Valid() && u.lease.Cause() != nil {
		cause = u.lease.Cause()
	}
	if cause == nil {
		cause = net.ErrClosed
	}
	return tuiccommon.WrapQUICError(cause, u.lease.Resource(), u.lease, op, u.fail)
}
