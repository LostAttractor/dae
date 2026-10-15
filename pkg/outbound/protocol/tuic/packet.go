package tuic

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pkg/fastrand"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
)

const packetQueueSize = 256

// UDP delivery is bounded. A slow association drops packets rather than
// retaining the connection's datagram reader or an unbounded linked list.
type packetQueue struct {
	packets chan *packetFrame
	done    chan struct{}
	once    sync.Once
}

func newPacketQueue() *packetQueue {
	return &packetQueue{packets: make(chan *packetFrame, packetQueueSize), done: make(chan struct{})}
}
func (p *packetQueue) PushBack(packet *packetFrame) {
	select {
	case <-p.done:
		return
	default:
	}
	select {
	case p.packets <- packet:
	default:
	}
}
func (p *packetQueue) Close() error { p.once.Do(func() { close(p.done) }); return nil }

type quicStreamPacketConn struct {
	target                string
	lease                 *netproxy.Lease
	fail                  func(error)
	connId                uint16
	quicConn              *quic.Conn
	incomingPackets       *packetQueue
	udpRelayMode          common.UdpRelayMode
	maxUdpRelayPacketSize int
	closeDeferFn          func()
	closeOnce             sync.Once
	closeErr              error
	closed                atomic.Bool

	readMu        sync.Mutex
	fragments     map[uint16]*deFragger
	readDeadline  protocol.Deadline
	writeMu       sync.Mutex
	stateMu       sync.Mutex
	writeDeadline time.Time
	sendStream    *quic.SendStream
}

func (q *quicStreamPacketConn) Close() error {
	q.closeOnce.Do(func() {
		cause := netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Resource: q.lease.Resource(), Stream: q.lease.Stream(), Scope: netproxy.ScopeStream, Layer: netproxy.LayerQUIC, Phase: netproxy.OpClose, Origin: netproxy.OriginLocalCleanup, Reason: netproxy.ReasonClosed})
		if !q.shutdown(cause) {
			return
		}

		// Dissociate is best effort and bounded even when the peer stops reading.
		stream, err := q.quicConn.OpenUniStream()
		if err != nil {
			q.closeErr = err
			return
		}
		_ = stream.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		frame := binary.BigEndian.AppendUint16([]byte{Ver5, DissociateType}, q.connId)
		if _, err = stream.Write(frame); err != nil {
			stream.CancelWrite(0)
		} else {
			err = stream.Close()
		}
		q.closeErr = common.WrapQUICError(err, q.lease.Resource(), nil, netproxy.OpClose, q.fail)
	})
	return q.closeErr
}

// shutdown is also used by the owning QUIC connection, so timers and blocked
// local reads end even when the application has not yet called Close.
func (q *quicStreamPacketConn) shutdown(cause error) bool {
	if !q.closed.CompareAndSwap(false, true) {
		return false
	}
	q.incomingPackets.Close()
	q.lease.Invalidate(cause)
	q.stateMu.Lock()
	q.readDeadline.Set(time.Time{})
	if q.sendStream != nil {
		q.sendStream.CancelWrite(0)
	}
	q.stateMu.Unlock()
	if q.closeDeferFn != nil {
		q.closeDeferFn()
	}
	return true
}

func (q *quicStreamPacketConn) SetDeadline(t time.Time) error {
	return errors.Join(q.SetReadDeadline(t), q.SetWriteDeadline(t))
}
func (q *quicStreamPacketConn) SetReadDeadline(t time.Time) error {
	q.stateMu.Lock()
	defer q.stateMu.Unlock()
	if q.closed.Load() {
		return net.ErrClosed
	}
	q.readDeadline.Set(t)
	return nil
}
func (q *quicStreamPacketConn) SetWriteDeadline(t time.Time) error {
	q.stateMu.Lock()
	defer q.stateMu.Unlock()
	if q.closed.Load() {
		return net.ErrClosed
	}
	q.writeDeadline = t
	if q.sendStream != nil {
		return q.sendStream.SetWriteDeadline(t)
	}
	return nil
}

func (q *quicStreamPacketConn) terminalError(op netproxy.Operation) error {
	cause := q.lease.Cause()
	if cause == nil {
		cause = net.ErrClosed
	}
	return common.WrapQUICError(cause, q.lease.Resource(), q.lease, op, q.fail)
}

func (q *quicStreamPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	q.readMu.Lock()
	defer q.readMu.Unlock()
	for {
		if q.closed.Load() || !q.lease.Valid() {
			return 0, nil, q.terminalError(netproxy.OpRead)
		}
		select {
		case <-q.incomingPackets.done:
			return 0, nil, q.terminalError(netproxy.OpRead)
		case <-q.lease.Done():
			return 0, nil, q.terminalError(netproxy.OpRead)
		case <-q.readDeadline.Wait():
			return 0, nil, common.WrapQUICError(os.ErrDeadlineExceeded, q.lease.Resource(), q.lease, netproxy.OpRead, q.fail)
		case packet := <-q.incomingPackets.packets:
			now := time.Now()
			for id, entry := range q.fragments {
				if now.Sub(entry.updated) >= 5*time.Second {
					delete(q.fragments, id)
				}
			}
			if packet.FRAG_TOTAL == 1 {
				return copy(p, packet.DATA), packet.ADDR.netAddr(), nil
			}
			if q.fragments == nil {
				q.fragments = make(map[uint16]*deFragger)
			}
			d := q.fragments[packet.PKT_ID]
			if d == nil {
				if len(q.fragments) >= packetQueueSize {
					continue
				}
				d = &deFragger{updated: now}
				q.fragments[packet.PKT_ID] = d
			}
			if n, addr, ready := d.Feed(packet, p); ready {
				delete(q.fragments, packet.PKT_ID)
				return n, addr, nil
			}
		}
	}
}

func (q *quicStreamPacketConn) writeTo(p []byte, addr string) (n int, err error) {
	defer func() { err = common.WrapQUICError(err, q.lease.Resource(), q.lease, netproxy.OpWrite, q.fail) }()
	if len(p) > 0xffff {
		return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 0xffff}
	}
	q.writeMu.Lock()
	defer q.writeMu.Unlock()
	if q.closed.Load() || !q.lease.Valid() {
		return 0, q.terminalError(netproxy.OpWrite)
	}
	q.stateMu.Lock()
	deadline := q.writeDeadline
	q.stateMu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	metadata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return 0, err
	}
	packet := &packetFrame{ASSOC_ID: q.connId, PKT_ID: uint16(fastrand.Uint32()), FRAG_TOTAL: 1, ADDR: addressFromMetadata(&metadata), DATA: p}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if err = packet.appendTo(buf); err != nil {
		return 0, err
	}
	if q.udpRelayMode == common.QUIC {
		stream, openErr := q.quicConn.OpenUniStream()
		if openErr != nil {
			return 0, openErr
		}
		q.stateMu.Lock()
		if q.closed.Load() {
			q.stateMu.Unlock()
			stream.CancelWrite(0)
			return 0, net.ErrClosed
		}
		q.sendStream = stream
		_ = stream.SetWriteDeadline(q.writeDeadline)
		q.stateMu.Unlock()
		_, err = buf.WriteTo(stream)
		q.stateMu.Lock()
		q.sendStream = nil
		q.stateMu.Unlock()
		if err != nil {
			stream.CancelWrite(0)
		} else {
			err = stream.Close()
		}
	} else {
		if q.maxUdpRelayPacketSize > 0 && len(p) > q.maxUdpRelayPacketSize {
			err = fragWriteNative(q.quicConn, packet, buf, q.maxUdpRelayPacketSize)
		} else {
			err = q.quicConn.SendDatagram(buf.Bytes())
		}
		if tooLarge, ok := errors.AsType[*quic.DatagramTooLargeError](err); ok {
			err = fragWriteNative(q.quicConn, packet, buf, int(tooLarge.MaxDatagramPayloadSize)-10-packet.ADDR.BytesLen())
		}
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (q *quicStreamPacketConn) DependencyLease() *netproxy.Lease { return q.lease }
func (q *quicStreamPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, errors.New("nil packet destination")
	}
	return q.writeTo(p, addr.String())
}
func (q *quicStreamPacketConn) LocalAddr() net.Addr         { return q.quicConn.LocalAddr() }
func (q *quicStreamPacketConn) RemoteAddr() net.Addr        { return netproxy.NewAddr("udp", q.target) }
func (q *quicStreamPacketConn) Read(p []byte) (int, error)  { n, _, err := q.ReadFrom(p); return n, err }
func (q *quicStreamPacketConn) Write(p []byte) (int, error) { return q.writeTo(p, q.target) }

var _ net.PacketConn = (*quicStreamPacketConn)(nil)
