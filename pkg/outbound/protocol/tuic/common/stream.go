package common

import (
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/quic-go"
)

type safeStreamConn struct {
	*quic.Stream
	lock  sync.Mutex
	lAddr net.Addr
	rAddr net.Addr

	closeOnce sync.Once
	closeErr  error
	lease     *netproxy.Lease
	fail      func(error)
}

func (q *safeStreamConn) BindRecovery(lease *netproxy.Lease, fail func(error)) {
	q.lease, q.fail = lease, fail
}
func (q *safeStreamConn) DependencyLease() *netproxy.Lease { return q.lease }
func (q *safeStreamConn) wrap(err error, op netproxy.Operation) error {
	if q.lease == nil {
		return err
	}
	return WrapQUICError(err, q.lease.Resource(), q.lease, op, q.fail)
}
func (q *safeStreamConn) Read(p []byte) (int, error) {
	n, err := q.Stream.Read(p)
	return n, q.wrap(err, netproxy.OpRead)
}

func (q *safeStreamConn) Write(p []byte) (n int, err error) {
	q.lock.Lock()
	defer q.lock.Unlock()
	n, err = q.Stream.Write(p)
	return n, q.wrap(err, netproxy.OpWrite)
}

func (q *safeStreamConn) Close() error {
	q.closeOnce.Do(func() {
		if q.lease != nil {
			q.lease.Invalidate(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Resource: q.lease.Resource(), Stream: q.lease.Stream(), Scope: netproxy.ScopeStream, Layer: netproxy.LayerQUIC, Phase: netproxy.OpClose, Origin: netproxy.OriginLocalCleanup, Reason: netproxy.ReasonClosed}))
		}
		q.closeErr = q.close()
	})
	return q.closeErr
}

func (s *safeStreamConn) CloseWrite() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// As documented by the quic-go library, this doesn't actually close the entire stream.
	// It prevents further writes, which in turn will result in an EOF signal being sent the other side of stream when
	// reading.
	// We can still read from this stream.
	return s.wrap(s.Stream.Close(), netproxy.OpCloseWrite)
}

func (q *safeStreamConn) close() error {
	q.Stream.CancelRead(0)
	q.Stream.CancelWrite(0)
	return nil
}

func (q *safeStreamConn) LocalAddr() net.Addr {
	return q.lAddr
}

func (q *safeStreamConn) RemoteAddr() net.Addr {
	return q.rAddr
}

func NewSafeStreamConn(stream *quic.Stream, lAddr, rAddr net.Addr) *safeStreamConn {
	return &safeStreamConn{Stream: stream, lAddr: lAddr, rAddr: rAddr}
}
