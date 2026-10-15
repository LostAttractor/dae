package udphop

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

const (
	packetQueueSize    = 1024
	udpBufferSize      = 2048
	defaultHopInterval = 30 * time.Second
)

type udpHopPacketConn struct {
	HopInterval                     time.Duration
	addrs                           []net.Addr
	dialFunc                        func(context.Context, net.Addr) (net.Conn, error)
	connMutex                       sync.RWMutex
	prevConn, currentConn           net.Conn
	readBufferSize, writeBufferSize int
	writeDeadline                   time.Time
	readDeadline                    protocol.Deadline
	recvQueue                       chan *udpPacket
	readError                       chan error
	ctx                             context.Context
	cancel                          context.CancelFunc
	hopDone                         chan struct{}
	receivers                       sync.WaitGroup
	lease                           *netproxy.Lease
	currentWatchCancel              context.CancelFunc
	closeAsyncOnce                  sync.Once
	closeOnce                       sync.Once
	closeErr                        error
}
type udpPacket struct {
	Buf  []byte
	N    int
	Addr net.Addr
}

// The initial context owns establishment only. Close cancels later hop dials
// and joins both the hopping worker and every socket receiver.
func NewUDPHopPacketConn(initial context.Context, addr *UDPHopAddr, interval time.Duration, dial func(context.Context, net.Addr) (net.Conn, error)) (net.PacketConn, error) {
	if interval == 0 {
		interval = defaultHopInterval
	} else if interval < 5*time.Second {
		return nil, errors.New("hop interval must be at least 5 seconds")
	}
	addrs, err := addr.addrs()
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("UDP hopping requires at least one port")
	}
	// Do not let the caller's dependency collector capture this temporary
	// socket: the stable hopper lease owns the current socket dependency.
	var dialCtx context.Context
	var cancelDial context.CancelFunc
	if deadline, ok := initial.Deadline(); ok {
		dialCtx, cancelDial = context.WithDeadline(context.Background(), deadline)
	} else {
		dialCtx, cancelDial = context.WithCancel(context.Background())
	}
	defer cancelDial()
	stop := context.AfterFunc(initial, cancelDial)
	defer stop()
	conn, err := dial(dialCtx, addrs[rand.IntN(len(addrs))])
	if err != nil {
		return nil, err
	}
	if err = initial.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	u := &udpHopPacketConn{HopInterval: interval, addrs: addrs, dialFunc: dial, currentConn: conn, recvQueue: make(chan *udpPacket, packetQueueSize), readError: make(chan error, 1), readDeadline: protocol.MakeDeadline(), lease: netproxy.NewLease(netproxy.NewResourceRef()), ctx: ctx, cancel: cancel, hopDone: make(chan struct{})}
	if parent := netproxy.DependencyOf(conn); parent != nil && !parent.Valid() {
		cancel()
		_ = conn.Close()
		return nil, parent.Cause()
	}
	u.receivers.Add(1)
	go u.recvLoop(conn)
	u.watchCurrent(conn)
	go u.hopLoop()
	return u, nil
}
func (u *udpHopPacketConn) DependencyLease() *netproxy.Lease { return u.lease }

// Called with the state lock held, or before publishing the hopper.
func (u *udpHopPacketConn) watchCurrent(conn net.Conn) {
	parent := netproxy.DependencyOf(conn)
	if parent == nil {
		u.currentWatchCancel = nil
		return
	}
	ctx, cancel := context.WithCancel(u.ctx)
	u.currentWatchCancel = cancel
	u.receivers.Add(1)
	go func() {
		defer u.receivers.Done()
		select {
		case <-ctx.Done():
			return
		case <-parent.Done():
		}
		u.connMutex.Lock()
		current := u.currentConn == conn && u.ctx.Err() == nil
		if current {
			if cause := parent.AbortCause(); cause != nil {
				u.lease.Abort(cause)
			} else {
				u.lease.Invalidate(parent.Cause())
			}
		}
		u.connMutex.Unlock()
		if current {
			u.closeAsyncOnce.Do(func() { go u.Close() })
		}
	}()
}
func (u *udpHopPacketConn) recvLoop(conn net.Conn) {
	defer u.receivers.Done()
	for {
		buf := pool.GetBuffer(udpBufferSize)
		n, err := conn.Read(buf)
		if err != nil {
			pool.PutBuffer(buf)
			u.connMutex.RLock()
			current := u.currentConn == conn
			u.connMutex.RUnlock()
			if current && u.ctx.Err() == nil {
				select {
				case u.readError <- err:
				default:
				}
			}
			return
		}
		packet := &udpPacket{Buf: buf, N: n, Addr: conn.RemoteAddr()}
		select {
		case <-u.ctx.Done():
			pool.PutBuffer(buf)
			return
		default:
		}
		select {
		case u.recvQueue <- packet:
		default:
			pool.PutBuffer(buf)
		}
	}
}
func (u *udpHopPacketConn) hopLoop() {
	defer close(u.hopDone)
	ticker := time.NewTicker(u.HopInterval)
	defer ticker.Stop()
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-ticker.C:
			u.hop()
		}
	}
}
func (u *udpHopPacketConn) hop() {
	if u.ctx.Err() != nil {
		return
	}
	conn, err := u.dialFunc(u.ctx, u.addrs[rand.IntN(len(u.addrs))])
	if err != nil {
		return
	}
	u.connMutex.Lock()
	if u.ctx.Err() != nil || !u.lease.Valid() {
		u.connMutex.Unlock()
		_ = conn.Close()
		return
	}
	previous := u.prevConn
	u.prevConn, u.currentConn = u.currentConn, conn
	if u.currentWatchCancel != nil {
		u.currentWatchCancel()
	}
	u.watchCurrent(conn)
	_ = conn.SetWriteDeadline(u.writeDeadline)
	if u.readBufferSize > 0 {
		_ = trySetReadBuffer(conn, u.readBufferSize)
	}
	if u.writeBufferSize > 0 {
		_ = trySetWriteBuffer(conn, u.writeBufferSize)
	}
	u.receivers.Add(1)
	u.connMutex.Unlock()
	go u.recvLoop(conn)
	if previous != nil {
		_ = previous.Close()
	}
}
func (u *udpHopPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if u.ctx.Err() != nil {
		return 0, nil, u.terminalError()
	}
	select {
	case <-u.ctx.Done():
		return 0, nil, u.terminalError()
	case <-u.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	case err := <-u.readError:
		return 0, nil, err
	case packet := <-u.recvQueue:
		n := copy(p, packet.Buf[:packet.N])
		pool.PutBuffer(packet.Buf)
		return n, packet.Addr, nil
	}
}
func (u *udpHopPacketConn) terminalError() error {
	if cause := u.lease.Cause(); cause != nil {
		return cause
	}
	return net.ErrClosed
}
func (u *udpHopPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if u.ctx.Err() != nil {
		return 0, u.terminalError()
	}
	u.connMutex.RLock()
	conn := u.currentConn
	u.connMutex.RUnlock()
	return conn.Write(p)
}
func (u *udpHopPacketConn) Close() error {
	u.closeOnce.Do(func() {
		u.cancel()
		u.lease.Invalidate(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Resource: u.lease.Resource(), Scope: netproxy.ScopeSharedResource, Layer: netproxy.LayerUDP, Origin: netproxy.OriginLocalCleanup, Reason: netproxy.ReasonClosed}))
		u.connMutex.Lock()
		current, previous := u.currentConn, u.prevConn
		u.readDeadline.Set(time.Time{})
		u.connMutex.Unlock()
		u.closeErr = current.Close()
		if previous != nil {
			u.closeErr = errors.Join(u.closeErr, previous.Close())
		}
		<-u.hopDone
		u.receivers.Wait()
		for {
			select {
			case packet := <-u.recvQueue:
				pool.PutBuffer(packet.Buf)
			default:
				return
			}
		}
	})
	return u.closeErr
}
func (u *udpHopPacketConn) LocalAddr() net.Addr {
	u.connMutex.RLock()
	conn := u.currentConn
	u.connMutex.RUnlock()
	return conn.LocalAddr()
}
func (u *udpHopPacketConn) SetDeadline(t time.Time) error {
	return errors.Join(u.SetReadDeadline(t), u.SetWriteDeadline(t))
}
func (u *udpHopPacketConn) SetReadDeadline(t time.Time) error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	if u.ctx.Err() != nil {
		return net.ErrClosed
	}
	u.readDeadline.Set(t)
	return nil
}
func (u *udpHopPacketConn) SetWriteDeadline(t time.Time) error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	if u.ctx.Err() != nil {
		return net.ErrClosed
	}
	u.writeDeadline = t
	err := u.currentConn.SetWriteDeadline(t)
	if u.prevConn != nil {
		err = errors.Join(err, u.prevConn.SetWriteDeadline(t))
	}
	return err
}
func (u *udpHopPacketConn) SetReadBuffer(size int) error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	if u.ctx.Err() != nil {
		return net.ErrClosed
	}
	u.readBufferSize = size
	return trySetReadBuffer(u.currentConn, size)
}
func (u *udpHopPacketConn) SetWriteBuffer(size int) error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	if u.ctx.Err() != nil {
		return net.ErrClosed
	}
	u.writeBufferSize = size
	return trySetWriteBuffer(u.currentConn, size)
}
func trySetReadBuffer(conn net.Conn, size int) error {
	if c, ok := conn.(interface{ SetReadBuffer(int) error }); ok {
		return c.SetReadBuffer(size)
	}
	return nil
}
func trySetWriteBuffer(conn net.Conn, size int) error {
	if c, ok := conn.(interface{ SetWriteBuffer(int) error }); ok {
		return c.SetWriteBuffer(size)
	}
	return nil
}
