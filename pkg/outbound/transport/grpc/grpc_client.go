package grpc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/common"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pkg/cert"
	proto "github.com/daeuniverse/dae/pkg/outbound/pkg/gun_proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
)

type ClientConn struct {
	lease           *netproxy.Lease
	tun             proto.Tunnel
	cancel          context.CancelFunc
	read, receive   net.Conn
	readMu          sync.Mutex
	readErr         error
	closeOnce       sync.Once
	workers         sync.WaitGroup
	done            chan struct{}
	writeGate       chan struct{}
	writes          chan sendRequest
	deadlineMu      sync.Mutex
	writeDeadline   time.Time
	deadlineChanged chan struct{}
	writeClosed     bool // owned by sendLoop
	sendErr         error
}

type sendRequest struct {
	hunk   *proto.Hunk
	fin    bool
	result chan error
}

// cancel must cancel the RPC backing tun, unblocking both Send and Recv.
func NewClientConn(tun proto.Tunnel, cancel context.CancelFunc) *ClientConn {
	read, receive := net.Pipe()
	c := &ClientConn{tun: tun, cancel: cancel, read: read, receive: receive,
		done: make(chan struct{}), writeGate: make(chan struct{}, 1), writes: make(chan sendRequest), deadlineChanged: make(chan struct{})}
	c.writeGate <- struct{}{}
	c.workers.Go(c.receiveLoop)
	c.workers.Go(c.sendLoop)
	return c
}

// One receive owns each decoded message until the application consumes it.
// A read deadline only interrupts the application's net.Pipe read; it cannot
// discard a message that arrives after that deadline.
func (c *ClientConn) receiveLoop() {
	defer c.receive.Close()
	for {
		hunk, err := c.tun.Recv()
		if err == nil && len(hunk.Data) != 0 {
			_, err = c.receive.Write(hunk.Data)
		}
		if err != nil {
			c.readMu.Lock()
			c.readErr = err
			c.readMu.Unlock()
			return
		}
	}
}
func (c *ClientConn) Read(p []byte) (int, error) {
	select {
	case <-c.done:
		return 0, c.failure(net.ErrClosed, netproxy.OpRead)
	default:
	}
	n, err := c.read.Read(p)
	if err == io.EOF {
		c.readMu.Lock()
		err = c.readErr
		c.readMu.Unlock()
	}
	return n, c.failure(err, netproxy.OpRead)
}

// Admission bounds the queue to one owned payload. Hunk data stays immutable:
// gRPC permits tracing/stats handlers to retain the message after Send returns.
func (c *ClientConn) sendLoop() {
	for {
		select {
		case <-c.done:
			return
		case request := <-c.writes:
			var err error
			select {
			case <-c.done:
				c.sendErr = net.ErrClosed
			default:
			}
			if c.sendErr != nil {
				err = c.sendErr
			} else if c.writeClosed {
				if !request.fin {
					err = io.ErrClosedPipe
				}
			} else if request.fin {
				c.writeClosed = true
				err = c.tun.CloseSend()
			} else {
				err = c.tun.Send(request.hunk)
			}
			if err != nil {
				c.sendErr = err
			}
			request.result <- err
			c.writeGate <- struct{}{}
		}
	}
}
func (c *ClientConn) send(p []byte, fin bool) error {
	request := sendRequest{fin: fin, result: make(chan error, 1)}
	admitted, sent := false, false
	defer func() {
		if admitted && !sent {
			c.writeGate <- struct{}{}
		}
	}()
	for {
		select {
		case <-c.done:
			return net.ErrClosed
		default:
		}
		c.deadlineMu.Lock()
		deadline, changed := c.writeDeadline, c.deadlineChanged
		c.deadlineMu.Unlock()
		if !deadline.IsZero() && !deadline.After(time.Now()) {
			if sent {
				_ = c.Close()
			}
			return os.ErrDeadlineExceeded
		}
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		var gate <-chan struct{}
		var submit chan sendRequest
		if !admitted {
			gate = c.writeGate
		} else if !sent {
			submit = c.writes
		}
		select {
		case <-gate:
			admitted = true
			request.hunk = &proto.Hunk{Data: append([]byte(nil), p...)}
		case submit <- request:
			sent = true
		case err := <-request.result:
			if timer != nil {
				timer.Stop()
			}
			return err
		case <-c.done:
			if timer != nil {
				timer.Stop()
			}
			return net.ErrClosed
		case <-changed:
		case <-timeout:
			if sent {
				_ = c.Close()
			}
			return os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
	}
}
func (c *ClientConn) Write(p []byte) (int, error) {
	err := c.failure(c.send(p, false), netproxy.OpWrite)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
func (c *ClientConn) CloseWrite() error { return c.failure(c.send(nil, true), netproxy.OpCloseWrite) }
func (c *ClientConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.cancel()
		_ = c.read.Close()
		_ = c.receive.Close()
		if c.lease != nil {
			c.lease.Invalidate(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Scope: netproxy.ScopeStream, Layer: netproxy.LayerGRPC, Origin: netproxy.OriginLocalCleanup}))
		}
	})
	c.workers.Wait()
	return nil
}
func (c *ClientConn) SetDeadline(t time.Time) error {
	_ = c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}
func (c *ClientConn) SetReadDeadline(t time.Time) error { return c.read.SetReadDeadline(t) }
func (c *ClientConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	close(c.deadlineChanged)
	c.deadlineChanged = make(chan struct{})
	c.deadlineMu.Unlock()
	return nil
}
func (c *ClientConn) DependencyLease() *netproxy.Lease { return c.lease }
func (c *ClientConn) failure(err error, phase netproxy.Operation) error {
	if err != nil {
		if cause := c.lease.AbortCause(); cause != nil {
			return cause
		}
	}
	if err == nil || phase == netproxy.OpRead && err == io.EOF {
		if err == io.EOF {
			c.lease.Invalidate(netproxy.WrapFailure(err, netproxy.Failure{Layer: netproxy.LayerGRPC, Scope: netproxy.ScopeStream, Reason: netproxy.ReasonClosed}))
		}
		return err
	}
	fact := netproxy.ClassifyFailure(err)
	fact.Layer, fact.Phase = netproxy.LayerGRPC, phase
	if fact.Scope == netproxy.ScopeUnknown {
		fact.Scope = netproxy.ScopeStream
	}
	select {
	case <-c.done:
		if err == net.ErrClosed || err == io.ErrClosedPipe || err == context.Canceled {
			fact.Origin = netproxy.OriginLocalCleanup
		}
	default:
	}
	if c.lease != nil {
		fact.Stream = c.lease.Stream()
	}
	wrapped := netproxy.WrapFailure(err, fact)
	if c.lease != nil && fact.Scope == netproxy.ScopeStream {
		c.lease.Invalidate(wrapped)
	}
	return wrapped
}
func (c *ClientConn) LocalAddr() net.Addr  { return nil }
func (c *ClientConn) RemoteAddr() net.Addr { return nil }

type Dialer struct {
	ParentDialer netproxy.Dialer
	ServiceName  string
	Address      string
	TLSConfig    *tls.Config // nil uses plaintext HTTP/2

	closed    atomic.Bool
	carrier   atomic.Pointer[carrier]
	handle    atomic.Pointer[netproxy.SingleSessionHandle[*grpc.ClientConn]]
	stateMu   sync.Mutex // orders Ready observations against carrier invalidation
	initOnce  sync.Once
	lifecycle *netproxy.SingleSession[*grpc.ClientConn]
}

func (d *Dialer) session() *netproxy.SingleSession[*grpc.ClientConn] {
	d.initOnce.Do(func() {
		d.lifecycle = netproxy.NewSingleSession(netproxy.SingleSessionConfig[*grpc.ClientConn]{
			Layer: netproxy.LayerGRPC, RecoveryExecutor: netproxy.RecoveryLibraryManaged, LogicalChannel: true,
			Establish: d.establish,
			IsConnected: func(cc *grpc.ClientConn) bool {
				return cc.GetState() == connectivity.Ready && d.carrier.Load().lease.Valid()
			},
			Recover: d.recover,
			Observe: d.observe,
			Close:   (*grpc.ClientConn).Close,
		})
	})
	return d.lifecycle
}

func (d *Dialer) Snapshot() netproxy.StateEvent {
	return d.session().Snapshot()
}

func (d *Dialer) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return d.session().WatchState(ctx)
}

// gRPC otherwise exposes only the blocking dial's deadline, losing the typed
// parent/TLS error that determines whether the daemon should retry.
type recordingCredentials struct {
	credentials.TransportCredentials
	record func(error)
}

func (c recordingCredentials) ClientHandshake(ctx context.Context, authority string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	secured, info, err := c.TransportCredentials.ClientHandshake(ctx, authority, conn)
	c.record(netproxy.WrapFailure(err, netproxy.Failure{Phase: netproxy.OpHandshake, Origin: netproxy.OriginPeer}))
	return secured, info, err
}

func (c recordingCredentials) Clone() credentials.TransportCredentials {
	return recordingCredentials{TransportCredentials: c.TransportCredentials.Clone(), record: c.record}
}

func (d *Dialer) dialOptions(record func(error)) ([]grpc.DialOption, error) {
	var transportCredentials credentials.TransportCredentials = insecure.NewCredentials()
	if d.TLSConfig != nil {
		config := d.TLSConfig.Clone()
		if config.RootCAs == nil && !config.InsecureSkipVerify {
			roots, err := cert.GetSystemCertPool()
			if err != nil {
				return nil, fmt.Errorf("failed to get system certificate pool: %w", err)
			}
			config.RootCAs = roots
		}
		transportCredentials = credentials.NewTLS(config)
	}
	return []grpc.DialOption{
		grpc.WithTransportCredentials(recordingCredentials{TransportCredentials: transportCredentials, record: record}),
		grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
			conn, err := d.ParentDialer.DialContext(ctx, "tcp", address)
			record(err)
			if err == nil {
				conn = d.trackCarrier(conn)
			}
			return conn, err
		}),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  500 * time.Millisecond,
				Multiplier: 1.5,
				Jitter:     0.2,
				MaxDelay:   19 * time.Second,
			},
			MinConnectTimeout: 5 * time.Second,
		}),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithBlock(),
	}, nil
}

func (d *Dialer) Connect(ctx context.Context) error {
	return d.session().Connect(ctx)
}

func (d *Dialer) establish(ctx context.Context) (*grpc.ClientConn, error) {
	if d.Address == "" {
		return nil, fmt.Errorf("grpc proxy address is empty")
	}
	var mu sync.Mutex
	var lastError error
	options, err := d.dialOptions(func(err error) {
		for _, failure := range netproxy.Failures(err) {
			if failure.Reason != netproxy.ReasonCanceled && failure.Reason != netproxy.ReasonDeadline {
				mu.Lock()
				lastError = err
				mu.Unlock()
				return
			}
		}
	})
	if err != nil {
		return nil, err
	}
	cc, err := grpc.DialContext(ctx, d.Address, options...)
	if err != nil {
		mu.Lock()
		err = errors.Join(lastError, err)
		mu.Unlock()
	}
	return cc, err
}

func (d *Dialer) recover(ctx context.Context, cc *grpc.ClientConn) (bool, error) {
	cc.Connect()
	for {
		state := cc.GetState()
		switch state {
		case connectivity.Ready:
			return false, nil
		case connectivity.Shutdown:
			return true, nil
		}
		if !cc.WaitForStateChange(ctx, state) {
			return false, ctx.Err()
		}
	}
}

func (d *Dialer) observe(ctx context.Context, handle *netproxy.SingleSessionHandle[*grpc.ClientConn]) {
	cc := handle.Resource()
	d.handle.Store(handle)
	for {
		d.stateMu.Lock()
		state := cc.GetState()
		var current bool
		switch state {
		case connectivity.Ready:
			carrier := d.carrier.Load()
			if cause := carrier.lease.Cause(); cause != nil {
				current = handle.Transition(netproxy.SessionDisconnected, carrier.sharedFailure(cause, netproxy.OpRead))
			} else {
				current = handle.Transition(netproxy.SessionConnected, nil)
			}
		case connectivity.Idle, connectivity.Connecting:
			current = handle.Transition(netproxy.SessionConnecting, nil)
		case connectivity.TransientFailure:
			current = handle.Transition(netproxy.SessionDisconnected, fmt.Errorf("grpc transport entered transient failure"))
		case connectivity.Shutdown:
			// A terminal channel has no library worker left to recover it.
			current = handle.Abort(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Layer: netproxy.LayerGRPC, Scope: netproxy.ScopeSharedResource}))
		}
		d.stateMu.Unlock()
		if !current {
			return
		}
		if state == connectivity.Idle {
			// This channel was explicitly started by Connect. A GOAWAY or
			// failed carrier must not leave library-owned recovery asleep.
			cc.Connect()
		}
		if state == connectivity.Shutdown || !cc.WaitForStateChange(ctx, state) {
			return
		}
	}
}

func (d *Dialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	switch network {
	case "tcp":
		handle, err := d.session().CurrentHandle()
		if err != nil {
			return nil, err
		}
		// ctx is the lifetime of the tun
		ctxStream, streamCloser := context.WithCancel(context.Background())
		tun, err := common.Invoke(ctx, func() (proto.Tunnel, error) {
			return proto.Open(ctxStream, handle.Resource(), d.ServiceName)
		}, streamCloser)
		if err != nil {
			return nil, netproxy.WrapFailure(err, netproxy.Failure{Layer: netproxy.LayerGRPC, Scope: netproxy.ScopeStream, Phase: netproxy.OpOpenStream})
		}
		// Context commits this RPC to its selected transport, disabling replay.
		// The channel's readiness lease only gates new work, not draining RPCs.
		remote, ok := peer.FromContext(tun.Context())
		if !ok || netproxy.DependencyOf(remote.Addr) == nil {
			streamCloser()
			return nil, fmt.Errorf("grpc stream has no carrier dependency")
		}
		lease := netproxy.DependencyOf(remote.Addr).NewStream()
		conn := NewClientConn(tun, streamCloser)
		conn.lease = lease
		if !lease.Valid() {
			_ = conn.Close()
			return nil, netproxy.ErrNotConnected
		}
		return conn, nil
	case "udp":
		return nil, fmt.Errorf("%w: grpc+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	return nil, fmt.Errorf("%w: grpc+udp", netproxy.UnsupportedTunnelTypeError)
}

func (d *Dialer) Close() error {
	d.closed.Store(true)
	return d.session().Close()
}
