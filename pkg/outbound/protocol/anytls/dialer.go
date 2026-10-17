package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

func init() {
	protocol.RegisterLayer("anytls", func(parent netproxy.Dialer, header protocol.Header) (netproxy.Layer, error) {
		dialer, err := NewDialer(parent, header)
		if err != nil {
			return netproxy.Layer{}, err
		}
		return netproxy.Layer{
			Data:      dialer,
			Sessions:  []netproxy.Session{dialer},
			Resources: []io.Closer{dialer},
		}, nil
	})
}

type Dialer struct {
	ParentDialer netproxy.Dialer
	proxyAddress string
	key          []byte
	padding      atomic.Pointer[paddingFactory]
	tlsConfig    *tls.Config

	idleSessionLock sync.Mutex
	idleSessions    map[*session]struct{}
	sessions        map[*session]struct{}
	ctx             context.Context
	cancel          context.CancelFunc
	operations      sync.WaitGroup
	workers         sync.WaitGroup
	closeOnce       sync.Once
	closeErr        error

	desired      int
	connecting   bool
	connectToken chan struct{}
	state        *netproxy.PoolState
	episode      uint64
}

func NewDialer(ParentDialer netproxy.Dialer, header protocol.Header) (*Dialer, error) {
	sum := sha256.Sum256([]byte(header.Password))
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dialer{
		ParentDialer: ParentDialer,
		proxyAddress: header.ProxyAddress,
		key:          sum[:],
		tlsConfig:    header.TlsConfig,
		idleSessions: make(map[*session]struct{}),
		sessions:     make(map[*session]struct{}),
		connectToken: make(chan struct{}, 1),
		state:        netproxy.NewPoolState(netproxy.LayerAnyTLS),
		ctx:          ctx,
		cancel:       cancel,
	}
	d.padding.Store(defaultPadding)
	return d, nil
}

func (d *Dialer) Snapshot() netproxy.StateEvent {
	d.idleSessionLock.Lock()
	defer d.idleSessionLock.Unlock()
	if d.ctx.Err() == nil {
		d.publishStateLocked(nil)
	}
	return d.state.Snapshot()
}

func (d *Dialer) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return d.state.WatchState(ctx)
}

func (d *Dialer) begin(ctx context.Context) (context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	d.idleSessionLock.Lock()
	if d.ctx.Err() != nil {
		d.idleSessionLock.Unlock()
		return nil, nil, net.ErrClosed
	}
	d.operations.Add(1)
	d.idleSessionLock.Unlock()

	operationCtx, cancel := context.WithCancel(ctx)
	stopClose := context.AfterFunc(d.ctx, cancel)
	return operationCtx, func() {
		stopClose()
		cancel()
		d.operations.Done()
	}, nil
}

func (d *Dialer) contextError(ctx context.Context) error {
	if d.ctx.Err() != nil {
		return net.ErrClosed
	}
	return ctx.Err()
}

func (d *Dialer) Connect(ctx context.Context) error {
	ctx, finish, err := d.begin(ctx)
	if err != nil {
		return err
	}
	defer finish()
	select {
	case d.connectToken <- struct{}{}:
		defer func() { <-d.connectToken }()
	case <-ctx.Done():
		return d.contextError(ctx)
	}
	if err := ctx.Err(); err != nil {
		return d.contextError(ctx)
	}
	d.idleSessionLock.Lock()
	if d.ctx.Err() != nil {
		d.idleSessionLock.Unlock()
		return net.ErrClosed
	}
	d.publishStateLocked(nil)
	if d.state.Snapshot().State == netproxy.SessionConnected && !d.state.Snapshot().RecoveryRequired {
		if ctx.Err() != nil {
			d.idleSessionLock.Unlock()
			return d.contextError(ctx)
		}
		d.idleSessionLock.Unlock()
		return nil
	}
	d.connecting = true
	d.publishStateLocked(nil)
	d.idleSessionLock.Unlock()
	defer func() {
		d.idleSessionLock.Lock()
		d.connecting = false
		if d.ctx.Err() == nil {
			d.publishStateLocked(nil)
		}
		d.idleSessionLock.Unlock()
	}()
	dialCtx, cancel := netproxy.NewDialTimeoutContextFrom(ctx)
	s, err := d.createSession(dialCtx)
	cancel()
	if err != nil {
		return d.sessionError(err)
	}
	d.idleSessionLock.Lock()
	_, alive := d.sessions[s]
	operationErr := ctx.Err()
	if operationErr == nil && alive && !s.closed.Load() {
		d.idleSessions[s] = struct{}{}
	}
	d.idleSessionLock.Unlock()
	if operationErr != nil {
		_ = s.Close()
		return d.contextError(ctx)
	}
	if !alive || s.closed.Load() {
		return d.sessionError(netproxy.ErrNotConnected)
	}
	return nil
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	ctx, finish, err := d.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	switch network {
	case "tcp":
		s, err := d.getSession(ctx)
		if err != nil {
			return nil, err
		}
		return d.openStream(ctx, s, addr)
	case "udp":
		conn, err := d.listenPacket(ctx, addr)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{
			PacketConn: conn,
			Address:    netproxy.NewAddr(network, addr),
		}, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	return protocol.NewPacketAssociation(ctx, addr, d.openPacket)
}

func (d *Dialer) openPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	ctx, finish, err := d.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	return d.listenPacket(ctx, addr)
}

func (d *Dialer) listenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	s, err := d.getSession(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := d.openStream(ctx, s, net.JoinHostPort("sp.v2.udp-over-tcp.arpa", port))
	if err != nil {
		return nil, err
	}
	return &packetStream{stream: stream, addr: addr}, nil
}

// An opening stream may already be writing a shared TLS record when its
// caller cancels. The owner tracks that worker until its carrier write exits;
// cancellation never closes the carrier merely to interrupt one stream.
func (d *Dialer) openStream(ctx context.Context, s *session, target string) (*stream, error) {
	type result struct {
		stream *stream
		err    error
	}
	results := make(chan result)
	d.workers.Go(func() {
		stream, err := s.newStreamContext(ctx, target)
		select {
		case results <- result{stream, err}:
		case <-ctx.Done():
			if stream != nil {
				_ = stream.Close()
			}
		}
	})
	select {
	case result := <-results:
		if err := ctx.Err(); err != nil {
			if result.stream != nil {
				_ = result.stream.Close()
			}
			return nil, errors.Join(result.err, err)
		}
		return result.stream, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *Dialer) getSession(ctx context.Context) (*session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := netproxy.RequireConnected(d); err != nil {
		return nil, err
	}
	d.idleSessionLock.Lock()
	defer d.idleSessionLock.Unlock()
	for s := range d.idleSessions {
		delete(d.idleSessions, s)
		if !s.closed.Load() && s.lease.Valid() {
			return s, nil
		}
	}
	var best *session
	load, capacity := 0, 0
	for s := range d.sessions {
		if s.closed.Load() || !s.lease.Valid() {
			continue
		}
		capacity++
		s.streamLock.RLock()
		current := len(s.streams)
		s.streamLock.RUnlock()
		if best == nil || current < load {
			best, load = s, current
		}
	}
	if best == nil {
		d.publishStateLocked(nil)
		return nil, netproxy.ErrNotConnected
	}
	// Existing AnyTLS sessions multiplex concurrent streams. Busy pools request
	// one extra ready session, while this operation uses current healthy capacity.
	d.desired = max(d.desired, capacity+1)
	d.publishStateLocked(nil)
	return best, nil
}

func (d *Dialer) createSession(ctx context.Context) (*session, error) {
	conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.proxyAddress)
	if err != nil {
		return nil, err
	}

	netproxy.CaptureDependency(ctx, conn)
	tlsConn := tls.Client(conn, d.tlsConfig)

	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	_, _ = buf.Write(d.key)
	padding := 0
	if sizes := d.padding.Load().GenerateRecordPayloadSizes(0); len(sizes) > 0 {
		padding = max(0, sizes[0])
	}
	_ = buf.WriteByte(byte(padding >> 8))
	_ = buf.WriteByte(byte(padding))
	_, _ = buf.Write(make([]byte, padding))
	if err := protocol.Handshake(ctx, tlsConn, func() error { _, err := tlsConn.Write(buf.Bytes()); return err }); err != nil {
		return nil, err
	}

	s := newSession(tlsConn, d.sessionIdle, netproxy.DependencyOf(conn))
	s.padding = &d.padding
	d.idleSessionLock.Lock()
	if d.ctx.Err() != nil {
		d.idleSessionLock.Unlock()
		_ = s.Close()
		return nil, net.ErrClosed
	}
	if !s.lease.Valid() {
		d.idleSessionLock.Unlock()
		_ = s.Close()
		return nil, netproxy.ErrDependencyInvalid
	}
	d.sessions[s] = struct{}{}
	d.publishStateLocked(nil)
	d.idleSessionLock.Unlock()
	d.workers.Go(func() {
		select {
		case <-d.ctx.Done():
			return
		case <-s.lease.Done():
		}
		_ = s.Close()
	})
	d.workers.Go(func() {
		err := s.run()
		d.sessionClosed(s, err)
	})

	return s, nil
}

func (d *Dialer) sessionIdle(s *session) {
	d.idleSessionLock.Lock()
	if _, exists := d.sessions[s]; d.ctx.Err() == nil && exists && !s.closed.Load() {
		d.idleSessions[s] = struct{}{}
	}
	d.idleSessionLock.Unlock()
}

func (d *Dialer) sessionClosed(s *session, cause error) {
	d.idleSessionLock.Lock()
	_, member := d.sessions[s]
	if member && d.ctx.Err() == nil {
		for _, failure := range netproxy.Failures(cause) {
			if failure.Scope == netproxy.ScopeSharedResource && failure.Origin != netproxy.OriginLocalCleanup {
				d.episode++
				break
			}
		}
	}
	delete(d.idleSessions, s)
	delete(d.sessions, s)
	if d.ctx.Err() == nil {
		d.publishStateLocked(cause)
	}
	d.idleSessionLock.Unlock()
}

func (d *Dialer) sessionError(cause error) error {
	d.idleSessionLock.Lock()
	defer d.idleSessionLock.Unlock()
	if d.ctx.Err() != nil {
		return net.ErrClosed
	}
	d.publishStateLocked(cause)
	return cause
}

func (d *Dialer) Close() error {
	d.closeOnce.Do(func() {
		d.idleSessionLock.Lock()
		d.cancel()
		sessions := make([]*session, 0, len(d.sessions))
		for session := range d.sessions {
			sessions = append(sessions, session)
		}
		clear(d.idleSessions)
		clear(d.sessions)
		d.state.Close()
		d.idleSessionLock.Unlock()
		for _, session := range sessions {
			d.closeErr = errors.Join(d.closeErr, session.Close())
		}
		d.operations.Wait()
		d.workers.Wait()
	})
	return d.closeErr
}

func (d *Dialer) publishStateLocked(cause error) {
	capacity := 0
	for s := range d.sessions {
		if !s.closed.Load() && s.lease.Valid() {
			capacity++
		}
	}
	connecting := 0
	if d.connecting {
		connecting = 1
	}
	d.state.ObserveCapacity(netproxy.PoolCapacity{UsableCapacity: capacity, DesiredCapacity: d.desired,
		Connecting: connecting, EpisodeID: d.episode, Cause: cause})
}
