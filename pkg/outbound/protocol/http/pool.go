package http

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"golang.org/x/net/http2"
)

type h2Conn struct {
	stateMu      sync.Mutex // orders installation with passive drain/failure reports
	raw          net.Conn
	h2           *http2.ClientConn
	observed     atomic.Pointer[http2.ClientConn]
	terminal     atomic.Pointer[h2TerminalError]
	unattributed atomic.Bool
	ref          netproxy.ResourceRef
	lease        *netproxy.Lease
	pool         *h2ConnsPool
	draining     atomic.Bool
	failed       atomic.Bool
}

type h2TerminalError struct{ cause error }

type h2ConnsPool struct {
	mu          sync.Mutex
	conns       []*h2Conn
	dialer      netproxy.Dialer
	addr        string
	ctx         context.Context
	cancel      context.CancelFunc
	operations  sync.WaitGroup
	closeOnce   sync.Once
	closeErr    error
	state       *netproxy.PoolState
	connectGate chan struct{}
}

func newH2ConnsPool(dialer netproxy.Dialer, addr string) *h2ConnsPool {
	ctx, cancel := context.WithCancel(context.Background())
	p := &h2ConnsPool{dialer: dialer, addr: addr, ctx: ctx, cancel: cancel, state: netproxy.NewPoolState(netproxy.LayerH2), connectGate: make(chan struct{}, 1)}
	return p
}

func (p *h2ConnsPool) Snapshot() netproxy.StateEvent { return p.state.Snapshot() }
func (p *h2ConnsPool) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return p.state.WatchState(ctx)
}

func (p *h2ConnsPool) Connect(ctx context.Context) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case p.connectGate <- struct{}{}:
		defer func() { <-p.connectGate }()
	case <-ctx.Done():
		return ctx.Err()
	case <-p.ctx.Done():
		return net.ErrClosed
	}
	if snapshot := p.Snapshot(); snapshot.Accepting && !snapshot.RecoveryRequired {
		return nil
	}
	if !p.state.BeginConnect() {
		return net.ErrClosed
	}
	defer func() { p.state.EndConnect(err) }()

	raw, h2, err := p.getConn(ctx, false)
	if err != nil {
		return err
	}
	// HTTP/1.1 has no shared connection to retain. A successful negotiation
	// selects the stateless path; subsequent HTTP/1 errors belong to that dial.
	if h2 == nil {
		_ = raw.Close()
	} else if !p.Snapshot().Accepting {
		if h2.State().StreamsActive == 0 && h2.State().StreamsReserved == 0 {
			_ = h2.Close()
		}
		if cause := p.Snapshot().Cause; cause != nil {
			return cause
		}
		return netproxy.ErrNotConnected
	}
	return nil
}

func (p *h2ConnsPool) getConn(ctx context.Context, reserve bool) (net.Conn, *http2.ClientConn, error) {
	p.mu.Lock()
	if p.ctx.Err() != nil {
		p.mu.Unlock()
		return nil, nil, net.ErrClosed
	}
	p.operations.Add(1)
	defer p.operations.Done()
	needNew := !reserve && p.Snapshot().RecoveryRequired
	for _, slot := range p.conns {
		if needNew {
			break
		}
		if slot.failed.Load() || slot.draining.Load() || !slot.lease.Valid() {
			continue
		}
		available := slot.h2.CanTakeNewRequest()
		if reserve {
			available = slot.h2.ReserveNewRequest()
		}
		if available {
			p.mu.Unlock()
			return slot.raw, slot.h2, nil
		}
	}
	p.mu.Unlock()
	if reserve && p.Snapshot().State != netproxy.SessionConnected {
		return nil, nil, netproxy.ErrNotConnected
	}
	snapshot := p.Snapshot()
	if reserve && snapshot.Layer != netproxy.LayerProxy {
		err := netproxy.WrapFailure(http2.ErrNoCachedConn, netproxy.Failure{Resource: snapshot.Resource, Scope: netproxy.ScopeOperation, Layer: netproxy.LayerH2, Phase: netproxy.OpOpenStream, Reason: netproxy.ReasonCapacity})
		p.state.RequestCapacity(err)
		return nil, nil, err
	}

	dialCtx, cancel := netproxy.NewDialTimeoutContextFrom(ctx)
	stopClose := context.AfterFunc(p.ctx, cancel)
	defer stopClose()
	defer cancel()
	raw, err := p.dialer.DialContext(dialCtx, "tcp", p.addr)
	if err != nil {
		return nil, nil, fmt.Errorf("HTTP proxy transport dial: %w", err)
	}
	netproxy.CaptureDependency(ctx, raw)
	nextProto := ""
	if negotiated, ok := raw.(interface{ NegotiatedProtocol() string }); ok {
		nextProto = negotiated.NegotiatedProtocol()
	}

	if p.ctx.Err() != nil {
		_ = raw.Close()
		return nil, nil, net.ErrClosed
	}
	switch nextProto {
	case "", "http/1.1":
		p.state.Stateless(netproxy.LayerProxy)
		return raw, nil, nil
	case "h2":
		ref := p.state.NewResource()
		installed := false
		defer func() {
			if !installed {
				p.state.Remove(ref)
			}
		}()
		slot := &h2Conn{ref: ref, pool: p, lease: netproxy.NewLease(ref, netproxy.DependencyOf(raw))}
		monitored := &h2ObservedConn{Conn: raw, slot: slot}
		slot.raw = monitored
		transport, err := http2.ConfigureTransports(&http.Transport{})
		if err != nil {
			slot.lease.Invalidate(err)
			_ = raw.Close()
			return nil, nil, err
		}
		transport.ConnPool = p
		cc, err := transport.NewClientConn(monitored)
		if err != nil {
			slot.lease.Invalidate(err)
			_ = raw.Close()
			return nil, nil, err
		}
		slot.h2 = cc
		slot.observed.Store(cc)
		if reserve && !cc.ReserveNewRequest() {
			slot.lease.Invalidate(http2.ErrNoCachedConn)
			_ = cc.Close()
			return nil, nil, http2.ErrNoCachedConn
		}
		p.mu.Lock()
		if p.ctx.Err() != nil || !slot.lease.Valid() || slot.failed.Load() {
			p.mu.Unlock()
			_ = cc.Close()
			return nil, nil, netproxy.ErrNotConnected
		}
		p.conns = append(p.conns, slot)
		installed = true
		// A passive GOAWAY can arrive during setup. Never make a draining
		// connection available when publishing the completed handshake.
		slot.stateMu.Lock()
		if !slot.draining.Load() && !slot.failed.Load() {
			p.state.Ready(ref)
		}
		slot.stateMu.Unlock()

		p.operations.Add(1)
		p.mu.Unlock()
		go func() {
			defer p.operations.Done()
			select {
			case <-p.ctx.Done():
			case <-slot.lease.Done():
				p.failSlot(slot, slot.lease.Cause(), netproxy.OpRead)
			}
		}()
		return monitored, cc, nil
	default:
		_ = raw.Close()
		return nil, nil, fmt.Errorf("unsupported negotiated proxy protocol: %s", nextProto)
	}
}

func (p *h2ConnsPool) GetClientConn(req *http.Request, _ string) (*http2.ClientConn, error) {
	_, conn, err := p.getConn(req.Context(), true)
	return conn, err
}

func (p *h2ConnsPool) MarkDead(cc *http2.ClientConn) {
	p.mu.Lock()
	var slot *h2Conn
	for _, candidate := range p.conns {
		if candidate.h2 == cc {
			slot = candidate
			break
		}
	}
	p.mu.Unlock()
	if slot == nil {
		return
	}
	// x/net invokes MarkDead before it stores GOAWAY in ClientConn.State.
	// The passive reader already observed the exact frame. Existing streams
	// retain their leases and x/net closes the socket when they finish.
	if slot.draining.Load() && !cc.State().Closed {
		return
	}
	p.failSlot(slot, net.ErrClosed, netproxy.OpClose)
}

func (p *h2ConnsPool) drainSlot(slot *h2Conn, err http2.GoAwayError) {
	if slot.failed.Load() || !slot.draining.CompareAndSwap(false, true) {
		return
	}
	cause := netproxy.WrapFailure(err, netproxy.Failure{Resource: slot.ref, Scope: netproxy.ScopeOperation, Layer: netproxy.LayerH2, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonRejected, Code: fmt.Sprint(uint32(err.ErrCode))})
	slot.stateMu.Lock()
	p.state.Unavailable(slot.ref, cause, "draining")
	slot.stateMu.Unlock()
}

func (p *h2ConnsPool) failSlot(slot *h2Conn, cause error, op netproxy.Operation) {
	if !slot.failed.CompareAndSwap(false, true) {
		return
	}
	if cause == nil {
		cause = net.ErrClosed
	}
	failure := netproxy.ClassifyFailure(cause)
	failure.Resource, failure.Scope, failure.Phase = slot.ref, netproxy.ScopeSharedResource, op
	drained := false
	// A GOAWAY socket retired after every allowed request finished is cleanup.
	// Independent resets and protocol errors retain their actual fatal scope.
	if slot.draining.Load() && (cause == io.EOF || errors.Is(cause, net.ErrClosed)) {
		if cc := slot.observed.Load(); cc != nil {
			state := cc.State()
			if state.StreamsActive == 0 && state.StreamsReserved == 0 {
				failure.Scope, failure.Origin, failure.Reason = netproxy.ScopeOperation, netproxy.OriginLocalCleanup, netproxy.ReasonClosed
				drained = true
			}
		}
	}
	if failure.Layer == netproxy.LayerUnknown || failure.Layer == "" {
		failure.Layer = netproxy.LayerH2
	}
	slot.unattributed.Store(cause == net.ErrClosed && failure.Origin != netproxy.OriginLocalCleanup)
	cause = netproxy.WrapFailure(cause, failure)
	slot.terminal.Store(&h2TerminalError{cause: cause})
	if drained {
		slot.lease.Invalidate(cause)
	} else {
		slot.lease.Abort(cause)
	}
	slot.stateMu.Lock()
	p.state.Unavailable(slot.ref, cause, "")
	slot.stateMu.Unlock()
	go func() {
		_ = slot.raw.Close()
		p.mu.Lock()
		for i, candidate := range p.conns {
			if candidate == slot {
				p.conns = append(p.conns[:i], p.conns[i+1:]...)
				break
			}
		}
		p.mu.Unlock()
		p.state.Remove(slot.ref)
	}()
}

func (p *h2ConnsPool) refineFailure(slot *h2Conn, err error, op netproxy.Operation) {
	if !slot.unattributed.Load() || err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	failure := netproxy.ClassifyFailure(err)
	if failure.Scope == netproxy.ScopeStream || failure.Scope == netproxy.ScopeOperation {
		return
	}
	if !slot.unattributed.CompareAndSwap(true, false) {
		return
	}
	failure.Resource, failure.Scope, failure.Layer, failure.Phase = slot.ref, netproxy.ScopeSharedResource, netproxy.LayerH2, op
	cause := netproxy.WrapFailure(err, failure)
	slot.terminal.Store(&h2TerminalError{cause: cause})
	p.state.RefineFailure(slot.ref, cause)
}

func (p *h2ConnsPool) Close() error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.cancel()
		p.mu.Unlock()
		p.state.Close()
		p.operations.Wait()
		p.mu.Lock()
		slots := p.conns
		p.conns = nil
		p.mu.Unlock()
		for _, slot := range slots {
			if slot.lease != nil {
				slot.lease.Invalidate(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Resource: slot.ref, Scope: netproxy.ScopeSharedResource, Layer: netproxy.LayerH2, Origin: netproxy.OriginLocalCleanup, Reason: netproxy.ReasonClosed}))
			}
			p.closeErr = errors.Join(p.closeErr, slot.raw.Close())
		}
	})
	return p.closeErr
}

// h2ObservedConn passes bytes unchanged. It observes only complete GOAWAY
// headers and a bounded prefix of their payload; x/net remains the parser and
// authority for malformed frames and all HTTP/2 protocol decisions.
type h2ObservedConn struct {
	net.Conn
	slot      *h2Conn
	received  h2FrameObserver
	closeOnce sync.Once
	closeErr  error
}

type h2FrameObserver struct {
	header      [9]byte
	headerRead  int
	remaining   int
	goAway      bool
	payload     [264]byte
	payloadRead int
}

func (c *h2ObservedConn) DependencyLease() *netproxy.Lease { return c.slot.lease }
func (c *h2ObservedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.observe(p[:n])
	if err != nil {
		c.slot.pool.failSlot(c.slot, err, netproxy.OpRead)
	}
	return n, err
}
func (c *h2ObservedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil {
		c.slot.pool.failSlot(c.slot, err, netproxy.OpWrite)
	}
	return n, err
}
func (c *h2ObservedConn) Close() error {
	c.closeOnce.Do(func() { c.slot.pool.failSlot(c.slot, net.ErrClosed, netproxy.OpClose); c.closeErr = c.Conn.Close() })
	return c.closeErr
}

func (c *h2ObservedConn) observe(data []byte) {
	c.received.observe(data, func(away http2.GoAwayError) { c.slot.pool.drainSlot(c.slot, away) })
}

func (c *h2FrameObserver) observe(data []byte, onGoAway func(http2.GoAwayError)) {
	for len(data) > 0 {
		if c.headerRead < 9 {
			n := copy(c.header[c.headerRead:], data)
			c.headerRead += n
			data = data[n:]
			if c.headerRead < 9 {
				return
			}
			c.remaining = int(c.header[0])<<16 | int(c.header[1])<<8 | int(c.header[2])
			c.goAway = c.header[3] == byte(http2.FrameGoAway) && binary.BigEndian.Uint32(c.header[5:])&0x7fffffff == 0 && c.remaining >= 8
			c.payloadRead = 0
			if c.remaining == 0 {
				c.headerRead = 0
				continue
			}
		}
		n := min(len(data), c.remaining)
		if c.goAway && c.payloadRead < len(c.payload) {
			c.payloadRead += copy(c.payload[c.payloadRead:], data[:n])
		}
		c.remaining -= n
		data = data[n:]
		if c.remaining == 0 {
			if c.goAway {
				onGoAway(http2.GoAwayError{LastStreamID: binary.BigEndian.Uint32(c.payload[:4]) & 0x7fffffff, ErrCode: http2.ErrCode(binary.BigEndian.Uint32(c.payload[4:8])), DebugData: string(c.payload[8:c.payloadRead])})
			}
			c.headerRead = 0
		}
	}
}
