// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/internal/pluginctx"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/quic-go"
)

// UpstreamPlanner runs before connection-pool lookup. The URL identifies the
// network/TLS target; Host identifies the HTTP authority. Unrewritten requests
// share the intercepted connection's original plan. Rewrites and auxiliary
// requests plan their explicit URL targets independently.
// Key identifies the complete immutable plan, including protocol, node, mark
// and actual addresses. URL/TLS identity remains the transport's responsibility.
type UpstreamPlanner func(*http.Request) (UpstreamPlan, error)

type UpstreamPlan struct {
	Key        string
	Dial       DialContext
	DialPacket DialPacketContext
	// Check validates a connection-bound plan's lifetime without selecting a
	// new route. The owner may terminate the downstream on revocation.
	Check func() error
	// Next supplies independently keyed routes for connection racing. io.EOF
	// ends the stream; any other error rejects it. Close releases discovery
	// after selection, including pool hits. Next must honor its context.
	Next  func(context.Context) (UpstreamPlan, error)
	Close func()
}

// Validate the planner contract before forwarding.
func planUpstream(planner UpstreamPlanner, request *http.Request, packet bool) (UpstreamPlan, error) {
	if planner == nil {
		return UpstreamPlan{}, fmt.Errorf("mitm: missing upstream planner")
	}
	plan, err := planner(request)
	if err != nil {
		return UpstreamPlan{}, err
	}
	if plan.Key == "" || packet && plan.DialPacket == nil || !packet && plan.Dial == nil {
		if plan.Close != nil {
			plan.Close()
		}
		return UpstreamPlan{}, fmt.Errorf("mitm: incomplete upstream plan")
	}
	return plan, nil
}

type plannedTransport struct {
	host   *Host
	packet bool
	plan   UpstreamPlanner // Returns structurally valid plans; may cache selection.
	mu     sync.Mutex
	closed bool
	serial uint64
	pools  map[string]*routePool
	owned  map[*routePool]func()
}

type routePool struct {
	transport   http.RoundTripper
	plan        UpstreamPlan
	prepared    []*connectedRoute // Guarded by plannedTransport.mu.
	connectQUIC func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error)
	used        uint64
	// The cache and each in-flight exchange hold one reference.
	refs int
}

func (h *Host) plannedTransport(plan UpstreamPlanner, packet bool) *plannedTransport {
	return &plannedTransport{
		host: h, packet: packet,
		plan:  func(r *http.Request) (UpstreamPlan, error) { return planUpstream(plan, r, packet) },
		pools: make(map[string]*routePool), owned: make(map[*routePool]func()),
	}
}

// RoutedHTTPClient gives one protocol invocation its own policy-keyed pools.
// The owner supplies the intercepted identity in plan and closes the pools when
// the invocation finishes, after its HTTP requests and response bodies finish.
func (h *Host) RoutedHTTPClient(plan UpstreamPlanner) (*http.Client, func()) {
	transport := h.plannedTransport(plan, false)
	return &http.Client{Transport: transport}, transport.close
}

// NewRoutedHTTPClient provides policy-keyed HTTP pools without a plugin or
// interception host. Its owner closes it after all background work finishes.
func NewRoutedHTTPClient(plan UpstreamPlanner) (*http.Client, func()) {
	return new(Host).RoutedHTTPClient(plan)
}

func (p *plannedTransport) RoundTripPolicy(request *http.Request, policy string) (*http.Response, error) {
	return p.RoundTrip(request.WithContext(pluginctx.WithHTTPPolicy(request.Context(), policy)))
}

func (p *plannedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	var exclude map[*routePool]bool
	for {
		response, missed, err := p.roundTrip(request, exclude)
		if missed == nil {
			return response, err
		}
		// A cached route can be busy or expire between selection and use.
		// Rediscover all candidates, without selecting that empty pool again.
		if exclude == nil {
			exclude = make(map[*routePool]bool)
		}
		exclude[missed] = true
	}
}

func (p *plannedTransport) roundTrip(request *http.Request, exclude map[*routePool]bool) (*http.Response, *routePool, error) {
	plan, err := p.plan(request)
	if err != nil {
		if request.Body != nil {
			_ = request.Body.Close()
		}
		return nil, nil, err
	}
	if plan.Close != nil {
		defer plan.Close()
	}
	var pool *routePool
	// Join selection before releasing this lease: an evicted pool's Close
	// waits for its Dial callback, which is still waiting for the race workers.
	defer func() {
		if pool != nil {
			p.release(pool)
		}
	}()
	var selection *routeDial
	if plan.Next != nil {
		selection = newRouteDial(request.Context(), plan, exclude)
		defer selection.close(p)
		request = request.WithContext(context.WithValue(request.Context(), routeDialKey{}, selection))
	}
	pool, err = p.acquire(plan)
	if err != nil {
		if request.Body != nil {
			_ = request.Body.Close()
		}
		return nil, nil, err
	}
	cachedOnly := false
	for {
		attempt := new(*request)
		var body *routeAttemptBody
		if request.Body != nil && request.Body != http.NoBody {
			body = &routeAttemptBody{ReadCloser: request.Body}
			attempt.Body = body
		}
		if !p.packet {
			attempt = watchHTTP1Upload(attempt)
		}
		response, err := pool.transport.RoundTrip(preserveRequestRejection(attempt, p.packet))
		if p.packet {
			err = preserveHTTP3Rejection(request, err)
		}
		changed, redirected := errors.AsType[*routeChanged](err)
		safe := response == nil && request.Context().Err() == nil && (body == nil || !body.read.Load())
		retry := redirected && safe
		miss := cachedOnly && errors.Is(err, errNoCachedConnection) && safe
		if !retry && !miss && body != nil {
			body.commit()
		}
		if err == nil {
			responsePool := pool
			pool = nil // Transfer the lease to the response body.
			wrapped := &plannedResponseBody{ReadCloser: response.Body, release: sync.OnceFunc(func() { p.release(responsePool) })}
			if writer, ok := response.Body.(io.Writer); ok {
				response.Body = &plannedReadWriteBody{plannedResponseBody: wrapped, Writer: writer}
			} else {
				response.Body = wrapped
			}
			return response, nil, nil
		}
		if miss {
			return nil, pool, nil
		}
		if !retry {
			if p.packet {
				err = markHTTP3ConnectionFailure(err, err)
			}
			return response, nil, err
		}
		next := changed.pool
		if next.plan.Check != nil {
			if err := next.plan.Check(); err != nil {
				if body != nil {
					body.commit()
					_ = body.Close()
				}
				return nil, nil, err
			}
		}
		if !p.retain(next) {
			return nil, next, nil
		}
		p.release(pool)
		pool = next
		cachedOnly = true
		probe := new(atomic.Bool)
		probe.Store(true)
		ctx := context.WithValue(request.Context(), routeDialKey{}, (*routeDial)(nil))
		ctx = context.WithValue(ctx, cachedRouteKey{}, probe)
		// Once a connection was acquired, native transport retries may dial.
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { probe.Store(false) }})
		request = request.WithContext(ctx)
	}
}

type upstreamDialError struct{ error }

func (e *upstreamDialError) Unwrap() error { return e.error }

// A transport closes Body even when dialing failed before it could read it.
// Keep that untouched stream available to the next route, then transfer normal
// asynchronous body ownership to the transport that actually uses it.
type routeAttemptBody struct {
	io.ReadCloser
	read              atomic.Bool
	mu                sync.Mutex
	committed, closed bool
	closeOnce         sync.Once
	closeErr          error
}

func (b *routeAttemptBody) Read(p []byte) (int, error) {
	b.read.Store(true)
	b.commit()
	return b.ReadCloser.Read(p)
}

func (b *routeAttemptBody) commit() {
	b.mu.Lock()
	b.committed = true
	closed := b.closed
	b.mu.Unlock()
	if closed {
		_ = b.Close()
	}
}

func (b *routeAttemptBody) Close() error {
	b.mu.Lock()
	b.closed = true
	committed := b.committed
	b.mu.Unlock()
	if !committed {
		return nil
	}
	b.closeOnce.Do(func() { b.closeErr = b.ReadCloser.Close() })
	return b.closeErr
}

// acquire owns planning and cache lookup. A successful acquisition transfers
// request-body closure to the underlying transport and leases its pool until
// the response finishes (or RoundTrip fails).
func (p *plannedTransport) acquire(plan UpstreamPlan) (*routePool, error) {
	if plan.Check != nil {
		if err := plan.Check(); err != nil {
			return nil, err
		}
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	p.serial++
	pool := p.pools[plan.Key]
	var closeEvicted func()
	if pool == nil {
		// Retired pools remain owned until their active response bodies finish.
		// In particular, evicting an HTTP/3 pool must not abort other streams.
		if len(p.pools) >= 32 {
			var oldestKey string
			oldest := p.serial
			for key, entry := range p.pools {
				if entry.used < oldest {
					oldestKey, oldest = key, entry.used
				}
			}
			entry := p.pools[oldestKey]
			delete(p.pools, oldestKey)
			closeEvicted = p.releaseLocked(entry)
		}
		plan.Next, plan.Close = nil, nil
		pool = &routePool{refs: 1, plan: plan} // Cache reference.
		var closePool func()
		if p.packet {
			dial := plan.DialPacket
			transport := p.host.http3Transport(func(ctx context.Context, address string) (net.PacketConn, net.Addr, error) {
				conn, peer, err := dial(ctx, address)
				if err != nil {
					err = &upstreamDialError{err}
				}
				return conn, peer, err
			})
			pool.connectQUIC = transport.Dial
			transport.Dial = func(ctx context.Context, address string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
				conn, err := p.dialQUIC(ctx, pool, address, tlsConfig, config)
				if err != nil {
					err = &upstreamQUICDialError{err}
				}
				return conn, err
			}
			pool.transport, closePool = transport, func() { _ = transport.Close() }
		} else {
			transport := p.host.httpTransport(func(ctx context.Context, network, address string) (net.Conn, error) {
				conn, err := p.dialStream(ctx, pool, network, address)
				if err != nil {
					err = &upstreamDialError{err}
				}
				return conn, err
			})
			pool.transport, closePool = transport, transport.CloseIdleConnections
		}
		p.pools[plan.Key] = pool
		p.owned[pool] = closePool
	}
	pool.used, pool.refs = p.serial, pool.refs+1
	p.mu.Unlock()
	if closeEvicted != nil {
		closeEvicted()
	}
	return pool, nil
}

// Retain the actual selected pool, including one evicted from the cache.
func (p *plannedTransport) retain(pool *routePool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.owned[pool] == nil {
		return false
	}
	pool.refs++
	p.serial++
	pool.used = p.serial
	return true
}

// Taking the callback under mu transfers exclusive cleanup ownership. A
// concurrent transport close can take it instead; no per-pool Once is needed.
func (p *plannedTransport) releaseLocked(pool *routePool) func() {
	pool.refs--
	if pool.refs != 0 {
		return nil
	}
	closePool := p.owned[pool]
	delete(p.owned, pool)
	return closePool
}

func (p *plannedTransport) release(pool *routePool) {
	p.mu.Lock()
	closePool := p.releaseLocked(pool)
	p.mu.Unlock()
	if closePool != nil {
		closePool()
	}
}

func (p *plannedTransport) close() {
	p.mu.Lock()
	p.closed = true
	for _, pool := range p.pools {
		pool.refs-- // Drop the cache reference; active exchanges finish later.
	}
	pools := p.owned
	var prepared []*connectedRoute
	for pool := range pools {
		prepared = append(prepared, pool.prepared...)
		pool.prepared = nil
	}
	p.pools, p.owned = nil, nil
	p.mu.Unlock()
	for _, route := range prepared {
		route.close()
	}
	for _, closePool := range pools {
		closePool()
	}
}

type plannedResponseBody struct {
	io.ReadCloser
	release func() // OnceFunc shared by Read and Close.
}

type plannedReadWriteBody struct {
	*plannedResponseBody
	io.Writer
}

func (b *plannedReadWriteBody) CloseWrite() error {
	if writer, ok := b.ReadCloser.(netproxy.CloseWriter); ok {
		return writer.CloseWrite()
	}
	return errors.ErrUnsupported
}

// An upgrade's read EOF only closes one direction. Keep the pool leased until
// ReverseProxy closes both directions, including any trailing client upload.
func (b *plannedReadWriteBody) Read(data []byte) (int, error) {
	return b.ReadCloser.Read(data)
}

func (b *plannedResponseBody) Read(data []byte) (int, error) {
	n, err := b.ReadCloser.Read(data)
	if err != nil {
		b.release()
	}
	return n, err
}

func (b *plannedResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.release()
	return err
}
