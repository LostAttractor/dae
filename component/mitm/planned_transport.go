// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/internal/pluginctx"
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
	// Next advances to another independently keyed route after a dial failure,
	// before any request body was consumed. Close releases the candidate stream
	// when this request finishes selecting a connection (also on a pool hit).
	Next  func() (UpstreamPlan, error)
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
	transport http.RoundTripper
	used      uint64
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
	plan, err := p.plan(request)
	if err != nil {
		if request.Body != nil {
			_ = request.Body.Close()
		}
		return nil, err
	}
	if plan.Close != nil {
		defer plan.Close()
	}
	var failures []error
	for {
		pool, err := p.acquire(plan)
		if err != nil {
			if request.Body != nil {
				_ = request.Body.Close()
			}
			return nil, errors.Join(append(failures, err)...)
		}
		attempt := new(*request)
		var body *routeAttemptBody
		if request.Body != nil && request.Body != http.NoBody {
			body = &routeAttemptBody{ReadCloser: request.Body}
			attempt.Body = body
		}
		response, err := pool.transport.RoundTrip(attempt)
		_, dialFailed := errors.AsType[*upstreamDialError](err)
		retry := err != nil && response == nil && dialFailed && plan.Next != nil &&
			request.Context().Err() == nil && (body == nil || !body.read.Load())
		if !retry && body != nil {
			body.commit()
		}
		if err == nil {
			wrapped := &plannedResponseBody{ReadCloser: response.Body, release: sync.OnceFunc(func() { p.release(pool) })}
			if writer, ok := response.Body.(io.Writer); ok {
				response.Body = &plannedReadWriteBody{plannedResponseBody: wrapped, Writer: writer}
			} else {
				response.Body = wrapped
			}
			return response, nil
		}
		p.release(pool)
		failures = append(failures, err)
		if !retry {
			return response, errors.Join(failures...)
		}
		plan, err = plan.Next()
		if err == nil && (plan.Key == "" || p.packet && plan.DialPacket == nil || !p.packet && plan.Dial == nil) {
			err = fmt.Errorf("mitm: incomplete fallback upstream plan")
		}
		if err != nil {
			if body != nil {
				body.commit()
				_ = body.Close()
			}
			return nil, errors.Join(append(failures, err)...)
		}
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
		pool = &routePool{refs: 1} // Cache reference.
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
			pool.transport, closePool = transport, func() { _ = transport.Close() }
		} else {
			dial := plan.Dial
			transport := p.host.httpTransport(func(ctx context.Context, network, address string) (net.Conn, error) {
				conn, err := dial(ctx, network, address)
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
	p.pools, p.owned = nil, nil
	p.mu.Unlock()
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
