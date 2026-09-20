// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
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

func (p *plannedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	pool, err := p.acquire(request)
	if err != nil {
		if request.Body != nil {
			_ = request.Body.Close()
		}
		return nil, err
	}
	response, err := pool.transport.RoundTrip(request)
	if err != nil {
		p.release(pool)
		return response, err
	}
	body := &plannedResponseBody{ReadCloser: response.Body, release: sync.OnceFunc(func() { p.release(pool) })}
	if writer, ok := response.Body.(io.Writer); ok {
		// HTTP/1 upgrades retain bidirectional body access for ReverseProxy.
		response.Body = &plannedReadWriteBody{plannedResponseBody: body, Writer: writer}
	} else {
		response.Body = body
	}
	return response, nil
}

// acquire owns planning and cache lookup. A successful acquisition transfers
// request-body closure to the underlying transport and leases its pool until
// the response finishes (or RoundTrip fails).
func (p *plannedTransport) acquire(request *http.Request) (*routePool, error) {
	plan, err := p.plan(request)
	if err != nil {
		return nil, err
	}
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
			transport := p.host.http3Transport(plan.DialPacket)
			pool.transport, closePool = transport, func() { _ = transport.Close() }
		} else {
			transport := p.host.httpTransport(plan.Dial)
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
