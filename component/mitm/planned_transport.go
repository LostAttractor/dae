// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
)

// UpstreamPlanner runs after request middleware, before connection-pool lookup.
// Key identifies the complete immutable plan, including protocol, node, mark
// and actual addresses. URL/TLS authority remains the transport's responsibility.
type UpstreamPlanner func(*http.Request) (UpstreamPlan, error)

type UpstreamPlan struct {
	Key        string
	Dial       DialContext
	DialPacket DialPacketContext
}

type plannedTransport struct {
	host   *Host
	packet bool
	plan   UpstreamPlanner
	mu     sync.Mutex
	closed bool
	serial uint64
	pools  map[string]*routePool
	owned  map[*routePool]struct{}
}

type routePool struct {
	transport http.RoundTripper
	close     func()
	once      sync.Once
	used      uint64
	active    int
	retired   bool
}

func (h *Host) plannedTransport(plan UpstreamPlanner, packet bool) *plannedTransport {
	return &plannedTransport{host: h, packet: packet, plan: plan, pools: make(map[string]*routePool), owned: make(map[*routePool]struct{})}
}

func (p *plannedTransport) RoundTrip(request *http.Request) (response *http.Response, err error) {
	delegated := false
	defer func() {
		if !delegated && request.Body != nil {
			_ = request.Body.Close()
		}
	}()
	if p.plan == nil {
		return nil, fmt.Errorf("mitm: missing upstream planner")
	}
	plan, err := p.plan(request)
	if err != nil {
		return nil, err
	}
	if plan.Key == "" || p.packet && plan.DialPacket == nil || !p.packet && plan.Dial == nil {
		return nil, fmt.Errorf("mitm: incomplete upstream plan")
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	p.serial++
	pool := p.pools[plan.Key]
	var evicted *routePool
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
			entry.retired = true
			if entry.active == 0 {
				delete(p.owned, entry)
				evicted = entry
			}
		}
		pool = &routePool{}
		if p.packet {
			transport := p.host.http3Transport(plan.DialPacket)
			pool.transport, pool.close = transport, func() { _ = transport.Close() }
		} else {
			transport := p.host.httpTransport(plan.Dial)
			pool.transport, pool.close = transport, transport.CloseIdleConnections
		}
		p.pools[plan.Key] = pool
		p.owned[pool] = struct{}{}
	}
	pool.used, pool.active = p.serial, pool.active+1
	p.mu.Unlock()
	if evicted != nil {
		evicted.once.Do(evicted.close)
	}
	delegated = true
	response, err = pool.transport.RoundTrip(request)
	if err != nil || response.Body == nil {
		p.release(pool)
	} else {
		body := &plannedResponseBody{ReadCloser: response.Body, release: func() { p.release(pool) }}
		if writer, ok := response.Body.(io.Writer); ok {
			// HTTP/1 upgrades retain bidirectional body access for ReverseProxy.
			response.Body = &plannedReadWriteBody{plannedResponseBody: body, Writer: writer}
		} else {
			response.Body = body
		}
	}
	return response, err
}

func (p *plannedTransport) release(pool *routePool) {
	p.mu.Lock()
	pool.active--
	closePool := pool.retired && pool.active == 0
	if closePool {
		delete(p.owned, pool)
	}
	p.mu.Unlock()
	if closePool {
		pool.once.Do(pool.close)
	}
}

func (p *plannedTransport) close() {
	p.mu.Lock()
	p.closed = true
	pools := p.owned
	p.pools, p.owned = nil, nil
	p.mu.Unlock()
	for pool := range pools {
		pool.once.Do(pool.close)
	}
}

type plannedResponseBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

type plannedReadWriteBody struct {
	*plannedResponseBody
	io.Writer
}

func (b *plannedResponseBody) Read(data []byte) (int, error) {
	n, err := b.ReadCloser.Read(data)
	if err != nil {
		b.once.Do(b.release)
	}
	return n, err
}

func (b *plannedResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}
