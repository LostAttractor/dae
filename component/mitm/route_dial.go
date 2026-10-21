// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"iter"
	"net"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/pkg/outbound/happyeyeballs"
	"github.com/daeuniverse/quic-go"
)

// Shared transport dials must give every waiter the same destination pool.
type routeChanged struct{ pool *routePool }

func (*routeChanged) Error() string { return "mitm: connection selected another route" }

var errNoCachedConnection = errors.New("mitm: route has no cached connection")

type routeDialKey struct{}
type cachedRouteKey struct{}

type connectedRoute struct {
	pool   *routePool
	stream net.Conn
	packet *quic.Conn
}

func (r *connectedRoute) close() {
	if r.stream != nil {
		_ = r.stream.Close()
	}
	if r.packet != nil {
		_ = r.packet.CloseWithError(0, "")
	}
}

// Selection owns a pool reference until RoundTrip has acquired its own. The
// pool owns prepared connections; any waiter may consume one exactly once.
type routeDial struct {
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	first   UpstreamPlan
	exclude map[*routePool]bool // Pools whose cache-only attempt missed.
	result  *connectedRoute
}

func newRouteDial(ctx context.Context, first UpstreamPlan, exclude map[*routePool]bool) *routeDial {
	ctx, cancel := context.WithCancel(ctx)
	return &routeDial{ctx: ctx, cancel: cancel, first: first, exclude: exclude}
}

func (d *routeDial) close(p *plannedTransport) {
	d.cancel()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.result != nil {
		p.mu.Lock()
		pool := d.result.pool
		index := slices.Index(pool.prepared, d.result)
		if index >= 0 {
			pool.prepared = slices.Delete(pool.prepared, index, index+1)
		}
		p.mu.Unlock()
		if index >= 0 {
			d.result.close()
		}
		p.release(pool)
	}
}

func (d *routeDial) connect(parent context.Context, p *plannedTransport, current *routePool, attempt func(context.Context, *routePool) (*connectedRoute, error)) (*connectedRoute, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(d.ctx, cancel)
	defer stop()
	defer cancel()
	if d.result == nil {
		route, err := happyeyeballs.Race(ctx, func(ctx context.Context) iter.Seq2[UpstreamPlan, error] {
			return func(yield func(UpstreamPlan, error) bool) {
				plan := d.first
				for yield(plan, nil) && plan.Next != nil {
					var err error
					plan, err = plan.Next(ctx)
					if errors.Is(err, io.EOF) {
						return
					}
					if err != nil {
						yield(UpstreamPlan{}, err)
						return
					}
				}
			}
		}, func(ctx context.Context, plan UpstreamPlan) (*connectedRoute, error) {
			if plan.Key == "" || p.packet && plan.DialPacket == nil || !p.packet && plan.Dial == nil {
				return nil, errors.New("mitm: incomplete fallback upstream plan")
			}
			if plan.Check != nil {
				if err := plan.Check(); err != nil {
					return nil, err
				}
			}
			p.mu.Lock()
			cached := p.pools[plan.Key]
			if cached != nil && cached != current && !d.exclude[cached] {
				cached.refs++
			} else {
				cached = nil
			}
			p.mu.Unlock()
			if cached != nil {
				return &connectedRoute{pool: cached}, nil
			}
			pool, err := p.acquire(plan)
			if err != nil {
				return nil, err
			}
			route, err := attempt(ctx, pool)
			if err != nil {
				p.release(pool)
			}
			return route, err
		}, func(route *connectedRoute) { route.close(); p.release(route.pool) })
		if err != nil {
			return nil, err
		}
		d.result = route
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			route.close()
			return nil, net.ErrClosed
		}
		if route.pool == current {
			p.mu.Unlock()
			return route, nil
		}
		if route.stream != nil || route.packet != nil {
			route.pool.prepared = append(route.pool.prepared, route)
		}
		p.mu.Unlock()
	}
	if d.result.pool != current {
		return nil, &routeChanged{pool: d.result.pool}
	}
	return attempt(ctx, current)
}

func (p *plannedTransport) takePrepared(pool *routePool) *connectedRoute {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(pool.prepared) == 0 || p.closed {
		return nil
	}
	route := pool.prepared[0]
	pool.prepared = slices.Delete(pool.prepared, 0, 1)
	return route
}

func (p *plannedTransport) dialStream(ctx context.Context, pool *routePool, network, address string) (net.Conn, error) {
	if route := p.takePrepared(pool); route != nil {
		return route.stream, nil
	}
	if cached, _ := ctx.Value(cachedRouteKey{}).(*atomic.Bool); cached != nil && cached.Load() {
		return nil, errNoCachedConnection
	}
	if selection, _ := ctx.Value(routeDialKey{}).(*routeDial); selection != nil {
		route, err := selection.connect(ctx, p, pool, func(ctx context.Context, pool *routePool) (*connectedRoute, error) {
			conn, err := pool.plan.Dial(ctx, network, address)
			return &connectedRoute{pool: pool, stream: conn}, err
		})
		if err != nil {
			return nil, err
		}
		return route.stream, nil
	}
	return pool.plan.Dial(ctx, network, address)
}

func (p *plannedTransport) dialQUIC(ctx context.Context, pool *routePool, address string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
	if route := p.takePrepared(pool); route != nil {
		return route.packet, nil
	}
	if cached, _ := ctx.Value(cachedRouteKey{}).(*atomic.Bool); cached != nil && cached.Load() {
		return nil, errNoCachedConnection
	}
	if selection, _ := ctx.Value(routeDialKey{}).(*routeDial); selection != nil {
		route, err := selection.connect(ctx, p, pool, func(ctx context.Context, pool *routePool) (*connectedRoute, error) {
			conn, err := pool.connectQUIC(ctx, address, tlsConfig, config)
			return &connectedRoute{pool: pool, packet: conn}, err
		})
		if err != nil {
			return nil, err
		}
		return route.packet, nil
	}
	return pool.connectQUIC(ctx, address, tlsConfig, config)
}
