// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/control/internal/splice"
)

// Matches HANDOFF_LIFETIME_SECONDS. A replaced generation admits queued setups for
// this bounded interval; accepted relays retain their own resources afterwards.
const handoffLifetime = 30 * time.Second

// ErrPublicationRejected means the candidate failed before touching the active
// generation or its links. The caller can discard it and resume the old API.
var ErrPublicationRejected = errors.New("configuration publication rejected")

func (c *ControlPlane) observeDNS(request *plugin.DNSExchange, response *plugin.DNSResponse, at time.Time) {
	if c.core.bpf == nil || c.core.bpf.Runtime == nil {
		observeDNSRegistryAt(c.core.domainRegistry, c.routingMatcher.domainMatcher.MatchDomainBitmap, request, response, at)
		return
	}
	r := c.core.bpf.Runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, plane := range r.planes {
		observeDNSRegistryAt(plane.core.domainRegistry, plane.routingMatcher.domainMatcher.MatchDomainBitmap, request, response, at)
	}
}

// Runtime owns resources whose lifetime is independent of configuration reload.
// Generations own private programs/projections and references to shared services.
type Runtime struct {
	lifecycle      sync.Mutex
	mu             sync.Mutex // generation admission and retirement
	current        *ControlPlane
	planes         map[uint32]*ControlPlane
	shared         map[string]*ebpf.Map
	nextGeneration uint32
	retired        <-chan struct{}
	done           chan struct{}
	errors         chan error
	closeOnce      sync.Once
	closeErr       error

	kernelLinks       kernelLinks
	tcpConnections    tcpConnectionSet
	udpEndpoints      *UdpEndpointPool
	deviceRoutes      *deviceRoutes
	splice            *splice.Runtime
	listener          *Listener
	ingress           sync.WaitGroup
	soMarkFromDae     uint32
	outboundResources outbound.Resources
}

func NewRuntime() *Runtime {
	return &Runtime{planes: make(map[uint32]*ControlPlane), shared: make(map[string]*ebpf.Map), udpEndpoints: new(UdpEndpointPool),
		done: make(chan struct{}), errors: make(chan error, 1)}
}

func (r *Runtime) IsReload() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current != nil
}

func (r *Runtime) waitForRetirement(ctx context.Context) error {
	r.mu.Lock()
	done := r.retired
	r.mu.Unlock()
	if done == nil {
		return ctx.Err()
	}
	select {
	case <-done:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	case <-r.done:
		return net.ErrClosed
	}
}

func (r *Runtime) retainMaps(b *bpfObjects) error {
	for name, m := range map[string]*ebpf.Map{
		"cookie_pid_map":    b.CookiePidMap,
		"device_routes_map": b.DeviceRoutesMap, "unused_device_routes": b.UnusedDeviceRoutes,
		"exited_map": b.ExitedMap, "listen_socket_map": b.ListenSocketMap,
		"redirect_track": b.RedirectTrack, "routing_tuples_map": b.RoutingTuplesMap,
		"tcp_flow_map":     b.TcpFlowMap,
		"udp_bindings_map": b.UdpBindingsMap, "udp_conn_state_map": b.UdpConnStateMap,
		"udp_routing_cache_map": b.UdpRoutingCacheMap,
	} {
		owned, err := m.Clone()
		if err != nil {
			return fmt.Errorf("retain %s: %w", name, err)
		}
		r.shared[name] = owned
	}
	r.deviceRoutes = &deviceRoutes{outer: r.shared["device_routes_map"]}
	return nil
}

// Publish refreshes private maps after the old API has drained. Once
// attachment updates begin, failure is terminal; Runtime still owns every
// generation and return path needed to abort traffic safely.
func (r *Runtime) Publish(c *ControlPlane, abort bool) error {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	select {
	case <-r.done:
		return net.ErrClosed
	default:
	}
	// Static rules and subscriptions are already prepared. Only selections
	// and changed client tries need refreshing after draining API writers.
	if err := c.restoreRuntimeSettings(true); err != nil {
		return fmt.Errorf("%w: %w", ErrPublicationRejected, err)
	}
	r.mu.Lock()
	old := r.current
	if old != nil {
		c.core.domainRegistry.ForkFrom(old.core.domainRegistry, c.routingMatcher.domainMatcher.MatchDomainBitmap, time.Now())
	}
	r.planes[c.routingGeneration] = c
	r.mu.Unlock()
	if old != nil {
		if err := old.core.quiesce(); err != nil {
			return err
		}
		if old.hostReconcileDone != nil {
			<-old.hostReconcileDone
		}
		c.InheritConnections(old)
	}
	if old != nil {
		if err := r.kernelLinks.updatePrograms(old.core.bpf.bpfObjects, c.core.bpf.bpfObjects); err != nil {
			return err
		}
	}
	if err := c.activateLinks(); err != nil {
		return err
	}
	r.mu.Lock()
	r.current = c
	r.mu.Unlock()
	// New workers can use routing immediately. Acquire shared worker ownership
	// before stopping the predecessor, including an explicit connection abort.
	if c.mitmHost != nil {
		if err := c.mitmHost.Start(c.ctx); err != nil {
			return err
		}
	}
	if old != nil {
		old.MITMHost().StopWorkers()
		if abort {
			old.StopAndAbortConnections()
		}
	}
	if old != nil {
		finished := make(chan struct{})
		r.mu.Lock()
		r.retired = finished
		r.mu.Unlock()
		go func() {
			defer close(finished)
			if !abort {
				timer := time.NewTimer(handoffLifetime)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-r.done:
				}
			}
			// Keep ownership visible to terminal shutdown until Close finishes.
			// The tracker's stopped transition serializes with Runtime admission.
			if err := old.Close(); err != nil {
				r.reportError(err)
			}
			r.mu.Lock()
			delete(r.planes, old.routingGeneration)
			r.mu.Unlock()
		}()
	}
	return nil
}

func (r *Runtime) reportError(err error) {
	select {
	case r.errors <- err:
	default:
	}
}

func (r *Runtime) Close() error {
	r.closeOnce.Do(func() {
		r.lifecycle.Lock()
		defer r.lifecycle.Unlock()
		close(r.done)
		r.mu.Lock()
		planes := slices.Collect(maps.Values(r.planes))
		clear(r.planes)
		r.current = nil
		listener := r.listener
		r.mu.Unlock()
		aborted := r.tcpConnections.abort()
		// Cancel every generation before taking UDP source locks: an endpoint
		// may still be dialing under one of those locks.
		for _, c := range planes {
			c.interruptTraffic()
		}
		r.udpEndpoints.closeAll()
		if listener != nil {
			if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				r.closeErr = err
			}
		}
		r.ingress.Wait()
		for _, c := range planes {
			r.closeErr = errors.Join(r.closeErr, c.Close())
		}
		if r.retired != nil {
			<-r.retired
		}
		<-aborted
		r.closeErr = errors.Join(r.closeErr, r.kernelLinks.Close())
		if r.splice != nil {
			r.closeErr = errors.Join(r.closeErr, r.splice.Close())
		}
		for _, m := range r.shared {
			r.closeErr = errors.Join(r.closeErr, m.Close())
		}
	})
	return r.closeErr
}
