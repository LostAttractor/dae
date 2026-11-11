// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"github.com/daeuniverse/dae/internal/routingabi"
	"maps"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/pluginhost"
	log "github.com/sirupsen/logrus"
)

// A replaced generation admits queued setups for
// this bounded interval; accepted relays retain their own resources afterwards.
const handoffLifetime = routingabi.HANDOFF_LIFETIME_SECONDS * time.Second

// ErrPublicationRejected means the candidate failed before touching the active
// generation or its links. The caller can discard it and resume the old API.
var ErrPublicationRejected = errors.New("configuration publication rejected")

// observeDNS registers the response's evidence in every serving generation and
// returns the journal append of its new pairs, or nil, to run after delivery.
func (c *ControlPlane) observeDNS(request *plugin.DNSExchange, response *plugin.DNSResponse, at time.Time) (journal func()) {
	if c.core.bpf == nil || c.core.bpf.Runtime == nil {
		return observeDNSRegistryAt(c.core.domainRegistry, c.routingMatcher.domainMatcher.MatchDomainBitmap, request, response, at)
	}
	observations := dnsEvidence(request, response, at)
	if len(observations) == 0 {
		return nil
	}
	r := c.core.bpf.Runtime
	// A delivered observation either precedes a reload's evidence copy or
	// reaches the new generation too: forks and plane insertion hold the
	// write lock. Registry work stays outside r.mu, which UDP ingress and TCP
	// admission take per packet and connection. The journal append needs
	// neither lock: it rechecks file ownership, and a reload leaves pairs
	// queued meanwhile to the successor's worker.
	r.dnsFanout.RLock()
	defer r.dnsFanout.RUnlock()
	r.mu.Lock()
	planes := slices.Collect(maps.Values(r.planes))
	r.mu.Unlock()
	// Only the generation that owns the files queues a journal append.
	for _, plane := range planes {
		if appendNew := plane.core.domainRegistry.observeEvidence(plane.routingMatcher.domainMatcher.MatchDomainBitmap, observations, at); appendNew != nil {
			journal = appendNew
		}
	}
	return journal
}

// Runtime owns resources whose lifetime is independent of configuration reload.
// Generations own private programs/projections and references to shared services.
type Runtime struct {
	lifecycle      sync.Mutex
	mu             sync.Mutex   // generation admission and retirement
	dnsFanout      sync.RWMutex // orders DNS evidence fanout with reload forks
	current        *ControlPlane
	planes         map[uint32]*ControlPlane
	shared         map[string]*ebpf.Map
	nextGeneration uint32
	retired        <-chan struct{}
	done           chan struct{}
	errors         chan error
	closeOnce      sync.Once
	closeErr       error
	offline        bool // Terminal transition, guarded by lifecycle.
	online         bool // Published DAEMON_ONLINE once, guarded by lifecycle.
	kernelOwned    bool // Set before this Runtime starts netns/sysctl setup.

	kernelLinks       kernelLinks
	tcpConnections    tcpConnectionSet
	udpEndpoints      *UdpEndpointPool
	deviceRoutes      *deviceRoutes
	fallbacks         *fallbackTokens
	tcpMonitor        tcpRelayMonitor
	listener          *Listener
	ingress           sync.WaitGroup
	soMarkFromDae     uint32
	outboundResources outbound.Resources
	pluginStates      pluginhost.StatePool
	interfaces        *network.InterfaceManager
}

func NewRuntime() *Runtime {
	return &Runtime{planes: make(map[uint32]*ControlPlane), shared: make(map[string]*ebpf.Map), udpEndpoints: new(UdpEndpointPool),
		done: make(chan struct{}), errors: make(chan error, 1)}
}

// SharedStates is scoped to each plugin instance by pluginhost during preparation.
func (r *Runtime) SharedStates() plugin.SharedStates { return &r.pluginStates }

// RelearnNodes makes node entry dials resolve node names and probe MPTCP again.
func (r *Runtime) RelearnNodes() { r.outboundResources.Paths.Relearn() }

// Interfaces returns the process-owned interface event source. Callers borrow
// scopes; the source remains alive until every generation has drained.
func (r *Runtime) Interfaces() (*network.InterfaceManager, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.done:
		return nil, net.ErrClosed
	default:
	}
	if r.interfaces == nil {
		var err error
		r.interfaces, err = network.NewInterfaceManager()
		if err != nil {
			return nil, err
		}
	}
	return r.interfaces, nil
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
		"socket_owner_map":      b.SocketOwnerMap,
		"daemon_identity_map":   b.DaemonIdentityMap,
		"device_routes_map":     b.DeviceRoutesMap,
		"exited_map":            b.ExitedMap,
		"fallback_lease_map":    b.FallbackLeaseMap,
		"fallback_sequence_map": b.FallbackSequenceMap,
		"listen_socket_map":     b.ListenSocketMap, "redirect_track": b.RedirectTrack,
		"routing_tuples_map":     b.RoutingTuplesMap,
		"tcp_flow_map":           b.TcpFlowMap,
		"tcp_proxy_socket_map":   b.TcpProxySocketMap,
		"tcp_handshake_gate_map": b.TcpHandshakeGateMap,
		"udp_bindings_map":       b.UdpBindingsMap, "udp_conn_state_map": b.UdpConnStateMap,
		"udp_inbound_pending_map": b.UdpInboundPendingMap,
		"udp_routing_cache_map":   b.UdpRoutingCacheMap,
	} {
		owned, err := m.Clone()
		if err != nil {
			return fmt.Errorf("retain %s: %w", name, err)
		}
		r.shared[name] = owned
	}
	r.deviceRoutes = &deviceRoutes{outer: r.shared["device_routes_map"]}
	if err := restoreDeviceEpochs(r.deviceRoutes); err != nil {
		return fmt.Errorf("restore device route epochs: %w", err)
	}
	r.fallbacks = newFallbackTokens(r.shared["fallback_lease_map"], r.shared["fallback_sequence_map"])
	return nil
}

// Publish refreshes private maps after the old API has drained. Once
// attachment updates begin, failure is terminal; Runtime still owns every
// generation and return path needed to abort traffic safely.
func (r *Runtime) Publish(c *ControlPlane, abort bool) (err error) {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	select {
	case <-r.done:
		return net.ErrClosed
	default:
	}
	if r.offline {
		return net.ErrClosed
	}
	if r.shared["exited_map"] != nil {
		r.mu.Lock()
		ready := r.listener != nil
		r.mu.Unlock()
		if !ready {
			return fmt.Errorf("%w: datapath listener is not ready", ErrPublicationRejected)
		}
	}
	// Static rules and subscriptions are already prepared. Only selections
	// and changed client tries need refreshing after draining API writers.
	if err := c.restoreRuntimeSettings(true); err != nil {
		return fmt.Errorf("%w: %w", ErrPublicationRejected, err)
	}
	exports, err := c.prepareClientExports()
	if err != nil {
		return fmt.Errorf("%w: prepare client exports: %w", ErrPublicationRejected, err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, exports.Rollback())
		} else if cleanup := exports.Commit(); cleanup != nil {
			log.WithError(cleanup).Warn("Remove client export backups after activation")
		}
	}()
	old, err := r.forkGeneration(c)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPublicationRejected, err)
	}
	if old != nil {
		if err := old.core.quiesce(); err != nil {
			return err
		}
		if old.hostReconcileDone != nil {
			<-old.hostReconcileDone
		}
		c.InheritConnections(old)
	}
	var previous *mitm.Host
	var handoff *mitmHandoff
	if old != nil {
		previous = old.MITMHost()
		if !previous.SameInstances(c.mitmHost) {
			if abort {
				// Wake retired hosts without canceling workers retained by the current host.
				old.interruptSetups()
			}
			old.retiredHosts.Wait()
			handoff = old.pauseMITM(&c.planeHTTP)
			defer func() { handoff.complete(err) }()
		}
	}
	releaseWorkers, err := previous.DrainFor(c.mitmHost, abort)
	if err != nil {
		return err
	}
	defer releaseWorkers()
	if old != nil {
		if err := r.kernelLinks.updatePrograms(old.core.bpf.bpfObjects, c.core.bpf.bpfObjects); err != nil {
			return err
		}
	}
	if err := exports.Apply(); err != nil {
		return err
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
		// Rebuilt instances belong only to the new routing generation. The
		// closed predecessor rejects late setups instead of mixing their policies.
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
	if err := r.setExited(routingabi.DAEMON_ONLINE); err != nil {
		return fmt.Errorf("publish online datapath: %w", err)
	}
	// Optional cleanup: a leftover pin costs memory, not correctness.
	if err := r.pruneUDPTimerPins(true); err != nil {
		log.WithError(err).Warn("Retire unreferenced runtime timer pins")
	}
	return nil
}

// forkGeneration copies the current generation's evidence into c and admits
// it. The caller holds lifecycle, which excludes other publications; c is not
// admitted before it joins planes, so the copy and its kernel writes need not
// stall ingress under r.mu.
func (r *Runtime) forkGeneration(c *ControlPlane) (*ControlPlane, error) {
	r.mu.Lock()
	old := r.current
	r.mu.Unlock()
	if old != nil {
		// DNS delivery waits for the fanout lock, so join the old worker
		// first: its current job can be an fdatasync or a compaction.
		old.core.domainRegistry.stopWorker()
	}
	r.dnsFanout.Lock()
	defer r.dnsFanout.Unlock()
	if old != nil {
		if err := c.core.domainRegistry.ForkFrom(old.core.domainRegistry, c.routingMatcher.domainMatcher.MatchDomainBitmap, time.Now()); err != nil {
			return nil, err
		}
	}
	r.mu.Lock()
	r.planes[c.routingGeneration] = c
	r.mu.Unlock()
	return old, nil
}

func (r *Runtime) reportError(err error) {
	select {
	case r.errors <- err:
	default:
	}
}

func (r *Runtime) setExited(value uint8) error {
	if m := r.shared["exited_map"]; m != nil {
		if err := m.Update(uint32(0), value, ebpf.UpdateAny); err != nil {
			return err
		}
		r.online = r.online || value == routingabi.DAEMON_ONLINE
	}
	return nil
}

func (r *Runtime) goOffline() error {
	r.offline = true
	err := r.setExited(routingabi.DAEMON_OFFLINE)
	if r.fallbacks != nil {
		r.fallbacks.Freeze()
	}
	return err
}

// GoOffline marks userspace offline before management requests are drained.
func (r *Runtime) GoOffline() error {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	select {
	case <-r.done:
		return r.closeErr
	default:
		return r.goOffline()
	}
}

// Close drains userspace and removes this Runtime's kernel resources. A runtime
// that took over a crash-retained datapath removes it only once online.
func (r *Runtime) Close() error {
	r.closeOnce.Do(func() {
		r.lifecycle.Lock()
		defer r.lifecycle.Unlock()
		r.closeErr = r.goOffline()
		close(r.done)
		r.pluginStates.StopAcquiring()
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
				r.closeErr = errors.Join(r.closeErr, err)
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
		if err := r.pluginStates.Close(); err != nil {
			log.WithError(err).Warn("Close shared plugin state")
		}
		if r.interfaces != nil {
			r.closeErr = errors.Join(r.closeErr, r.interfaces.Close())
		}
		// Until it goes online, a takeover leaves a crashed predecessor's
		// datapath to unexpected_exit_behavior, as that crash did.
		retain := r.kernelLinks.inherited && !r.online
		if retain {
			log.Warn("Startup did not go online; keeping the kernel datapath left by the previous unexpected exit")
			// Keep the timer pins the retained programs still reference.
			r.closeErr = errors.Join(r.closeErr, r.pruneUDPTimerPins(false))
		}
		r.closeErr = errors.Join(r.closeErr, r.kernelLinks.Close(retain))
		r.tcpMonitor.close()
		for _, m := range r.shared {
			r.closeErr = errors.Join(r.closeErr, m.Close())
		}
		if r.kernelOwned {
			if ns := GetDaeNetns(); ns != nil {
				r.closeErr = errors.Join(r.closeErr, ns.Close())
			}
			CloseSysctlManager()
		}
		if r.closeErr == nil && !retain {
			r.closeErr = r.removePins()
		}
	})
	return r.closeErr
}
