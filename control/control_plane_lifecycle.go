/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/daeuniverse/dae/component/outbound"
	log "github.com/sirupsen/logrus"
)

// Activate commits the in-memory control plane to the kernel:
//   - writes routing rules to BPF maps,
//   - clears reload-inherited UDP route cache entries while preserving TCP state,
//   - drops stale domain routing entries inherited from the previous plane
//     (when reloading without an adopted domain registry),
//   - binds eBPF programs to LAN/WAN interfaces and the dae netns,
//   - publishes the prepared outbound connectivity state.
//
// It must be called exactly once after NewControlPlane succeeds. An activation
// failure is terminal: the BPF state may be partially committed, so the caller
// must close the plane and exit rather than retrying or restoring the old plane.
func (c *ControlPlane) Activate() error {
	started := time.Now()
	core := c.core
	core.lifecycleMu.Lock()
	defer core.lifecycleMu.Unlock()
	if core.closed.Err() != nil {
		return net.ErrClosed
	}
	builder := c.routingMatcherBuilder
	if err := c.restoreRuntimeSettings(true); err != nil {
		return err
	}

	// The caller has already retired the previous plane on reload. Only now
	// may the candidate publish its routing and connectivity state.
	c.reconcileStats()
	for _, group := range c.outbounds {
		group.PublishStats()
	}
	if err := c.commitKernelState(builder); err != nil {
		return err
	}
	if err := c.syncClientExports(); err != nil {
		return err
	}
	if err := core.publishOutboundConnectivity(); err != nil {
		return err
	}
	// Bind every interface only after connectivity initialization, so traffic
	// cannot observe partially published outbound state.
	if err := core.setupExitHandler(); err != nil {
		return fmt.Errorf("failed to setup exit handler: %w", err)
	}
	if err := core.bindDaens(); err != nil {
		return fmt.Errorf("bindDaens: %w", err)
	}
	if err := c.bindHostInterfaces(); err != nil {
		return err
	}
	for _, g := range c.outbounds {
		g.EnableSelectionTolerance()
	}
	c.kernelActive = true
	log.WithFields(log.Fields{"window": core.domainRegistry.window, "activity": "userspace and captured splice", "kernel_capacity": core.domainRegistry.kernel.max}).Info("Domain retention active; uncaptured kernel-direct traffic does not refresh evidence")
	if c.domainRegistryPath != "" {
		core.domainRegistry.EnablePersistence(c.domainRegistryPath)
	}
	if c.mitmHost != nil {
		if err := c.mitmHost.Start(c.ctx); err != nil {
			return err
		}
	}
	SetAnyfromSoMark(c.soMarkFromDae)
	log.WithField("duration", time.Since(started)).Debug("Control plane activated")
	return nil
}

func (c *ControlPlane) commitKernelState(builder *RoutingMatcherBuilder) error {
	core := c.core
	if err := c.publishAPIObservation(); err != nil {
		return err
	}
	if err := c.updateRouteExemptions(); err != nil {
		return err
	}
	if err := builder.BuildKernspace(); err != nil {
		return fmt.Errorf("RoutingMatcherBuilder.BuildKernspace: %w", err)
	}
	if !core.isReload && c.domainRegistryPath != "" {
		if err := core.domainRegistry.Restore(c.domainRegistryPath, c.routingMatcher.domainMatcher.MatchDomainBitmap, time.Now()); err != nil {
			log.WithError(err).Warn("Restore domain registry; starting without disk observations")
		}
	}
	if core.isReload {
		if err := deleteUDPRoutingTuples(core.bpf.RoutingTuplesMap); err != nil {
			return fmt.Errorf("clear inherited UDP routing handoff: %w", err)
		}
		if err := deleteUDPRoutingCache(core.bpf.UdpRoutingCacheMap, true); err != nil {
			return fmt.Errorf("clear inherited UDP routing cache: %w", err)
		}
	}
	if core.isReload && !core.domainRegistry.Adopted() {
		log.Warnln("Reload without an adopted domain registry: wiping the inherited kernel domain map; domain routing restarts from scratch")
		var key [4]uint32
		var val bpfDomainRouting
		iter := core.bpf.DomainRoutingMap.Iterate()
		for iter.Next(&key, &val) {
			if err := core.bpf.DomainRoutingMap.Delete(&key); err != nil {
				return fmt.Errorf("failed to wipe inherited domain routing entry %v: %w", key, err)
			}
		}
		if err := iter.Err(); err != nil {
			return fmt.Errorf("failed to iterate inherited domain routing map: %w", err)
		}
	}
	return nil
}

// EjectBpf releases this plane's cleanup ownership of the shared BPF state and
// returns it for a reload candidate. The state remains unowned until InjectBpf.
func (c *ControlPlane) EjectBpf() *BPFState {
	c.core.domainRegistry.activity.prepareHandoff()
	return c.core.EjectBpf()
}

// SetDomainRegistryPath selects the state file before activation. Reload uses
// in-memory adoption; cold starts restore observations from this path.
func (c *ControlPlane) SetDomainRegistryPath(path string) { c.domainRegistryPath = path }

// InjectBpf makes this plane responsible for closing the shared BPF state.
func (c *ControlPlane) InjectBpf() {
	c.core.InjectBpf()
}

// InheritDomainRegistry transfers DNS domain -> IP registrations of a
// retired plane into this plane's registry, recomputing every domain's match
// bitmap with this plane's routing rules, and syncs the shared kernel domain
// map to the adopted state. Retention deadlines survive unchanged except for
// actual connection activity observed during the handoff.
// This must be called after the old plane is
// retired (its writers stopped, its kernel programs detached) and before
// Activate, which then skips wiping the kernel map. Domain routing and
// sniff verification therefore survive a reload instead of waiting for every
// domain to be re-resolved.
//
// It panics if the old plane is not fully closed: adoption rewrites the
// shared kernel map while the old plane's TCX programs might still read
// it (old rules with new-rule bitmaps = misrouting), and the old
// registry's writers would fight the adopted state.
func (c *ControlPlane) InheritDomainRegistry(old *ControlPlane) {
	if !old.closedDone.Load() {
		panic("InheritDomainRegistry: old control plane is not fully closed")
	}
	c.core.domainRegistry.AdoptFrom(
		old.core.domainRegistry,
		c.routingMatcher.domainMatcher.MatchDomainBitmap,
		time.Now(),
	)
}

// StopAndAbortConnections interrupts traffic without waiting for peer EOF or
// handlers to finish. Close must join control-plane users before freeing state.
func (c *ControlPlane) StopAndAbortConnections() error {
	c.abortConnections.Store(true)
	// Retire ingress first: closing a large connection set must not leave the
	// old Accept/Read calls consuming traffic intended for the successor.
	_, err := c.closeIngress()
	c.cancelTCPSetups()
	c.udpTaskPool.cancel()
	c.dnsRelay.stop()
	if c.mitmHost != nil {
		c.mitmHost.Abort()
	}
	for _, conn := range c.tcpConnections.stopAndSnapshot() {
		closeInBackground(conn)
	}
	c.udpEndpoints.closeAll()
	return err
}

func (c *ControlPlane) retireTraffic() error {
	// Stop admitting new work, but keep established QUIC delivery alive until
	// MITM has drained. The successor does not start serving until Close returns.
	keepUDP := c.mitmHost != nil && !c.abortConnections.Load()
	ingress, ingressErr := c.retireIngress(keepUDP)
	c.tcpConnections.stopAccepting()
	c.cancelTCPSetups()
	c.udpTaskPool.close()
	c.tcpConnections.waitForSetups()
	if c.abortConnections.Load() {
		// StopAndAbortConnections performs an initial sweep. Repeat after the
		// task drain to catch an endpoint published by an already-accepted task.
		c.udpEndpoints.closeAll()
	} else {
		c.udpEndpoints.removePending()
	}
	if c.mitmHost != nil {
		ingressErr = errors.Join(ingressErr, c.mitmHost.Close())
	}
	_, closeErr := c.closeIngress()
	// Admission is closed above; join any final reads before releasing maps.
	if ingress != nil {
		ingress.loops.Wait()
	}
	c.cancel()
	return errors.Join(ingressErr, closeErr)
}

// Close drains requests and releases the plane. For terminal shutdown or an
// aborting reload, call StopAndAbortConnections first to skip business draining.
func (c *ControlPlane) Close() (err error) {
	c.core.lifecycleMu.Lock()
	defer c.core.lifecycleMu.Unlock()
	err = c.retireTraffic()
	if c.hostReconcileDone != nil {
		<-c.hostReconcileDone
	}
	// Invoke defer funcs in reverse order.
	for i := len(c.deferFuncs) - 1; i >= 0; i-- {
		err = errors.Join(err, c.deferFuncs[i]())
	}
	err = errors.Join(err, c.core.closeLocked())
	if err == nil {
		c.closedDone.Store(true)
	}
	return err
}

func (c *ControlPlane) InheritConnections(old *ControlPlane) {
	previous := make(map[string]*outbound.DialerGroup, len(old.outbounds))
	for _, group := range old.outbounds {
		previous[group.Name] = group
	}
	for _, group := range c.outbounds {
		if predecessor := previous[group.Name]; predecessor != nil {
			group.InheritConnections(predecessor)
		}
	}
}
