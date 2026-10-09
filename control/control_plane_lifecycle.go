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

// PrepareKernel populates only this generation's private routing environment.
// It is safe to discard a failed candidate while Runtime keeps serving traffic.
func (c *ControlPlane) PrepareKernel() error {
	if c.kernelReady {
		return nil
	}
	if err := c.restoreRuntimeSettings(false); err != nil {
		return err
	}
	if err := c.commitKernelState(c.routingMatcherBuilder); err != nil {
		return err
	}
	if err := c.core.publishOutboundConnectivity(); err != nil {
		return err
	}
	c.routingMatcherBuilder = nil
	c.kernelReady = true
	return nil
}

func (c *ControlPlane) activateLinks() error {
	started := time.Now()
	core := c.core
	core.lifecycleMu.Lock()
	defer core.lifecycleMu.Unlock()
	if core.closed.Err() != nil {
		return net.ErrClosed
	}

	// Runtime has stopped the old plane's interface and connectivity writers.
	c.reconcileStats()
	for _, group := range c.outbounds {
		group.PublishStats()
	}
	if err := c.syncClientExports(); err != nil {
		return err
	}
	// Keep inherited attachments live, and only prune interfaces no longer used.
	if err := core.setupExitHandler(); err != nil {
		return fmt.Errorf("failed to setup exit handler: %w", err)
	}
	if err := core.bindDaens(); err != nil {
		return fmt.Errorf("bindDaens: %w", err)
	}
	core.beginRebind()
	if err := c.bindHostInterfaces(); err != nil {
		return err
	}
	if err := core.finishRebind(); err != nil {
		return fmt.Errorf("retire removed interface attachments: %w", err)
	}
	for _, g := range c.outbounds {
		g.EnableSelectionTolerance()
	}
	log.WithFields(log.Fields{"window": core.domainRegistry.window, "activity": "userspace and captured splice", "kernel_capacity": core.domainRegistry.kernel.max}).Info("Domain retention active; uncaptured kernel-direct traffic does not refresh evidence")
	if c.domainRegistryPath != "" {
		core.domainRegistry.EnablePersistence(c.domainRegistryPath)
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
	return nil
}

// SetDomainRegistryPath selects the state file before activation. Reload uses
// in-memory adoption; cold starts restore observations from this path.
func (c *ControlPlane) SetDomainRegistryPath(path string) { c.domainRegistryPath = path }

func (c *ControlPlane) Runtime() *Runtime { return c.core.bpf.Runtime }

// StopAndAbortConnections interrupts traffic without waiting for peer EOF or
// handlers to finish. Close must join control-plane users before freeing state.
func (c *ControlPlane) StopAndAbortConnections() {
	c.interruptTraffic()
	c.udpEndpoints.closeAll()
}

func (c *ControlPlane) interruptTraffic() {
	c.abortConnections.Store(true)
	// Stop this generation's admission before aborting Runtime-owned sockets.
	c.tcpConnections.abort()
	c.cancelTCPSetups()
	c.udpTaskPool.cancel()
	c.dnsRelay.stop()
	if host := c.MITMHost(); host != nil {
		host.Abort()
	}
}

func (c *ControlPlane) retireTraffic() error {
	// Close generation admission. Established QUIC delivery continues through
	// Runtime's current plane while MITM drains.
	var ingressErr error
	c.udpDraining.Store(true)
	c.tcpConnections.stopAccepting()
	c.cancelTCPSetups()
	c.udpTaskPool.close()
	c.tcpConnections.waitForSetups()
	if c.abortConnections.Load() {
		// StopAndAbortConnections performs an initial sweep. Repeat after the
		// task drain to catch an endpoint published by an already-accepted task.
		c.udpEndpoints.closeGeneration(c.routingGeneration)
	} else {
		c.udpEndpoints.removePending(c)
	}
	if host := c.MITMHost(); host != nil {
		host.StopWorkers()
	}
	c.workerRoundTrips.Wait()
	if host := c.MITMHost(); host != nil {
		ingressErr = errors.Join(ingressErr, host.Close())
	}
	c.retiredHosts.Wait()
	c.tcpConnections.waitForAbort()
	c.cancel()
	return ingressErr
}

// Close drains requests and releases the plane. For terminal shutdown or an
// aborting reload, call StopAndAbortConnections first to skip business draining.
func (c *ControlPlane) Close() (err error) {
	c.core.lifecycleMu.Lock()
	defer c.core.lifecycleMu.Unlock()
	if c.closedDone.Load() {
		return c.closeErr
	}
	err = c.retireTraffic()
	err = errors.Join(err, c.core.quiesce())
	if c.hostReconcileDone != nil {
		<-c.hostReconcileDone
	}
	// Invoke defer funcs in reverse order.
	for i := len(c.deferFuncs) - 1; i >= 0; i-- {
		err = errors.Join(err, c.deferFuncs[i]())
	}
	err = errors.Join(err, c.core.closeLocked())
	c.closeErr = err
	c.closedDone.Store(true)
	return err
}

func (c *ControlPlane) InheritConnections(old *ControlPlane) {
	previous := make(map[string]*outbound.DialerGroup, len(old.outbounds))
	for _, group := range old.outbounds {
		previous[group.Name] = group
	}
	for _, group := range c.outbounds {
		if predecessor := previous[group.Name]; predecessor != nil && predecessor != group {
			group.InheritConnections(predecessor)
		}
	}
}
