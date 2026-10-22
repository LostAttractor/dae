/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/internal/routingabi"
	log "github.com/sirupsen/logrus"
)

const (
	// States stored in outbound_connectivity_map. They encode both the
	// group's actual connectivity and the action for an unannotated rule.
	outboundConnectivityAlive            uint32 = routingabi.OUTBOUND_CONNECTIVITY_ALIVE
	outboundConnectivityNoAliveDirect    uint32 = routingabi.OUTBOUND_CONNECTIVITY_NOALIVE_DIRECT
	outboundConnectivityNoAliveBlock     uint32 = routingabi.OUTBOUND_CONNECTIVITY_NOALIVE_BLOCK
	outboundConnectivityNoAliveUserspace uint32 = routingabi.OUTBOUND_CONNECTIVITY_NOALIVE_USERSPACE
)

func encodeOutboundConnectivity(alive, admitted bool, noConnectivityOutbound consts.OutboundIndex) uint32 {
	if alive {
		return outboundConnectivityAlive
	}
	if admitted {
		return outboundConnectivityNoAliveUserspace
	}
	switch noConnectivityOutbound {
	case consts.OutboundDirect:
		return outboundConnectivityNoAliveDirect
	case consts.OutboundBlock:
		return outboundConnectivityNoAliveBlock
	default:
		panic("invalid no-connectivity outbound")
	}
}

// The kernel forwards a group's direct fallback itself. Its token ties those
// flows to the group's fallback generation, so connection policies end them
// with the generation's relays.
func (c *controlPlaneCore) outboundConnectivityValue(update outbound.Connectivity, admitted bool, noConnectivityOutbound consts.OutboundIndex) bpfOutboundConnectivity {
	value := bpfOutboundConnectivity{State: encodeOutboundConnectivity(update.Available, admitted, noConnectivityOutbound)}
	if value.State == outboundConnectivityNoAliveDirect && c.bpf != nil && c.bpf.Runtime != nil {
		value.Fallback = c.bpf.fallbacks.token(update.Fallback)
	}
	return value
}

// With reroute_mode while_possible, flows to an unavailable group enter
// userspace instead of degrading in the kernel, to try a sniffed name.
func (c *controlPlaneCore) outboundAliveChangeCallback(id uint8, outboundName string, whilePossible bool, noConnectivityOutbound consts.OutboundIndex) func(outbound.Connectivity) error {
	return func(update outbound.Connectivity) error {
		c.outboundCallbackMu.Lock()
		defer c.outboundCallbackMu.Unlock()
		if c.closed != nil && c.closed.Err() != nil {
			return c.closed.Err()
		}
		networkType := update.Network
		if log.IsLevelEnabled(log.TraceLevel) {
			state := "UNAVAILABLE"
			if update.Available {
				state = "AVAILABLE"
			}
			log.WithFields(log.Fields{
				"outboundId":       id,
				"kernel_published": c.outboundConnectivityPublished,
			}).Debugf("Outbound <%v> %v -> %v", outboundName, networkType.String(), state)
		}

		key := bpfOutboundConnectivityQuery{
			Outbound:  id,
			L4proto:   networkType.L4Proto.ToL4Proto(),
			Ipversion: networkType.IpVersion.ToIpVersion(),
		}
		value := c.outboundConnectivityValue(update, whilePossible, noConnectivityOutbound)
		wasAvailable := c.anyOutboundAvailable(networkType.Index())
		if err := c.writeOutboundConnectivity(map[bpfOutboundConnectivityQuery]bpfOutboundConnectivity{key: value}); err != nil {
			return fmt.Errorf("publish %s connectivity for %s: %w", networkType, outboundName, err)
		}
		// A recovery from no usable outbound at all rechecks the others.
		if !wasAvailable && update.Available && c.outboundRecovery != nil {
			c.outboundRecovery()
		}
		return nil
	}
}

// writeOutboundConnectivity applies all values or none. Before publication it
// only prepares them for publishOutboundConnectivity.
func (c *controlPlaneCore) writeOutboundConnectivity(values map[bpfOutboundConnectivityQuery]bpfOutboundConnectivity) error {
	if c.outboundConnectivityPublished {
		var written []bpfOutboundConnectivityQuery
		for key, value := range values {
			if previous, ok := c.outboundConnectivityValues[key]; ok && previous == value {
				continue
			}
			written = append(written, key)
			if err := c.bpf.OutboundConnectivityMap.Update(key, value, ebpf.UpdateAny); err != nil {
				err = fmt.Errorf("protocol %d, IPv%d (state %d): %w", key.L4proto, key.Ipversion, value.State, err)
				for _, key := range written {
					if previous, ok := c.outboundConnectivityValues[key]; ok {
						err = errors.Join(err, c.bpf.OutboundConnectivityMap.Update(key, previous, ebpf.UpdateAny))
					}
				}
				return err
			}
		}
	}
	if c.outboundConnectivityValues == nil {
		c.outboundConnectivityValues = make(map[bpfOutboundConnectivityQuery]bpfOutboundConnectivity)
	}
	maps.Copy(c.outboundConnectivityValues, values)
	return nil
}

// publishOutboundConnectivity initializes the candidate's private map after
// uploading routing rules. Later checks publish directly to that map.
func (c *controlPlaneCore) publishOutboundConnectivity() error {
	c.outboundCallbackMu.Lock()
	defer c.outboundCallbackMu.Unlock()
	if c.closed.Err() != nil {
		return c.closed.Err()
	}
	if c.outboundConnectivityPublished {
		return nil
	}
	for key, value := range c.outboundConnectivityValues {
		if err := c.bpf.OutboundConnectivityMap.Update(key, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("publish outbound %d connectivity (protocol %d, IPv%d): %w", key.Outbound, key.L4proto, key.Ipversion, err)
		}
	}
	c.outboundConnectivityPublished = true
	return nil
}

func (c *controlPlaneCore) setOutboundRecoveryCallback(callback func()) {
	c.outboundCallbackMu.Lock()
	defer c.outboundCallbackMu.Unlock()
	c.outboundRecovery = callback
}

// anyOutboundAvailable reports whether this plane published any user-defined
// outbound as alive on the network. Caller holds outboundCallbackMu.
func (c *controlPlaneCore) anyOutboundAvailable(network common.NetworkIndex) bool {
	l4proto, ipversion := network.NetworkType().L4Proto.ToL4Proto(), network.NetworkType().IpVersion.ToIpVersion()
	for key, value := range c.outboundConnectivityValues {
		if key.Outbound >= uint8(consts.OutboundUserDefinedMin) && key.L4proto == l4proto && key.Ipversion == ipversion && value.State == outboundConnectivityAlive {
			return true
		}
	}
	return false
}

const initialConnectivityTimeout = 60 * time.Second

func (c *ControlPlane) watchConnectivity() {
	c.connectivityOutbounds.Store(new(c.outbounds))
	core := c.core
	core.netmon.Register(func(previous, current network.HostNetworkSnapshot) {
		if c.ctx.Err() != nil {
			return
		}
		if current.ConnectivityChanged(previous) {
			c.requestConnectivityRechecks()
		}
		if c.autoWan {
			c.requestHostReconcile()
		}
	})
	core.setOutboundRecoveryCallback(c.requestConnectivityRechecks)
}

func startConnectivityChecks(groups []*outbound.DialerGroup, async []bool) ([]startupConnectivityWaiter, error) {
	checkStart := make(chan struct{})
	waiters := make([]startupConnectivityWaiter, 0, len(groups))
	for i, group := range groups {
		ready, err := group.StartConnectivityChecks(checkStart)
		if err != nil {
			return nil, fmt.Errorf("start outbound %q connectivity checks: %w", group.Name, err)
		}
		if ready != nil && !async[i] {
			waiters = append(waiters, startupConnectivityWaiter{name: group.Name, ready: ready})
		}
	}
	close(checkStart)
	return waiters, nil
}

type startupConnectivityWaiter struct {
	name  string
	ready <-chan struct{}
}

func waitForStartupConnectivity(waiters []startupConnectivityWaiter, timeout time.Duration, stop <-chan struct{}) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for i, waiter := range waiters {
		select {
		case <-waiter.ready:
			continue
		case <-stop:
			return net.ErrClosed
		case <-timer.C:
		}
		select {
		case <-stop:
			return net.ErrClosed
		default:
		}
		for _, pending := range waiters[i:] {
			select {
			case <-pending.ready:
			default:
				log.WithField("group", pending.name).Warn(
					"No usable candidate before the startup connectivity deadline; startup continues and checking remains active",
				)
			}
		}
		return nil
	}
	select {
	case <-stop:
		return net.ErrClosed
	default:
		return nil
	}
}

func (c *ControlPlane) requestConnectivityRechecks() {
	if c.ctx.Err() != nil {
		return
	}
	groups := c.connectivityOutbounds.Load()
	if groups == nil {
		return
	}
	for _, group := range *groups {
		if !group.ChecksConnectivity() {
			continue
		}
		for _, d := range group.Dialers {
			d.RequestConnectivityCheck()
		}
	}
}

func (c *ControlPlane) startConnectivity(startupCtx context.Context) error {
	for _, group := range c.outbounds {
		group.DeferStats()
	}
	if err := c.restoreRuntimeSettings(false); err != nil {
		return err
	}
	c.watchConnectivity()
	connectivityStarted := time.Now()
	waiters, err := startConnectivityChecks(c.outbounds, c.outboundCheckAsync)
	if err != nil {
		return err
	}
	remaining := max(initialConnectivityTimeout-time.Since(connectivityStarted), 0)
	if err := waitForStartupConnectivity(waiters, remaining, startupCtx.Done()); err != nil {
		return err
	}
	log.WithField("duration", time.Since(connectivityStarted)).Debug("Initial connectivity checks finished")

	return nil
}
