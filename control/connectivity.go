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

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/network"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
)

const (
	// Values stored in outbound_connectivity_map. They encode both the
	// group's actual connectivity and the action for an unannotated rule.
	// Keep the explicit values in sync with enum outbound_connectivity_state
	// in control/kern/tproxy.c: this map is a Go/eBPF ABI boundary.
	outboundConnectivityAlive           uint32 = 0
	outboundConnectivityNoAliveDirect   uint32 = 1
	outboundConnectivityNoAliveBlock    uint32 = 2
	outboundConnectivityNoAliveTrySniff uint32 = 3
)

func encodeOutboundConnectivity(alive bool, noConnectivityTrySniff bool, noConnectivityOutbound consts.OutboundIndex) uint32 {
	if alive {
		return outboundConnectivityAlive
	}
	if noConnectivityTrySniff {
		return outboundConnectivityNoAliveTrySniff
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

func (c *controlPlaneCore) outboundAliveChangeCallback(outbound uint8, outboundName string, noConnectivityTrySniff bool, noConnectivityOutbound consts.OutboundIndex) func(available bool, networkType *common.NetworkType) error {
	return func(available bool, networkType *common.NetworkType) error {
		c.outboundCallbackMu.Lock()
		defer c.outboundCallbackMu.Unlock()
		if c.closed.Err() != nil {
			return c.closed.Err()
		}
		if log.IsLevelEnabled(log.DebugLevel) {
			state := "UNAVAILABLE"
			if available {
				state = "AVAILABLE"
			}
			log.WithFields(log.Fields{
				"outboundId":       outbound,
				"kernel_published": c.outboundConnectivityPublished,
			}).Debugf("Outbound <%v> %v -> %v", outboundName, networkType.String(), state)
		}

		key := bpfOutboundConnectivityQuery{
			Outbound:  outbound,
			L4proto:   networkType.L4Proto.ToL4Proto(),
			Ipversion: networkType.IpVersion.ToIpVersion(),
		}
		network := networkType.Index()
		value := encodeOutboundConnectivity(available, noConnectivityTrySniff, noConnectivityOutbound)
		if !c.outboundConnectivityPublished {
			c.pendingOutboundConnectivity[key] = value
		} else {
			updateKernel := func(value uint32) error {
				if err := c.bpf.OutboundConnectivityMap.Update(key, value, ebpf.UpdateAny); err != nil {
					log.WithFields(log.Fields{
						"network":  networkType.String(),
						"outbound": outboundName,
						"value":    value,
					}).Warnf("Failed to notify the kernel program: %v", err)
					return err
				}
				return nil
			}
			if err := updateKernel(value); err != nil {
				previous := c.outboundConnectivityMap[outbound][network].Load()
				rollbackValue := encodeOutboundConnectivity(previous, noConnectivityTrySniff, noConnectivityOutbound)
				return errors.Join(err, updateKernel(rollbackValue))
			}
		}

		recovered := c.recordOutboundConnectivity(outbound, network, available)
		if recovered != nil {
			recovered()
		}
		return nil
	}
}

// publishOutboundConnectivity runs during activation, after committing routing
// rules and before attaching interfaces. Later checks publish directly to BPF.
func (c *controlPlaneCore) publishOutboundConnectivity() error {
	c.outboundCallbackMu.Lock()
	defer c.outboundCallbackMu.Unlock()
	if c.closed.Err() != nil {
		return c.closed.Err()
	}
	if c.outboundConnectivityPublished {
		return nil
	}
	for key, value := range c.pendingOutboundConnectivity {
		if err := c.bpf.OutboundConnectivityMap.Update(key, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("publish outbound %d connectivity (protocol %d, IPv%d): %w", key.Outbound, key.L4proto, key.Ipversion, err)
		}
	}
	c.pendingOutboundConnectivity = nil
	c.outboundConnectivityPublished = true
	return nil
}

func (c *controlPlaneCore) setOutboundRecoveryCallback(callback func()) {
	c.outboundRecovery = callback
}

func (c *controlPlaneCore) recordOutboundConnectivity(outbound uint8, network common.NetworkIndex, available bool) func() {
	if outbound > uint8(consts.OutboundUserDefinedMax) {
		return nil
	}
	wasAvailable := c.anyOutboundAvailable(network)
	c.outboundConnectivityMap[outbound][network].Store(available)
	if !wasAvailable && available {
		return c.outboundRecovery
	}
	return nil
}

func (c *controlPlaneCore) anyOutboundAvailable(network common.NetworkIndex) bool {
	for outbound := uint8(consts.OutboundUserDefinedMin); outbound <= uint8(consts.OutboundUserDefinedMax); outbound++ {
		if c.outboundConnectivityMap[outbound][network].Load() {
			return true
		}
	}
	return false
}

// outboundUsable reports whether the group can serve the requested network.
// Unknown network masks conservatively remain usable.
func (c *controlPlaneCore) outboundUsable(outbound uint8, l4proto consts.L4ProtoType, ipVersion consts.IpVersionType) bool {
	if outbound > uint8(consts.OutboundUserDefinedMax) {
		return true
	}
	var networkType common.NetworkType
	switch {
	case l4proto&consts.L4ProtoType_TCP != 0:
		networkType.L4Proto = consts.L4ProtoStr_TCP
	case l4proto&consts.L4ProtoType_UDP != 0:
		networkType.L4Proto = consts.L4ProtoStr_UDP
	default:
		return true
	}
	switch {
	case ipVersion&consts.IpVersion_4 != 0:
		networkType.IpVersion = consts.IpVersionStr_4
	case ipVersion&consts.IpVersion_6 != 0:
		networkType.IpVersion = consts.IpVersionStr_6
	default:
		return true
	}
	return c.outboundConnectivityMap[outbound][networkType.Index()].Load()
}

const initialConnectivityTimeout = 60 * time.Second

func (c *ControlPlane) startConnectivityChecks() ([]startupConnectivityWaiter, error) {
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
	checkStart := make(chan struct{})
	waiters := make([]startupConnectivityWaiter, 0, len(c.outbounds))
	for _, group := range c.outbounds {
		ready, err := group.StartConnectivityChecks(checkStart)
		if err != nil {
			return nil, oops.Errorf("start outbound %q connectivity checks: %w", group.Name, err)
		}
		if ready != nil {
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
	for _, group := range c.outbounds {
		if !group.ChecksConnectivity() {
			continue
		}
		for _, d := range group.Dialers {
			d.RequestConnectivityCheck()
		}
	}
}
