/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
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
				"outboundId": outbound,
			}).Debugf("Outbound <%v> %v -> %v, notify the kernel program.", outboundName, networkType.String(), state)
		}

		key := bpfOutboundConnectivityQuery{
			Outbound:  outbound,
			L4proto:   networkType.L4Proto.ToL4Proto(),
			Ipversion: networkType.IpVersion.ToIpVersion(),
		}
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

		network := common.NetworkTypeToIndex(networkType)
		previous := c.outboundConnectivityMap[outbound][network].Load()
		value := encodeOutboundConnectivity(available, noConnectivityTrySniff, noConnectivityOutbound)
		if err := updateKernel(value); err != nil {
			rollbackValue := encodeOutboundConnectivity(previous, noConnectivityTrySniff, noConnectivityOutbound)
			return errors.Join(err, updateKernel(rollbackValue))
		}

		recovered := c.recordOutboundConnectivity(outbound, network, available)
		if recovered != nil {
			recovered()
		}
		return nil
	}
}

func (c *controlPlaneCore) setOutboundRecoveryCallback(callback func()) {
	c.outboundRecovery = callback
}

func (c *controlPlaneCore) recordOutboundConnectivity(outbound uint8, network int, available bool) func() {
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

func (c *controlPlaneCore) anyOutboundAvailable(network int) bool {
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
	return c.outboundConnectivityMap[outbound][common.NetworkTypeToIndex(&networkType)].Load()
}
