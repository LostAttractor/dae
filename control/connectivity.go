/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	log "github.com/sirupsen/logrus"
)

const (
	// Values stored in outbound_connectivity_map. They encode both the
	// group's actual connectivity and the action for an unannotated rule.
	outboundConnectivityAlive uint32 = iota
	outboundConnectivityNoAliveDirect
	outboundConnectivityNoAliveBlock
	outboundConnectivityNoAliveTrySniff
)

func encodeOutboundConnectivity(alive bool, noConnectivityTrySniff bool, noConnectivityOutbound consts.OutboundIndex) uint32 {
	if alive {
		return outboundConnectivityAlive
	}
	if noConnectivityTrySniff {
		return outboundConnectivityNoAliveTrySniff
	}
	return uint32(noConnectivityOutbound) + outboundConnectivityNoAliveDirect
}

func (c *controlPlaneCore) outboundAliveChangeCallback(outbound uint8, outboundName string, noConnectivityTrySniff bool, noConnectivityOutbound consts.OutboundIndex) func(alive bool, networkType *common.NetworkType) {
	return func(alive bool, networkType *common.NetworkType) {
		if c.closed.Err() != nil {
			return
		}
		if log.IsLevelEnabled(log.DebugLevel) {
			strAlive := "NOT ALIVE"
			if alive {
				strAlive = "ALIVE"
			}
			log.WithFields(log.Fields{
				"outboundId": outbound,
			}).Debugf("Outbound <%v> %v -> %v, notify the kernel program.", outboundName, networkType.String(), strAlive)
		}

		value := encodeOutboundConnectivity(alive, noConnectivityTrySniff, noConnectivityOutbound)

		// Keep the actual liveness in memory for the userspace routing matcher.
		// The eBPF map value also carries the global no-connectivity action, so
		// deriving liveness from that action would conflate alive with
		// dead-but-try-sniff.
		if outbound <= uint8(consts.OutboundUserDefinedMax) {
			c.outboundConnectivityMap[outbound][common.NetworkTypeToIndex(networkType)].Store(alive)
		}

		if err := c.bpf.OutboundConnectivityMap.Update(bpfOutboundConnectivityQuery{
			Outbound:  outbound,
			L4proto:   networkType.L4Proto.ToL4Proto(),
			Ipversion: networkType.IpVersion.ToIpVersion(),
		}, value, ebpf.UpdateAny); err != nil {
			log.WithFields(log.Fields{
				"alive":    alive,
				"network":  networkType.String(),
				"outbound": outboundName,
			}).Warnf("Failed to notify the kernel program: %v", err)
		}
	}
}

// outboundUsable reports whether the outbound group has a live dialer for the
// given network type. A group whose state has never been reported (e.g. before
// the first check completes) is not usable. Unknown network types
// conservatively report usable so that traffic is not unexpectedly rerouted.
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
