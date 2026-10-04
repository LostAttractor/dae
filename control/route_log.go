// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"bytes"
	"encoding/hex"
	"net"
	"net/netip"
	"strconv"

	"github.com/daeuniverse/dae/common/consts"
	log "github.com/sirupsen/logrus"
)

const routeLogMessage = "route"

func RefineSourceToShow(src netip.AddrPort, dst netip.Addr) string {
	if src.Addr() == dst {
		// If nothing else, this means this packet is sent from localhost.
		return net.JoinHostPort("localhost", strconv.Itoa(int(src.Port())))
	}
	return RefineAddrPortToShow(src)
}

func RefineAddrPortToShow(addrPort netip.AddrPort) string {
	return net.JoinHostPort(net.IP(addrPort.Addr().AsSlice()).String(), strconv.Itoa(int(addrPort.Port())))
}

func ProcessName2String(pname []uint8) string {
	return string(bytes.TrimRight(pname, "\x00"))
}

func Mac2String(mac []uint8) string {
	ori := []byte(hex.EncodeToString(mac))
	// Insert ":".
	b := make([]byte, len(ori)/2*3-1)
	for i, j := 0, 0; i < len(ori); i, j = i+2, j+3 {
		copy(b[j:j+2], ori[i:i+2])
		if j+2 < len(b) {
			b[j+2] = ':'
		}
	}
	return string(b)
}

func routingLogFields(routingResult *routingResult, interfaceName string) log.Fields {
	fields := make(log.Fields)
	if routingResult.Pid != 0 {
		fields["pid"] = routingResult.Pid
	}
	if pname := ProcessName2String(routingResult.Pname[:]); pname != "" {
		fields["pname"] = pname
	}
	if interfaceName != "" {
		fields["interface"] = interfaceName
	}
	if routingResult.Dscp != 0 {
		fields["dscp"] = routingResult.Dscp
	}
	if routingResult.Mac != [6]uint8{} {
		fields["mac"] = Mac2String(routingResult.Mac[:])
	}
	return fields
}

func routeLogFields(routingResult *routingResult, interfaceName, network, source, destination string) log.Fields {
	fields := routingLogFields(routingResult, interfaceName)
	fields["action"] = "forward"
	fields["network"] = network
	fields["source"] = source
	fields["destination"] = destination
	return fields
}

func (c *ControlPlane) interfaceName(ifindex uint32) string {
	if ifindex == 0 || c == nil || c.core == nil || c.core.ifmgr == nil {
		return ""
	}
	return c.core.ifmgr.NameByIndex(int(ifindex))
}

func (c *ControlPlane) logDial(src, dst netip.AddrPort, domain string, dialOption *DialOption, network string, routingResult *routingResult) {
	if log.IsLevelEnabled(log.InfoLevel) {
		destinationIP := RefineAddrPortToShow(dst)
		fields := routeLogFields(
			routingResult,
			c.interfaceName(routingResult.Ifindex),
			network,
			RefineSourceToShow(src, dst.Addr()),
			dialOption.DialTarget,
		)
		fields["target_kind"] = dialOption.Outbound.TargetKind.String()
		if dialOption.DialTarget != destinationIP {
			fields["destination_ip"] = destinationIP
		}
		if domain != "" {
			fields["sniffed"] = domain
		}
		fields["dialer"] = dialOption.Dialer.Name
		if consts.OutboundIndex(routingResult.Outbound) == consts.OutboundControlPlaneRouting {
			fields["control_plane_route"] = true
		}
		if dialOption.Outbound.Name == consts.OutboundBlock.String() {
			fields["action"] = "block"
		}
		if dialOption.FallbackIpVersion || dialOption.OriginalOutbound != nil {
			fields["fallback"] = true
		}
		fields["outbound"] = dialOption.Outbound.Name
		if dialOption.OriginalOutbound != nil {
			fields["original_outbound"] = dialOption.OriginalOutbound.Name
			if policy := dialOption.OriginalOutbound.DisplayPolicy(); policy != "" {
				fields["original_policy"] = policy
			}
		} else {
			if policy := dialOption.Outbound.DisplayPolicy(); policy != "" {
				fields["policy"] = policy
			}
		}
		log.WithFields(fields).Info(routeLogMessage)
	}
}
