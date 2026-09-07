// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	log "github.com/sirupsen/logrus"
)

const routeLogMessage = "route"

func routingLogFields(routingResult *bpfRoutingResult, interfaceName string) log.Fields {
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

func routeLogFields(routingResult *bpfRoutingResult, interfaceName, network, source, destination string) log.Fields {
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

func (c *ControlPlane) logDial(src, dst netip.AddrPort, domain string, dialOption *DialOption, network string, routingResult *bpfRoutingResult) {
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
