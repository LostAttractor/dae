// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"net"
	"net/netip"
	"strconv"
)

// Preserve the original LAN peer for the daemon's HTTP API, including when the
// configured fallback is a proxy. Only exact host addresses and this TCP port
// bypass routing; changes to interface addresses are picked up on reload.
func (p *preparedRules) bypassAPI(port uint16, addresses []net.Addr) {
	if port == 0 {
		return
	}
	var hosts []*config_parser.Param
	seen := make(map[netip.Addr]bool)
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			continue
		}
		ip := prefix.Addr().Unmap()
		if (!ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() && !ip.IsLoopback()) || seen[ip] {
			continue
		}
		hosts = append(hosts, &config_parser.Param{Val: ip.String()})
		seen[ip] = true
	}
	if len(hosts) == 0 {
		return
	}
	rule := &config_parser.RoutingRule{
		AndFunctions: []*config_parser.Function{
			{Name: "dip", Params: hosts},
			{Name: "dport", Params: []*config_parser.Param{{Val: strconv.Itoa(int(port))}}},
			{Name: "l4proto", Params: []*config_parser.Param{{Val: "tcp"}}},
		},
		Outbound: config_parser.Function{Name: consts.OutboundDirect.String()},
	}
	p.routing = append([]*config_parser.RoutingRule{rule}, p.routing...)
}
