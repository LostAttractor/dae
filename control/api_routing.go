// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func (p *preparedRules) bypassLocalAPI(port uint16) error {
	if port == 0 {
		return nil
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("read host addresses for API routing: %w", err)
	}
	p.bypassAPI(port, addresses)
	return nil
}

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
		key := bpfIpPort{Port: common.Htons(port)}
		key.Ip.U6Addr8 = ip.As16()
		p.apiBypass = append(p.apiBypass, key)
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
	p.bypass = append(p.bypass, rule)
}

// The API changes membership itself, so its local TCP connection must survive
// that change. Refresh the same exact address/port exclusions on activation.
func (c *ControlPlane) updateRouteExemptions() error {
	m := c.core.bpf.RouteExemptMap
	var key bpfIpPort
	var value uint8
	it := m.Iterate()
	for it.Next(&key, &value) {
		if err := m.Delete(&key); err != nil {
			return err
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, key := range c.apiBypass {
		if err := m.Update(&key, uint8(1), ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}
