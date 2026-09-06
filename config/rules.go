// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"net/netip"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type Rules struct {
	Rules []*config_parser.RoutingRule `mapstructure:"_"`
}

func (r Rules) Destinations() (routing.DestinationRewrites, error) {
	result := make(routing.DestinationRewrites, 0, len(r.Rules))
	for i, rule := range r.Rules {
		if rule == nil {
			return nil, fmt.Errorf("rules: nil rule at %d", i+1)
		}
		a := rule.Outbound
		if a.Name != "dnat" || a.Not || a.Quoted || len(a.Params) != 1 || a.Params[0].Key != "" || a.Params[0].AndFunctions != nil || len(a.Params[0].Annotation) != 0 {
			return nil, fmt.Errorf("rules rule %d: expected dnat(ip) with exactly one IP argument", i+1)
		}
		ip, err := netip.ParseAddr(a.Params[0].Val)
		if err != nil || ip.Zone() != "" {
			return nil, fmt.Errorf("rules rule %d: dnat target must be an IPv4 or IPv6 address without a port or zone", i+1)
		}
		if len(rule.AndFunctions) == 0 {
			return nil, fmt.Errorf("rules rule %d: empty filter", i+1)
		}
		result = append(result, routing.DestinationRewrite{Filter: rule.AndFunctions, To: []netip.Addr{ip.Unmap()}, Proxy: true})
	}
	return result, nil
}
