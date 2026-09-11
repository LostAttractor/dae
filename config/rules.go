// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type Rules struct {
	Rules []*config_parser.RoutingRule `mapstructure:"_"`
}

// RulePlan separates orthogonal flow controls from first-match destination
// rewrites. None of these actions selects an ordinary routing outbound.
type RulePlan struct {
	Destinations routing.DestinationRewrites
	Controls     []routing.FlowRule
}

func (r Rules) Plan() (RulePlan, error) {
	var result RulePlan
	for i, rule := range r.Rules {
		if rule == nil {
			return RulePlan{}, fmt.Errorf("rules: nil rule at %d", i+1)
		}
		a := rule.Outbound
		if len(rule.AndFunctions) == 0 {
			return RulePlan{}, fmt.Errorf("rules rule %d: empty filter", i+1)
		}
		if a.Not || a.Quoted {
			return RulePlan{}, fmt.Errorf("rules rule %d: actions cannot be quoted or negated", i+1)
		}
		switch a.Name {
		case "must", consts.OutboundControlPlaneRouting.String():
			if len(a.Params) != 0 {
				return RulePlan{}, fmt.Errorf("rules rule %d: %s takes no arguments", i+1, a.Name)
			}
			control := routing.FlowRule{Filter: rule.AndFunctions, Action: consts.MatchActionBump}
			if a.Name == "must" {
				control.Action = consts.MatchActionMust
			}
			result.Controls = append(result.Controls, control)
			continue
		case "dnat":
			if len(a.Params) != 1 || a.Params[0] == nil || a.Params[0].Key != "" || a.Params[0].AndFunctions != nil || len(a.Params[0].Annotation) != 0 {
				return RulePlan{}, fmt.Errorf("rules rule %d: expected dnat(ip) with exactly one IP argument", i+1)
			}
		default:
			return RulePlan{}, fmt.Errorf("rules rule %d: expected dnat(ip), must or bump", i+1)
		}
		ip, err := netip.ParseAddr(a.Params[0].Val)
		var port uint16
		if err != nil {
			var target netip.AddrPort
			target, err = netip.ParseAddrPort(a.Params[0].Val)
			if err == nil && target.Port() == 0 {
				err = fmt.Errorf("zero port")
			}
			if err == nil {
				ip, port = target.Addr(), target.Port()
			}
		}
		if err != nil || ip.Zone() != "" {
			return RulePlan{}, fmt.Errorf("rules rule %d: dnat target must be an IP or IP:port without a zone", i+1)
		}
		result.Destinations = append(result.Destinations, routing.DestinationRewrite{Filter: rule.AndFunctions, To: []netip.Addr{ip.Unmap()}, Port: port})
	}
	return result, nil
}

func (r Rules) Destinations() (routing.DestinationRewrites, error) {
	plan, err := r.Plan()
	return plan.Destinations, err
}
