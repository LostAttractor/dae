// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"slices"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/surgemodule"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// Pre-matching reject rules precede user rules. Ordinary module rules follow
// explicit user rules but precede fallback; a module DIRECT can never override
// the user's selected block or explicitly configured proxy. Capture and API
// routing rules are prepended separately.
func (p *preparedRules) enableSurgeModuleRules(engine *surgemodule.Engine) {
	var early, normal []*config_parser.RoutingRule
	for _, rule := range engine.ModuleRules() {
		policy := consts.OutboundBlock.String()
		if rule.Policy == "DIRECT" {
			policy = consts.OutboundDirect.String()
		}
		for _, clause := range rule.RoutingClauses() {
			compiled := &config_parser.RoutingRule{Outbound: config_parser.Function{Name: policy}}
			for _, predicate := range clause {
				key, value := predicate.DomainParameter()
				compiled.AndFunctions = append(compiled.AndFunctions, &config_parser.Function{
					Name: consts.Function_Domain, Not: predicate.Not, Params: []*config_parser.Param{{Key: key, Val: value}},
				})
			}
			if rule.PreMatching {
				early = append(early, compiled)
			} else {
				normal = append(normal, compiled)
			}
		}
	}
	p.routing = slices.Concat(early, p.routing, normal)
}
