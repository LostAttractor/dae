// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

// Rule sets have one action family. Empty sets can be used in either stage.
type RoutingRuleSetKind uint8

const (
	RoutingRuleSetEmpty RoutingRuleSetKind = iota
	RoutingRuleSetRoutes
	RoutingRuleSetFlow
)

// RuleSetKinds checks action families after Validate has checked the structure
// and bounded the reference graph. Compilation uses the same classification.
func (routing *Routing) RuleSetKinds() (map[string]RoutingRuleSetKind, error) {
	sets := make(map[string]RoutingRuleSet, len(routing.RuleSets))
	for _, set := range routing.RuleSets {
		sets[set.Name] = set
	}
	kinds := make(map[string]RoutingRuleSetKind, len(sets))
	var classify func(string, []RoutingStatement) (RoutingRuleSetKind, error)
	classify = func(name string, statements []RoutingStatement) (RoutingRuleSetKind, error) {
		kind := RoutingRuleSetEmpty
		for _, statement := range statements {
			var current RoutingRuleSetKind
			if statement.Kind == RoutingStatementUse {
				var ok bool
				current, ok = kinds[statement.Use]
				if !ok {
					var err error
					current, err = classify(statement.Use, sets[statement.Use].Statements)
					if err != nil {
						return 0, err
					}
					kinds[statement.Use] = current
				}
			} else {
				action := &statement.Rule.Outbound
				if !action.Quoted && (action.Name == "must" || action.Name == "bump" || action.Name == "dnat") {
					if _, err := (Rules{Rules: []*config_parser.RoutingRule{statement.Rule}}).Plan(); err != nil {
						return 0, fmt.Errorf("routing block %q: %w", name, err)
					}
					current = RoutingRuleSetFlow
				} else {
					if err := validateRoutingAction(action); err != nil {
						return 0, fmt.Errorf("routing block %q: %w", name, err)
					}
					current = RoutingRuleSetRoutes
				}
			}
			if current == RoutingRuleSetEmpty {
				continue
			}
			if kind != RoutingRuleSetEmpty && kind != current {
				return 0, fmt.Errorf("routing block %q mixes flow controls and outbounds; flow controls belong in rules {}", name)
			}
			kind = current
		}
		return kind, nil
	}
	for _, set := range routing.RuleSets {
		if _, ok := kinds[set.Name]; ok {
			continue
		}
		kind, err := classify(set.Name, set.Statements)
		if err != nil {
			return nil, err
		}
		kinds[set.Name] = kind
	}
	for _, policy := range routing.Policies {
		kind, err := classify(policy.Name, policy.Statements)
		if err != nil {
			return nil, err
		}
		if kind == RoutingRuleSetFlow {
			return nil, fmt.Errorf("policy %q: flow controls belong in rules {}", policy.Name)
		}
		kind, err = classify(policy.Name+".rules", policy.Rules)
		if err != nil {
			return nil, err
		}
		if kind == RoutingRuleSetRoutes {
			return nil, fmt.Errorf("policy %q rules: expected dnat(ip), must or bump; outbounds belong in the policy body", policy.Name)
		}
		if err := validateRoutingAction(policy.Fallback); err != nil {
			return nil, fmt.Errorf("policy %q fallback: %w", policy.Name, err)
		}
	}
	return kinds, nil
}
