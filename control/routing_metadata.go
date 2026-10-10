// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"maps"
	"slices"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// Metadata is a side table: instruction layouts, jumps and kernel map values
// remain independent of source text and diagnostic requests.
type routingRuleMetadata struct {
	start, end uint32
	expression string
	sources    []api.DiagnosticSource
	owner      string
}

type routingMatchMetadata struct {
	expression string
	function   string
	client     string
}

func (b *RoutingMatcherBuilder) rememberMatch(index int, f *config_parser.Function) {
	if b.matchMetadata == nil {
		b.matchMetadata = make(map[uint32]routingMatchMetadata)
	}
	text := f.String(false, true, false)
	if len(text) > 1024 {
		text = fmt.Sprintf("%s(%d expanded values)", f.Name, len(f.Params))
	}
	meta := routingMatchMetadata{expression: text, function: f.Name}
	if f.Name == "client" && len(f.Params) == 1 {
		meta.client = f.Params[0].Val
	}
	b.matchMetadata[uint32(index)] = meta
}

func (b *RoutingMatcherBuilder) rememberRule(start uint32, rule *config_parser.RoutingRule, owner string) {
	if b.ruleMetadata == nil {
		b.ruleMetadata = make(map[uint32]routingRuleMetadata)
	}
	meta := routingRuleMetadata{start: start, end: uint32(len(b.rules)), owner: owner}
	for _, source := range rule.Sources {
		meta.sources = append(meta.sources, api.DiagnosticSource{File: source.File, Line: source.Line, Column: source.Column, Expression: source.Expression})
	}
	meta.expression = rule.String(false, false, true)
	if len(meta.expression) > 2048 {
		meta.expression = rule.String(true, false, true)
	}
	b.ruleMetadata[start] = meta
}

func (b *RoutingMatcherBuilder) rememberInactive(other *RoutingMatcherBuilder, owner string) {
	for _, start := range slices.Sorted(maps.Keys(other.ruleMetadata)) {
		metadata := other.ruleMetadata[start]
		metadata.owner = owner
		b.inactiveRules = append(b.inactiveRules, metadata)
	}
}

func (m *RoutingMatcher) inactiveSteps(profile uint32, names map[uint8]string) []api.ExplainStep {
	var steps []api.ExplainStep
	for _, metadata := range m.inactiveRules {
		steps = append(steps, api.ExplainStep{ID: fmt.Sprintf("inactive/%d", len(steps)), Parent: metadata.owner, Stage: "configuration", Expression: metadata.expression, Sources: metadata.sources, Status: "inactive", Match: "unknown", Reason: "not_bound_to_active_policy"})
	}
	for _, other := range m.profileInfo {
		if other.ID == profile {
			continue
		}
		for _, span := range other.Spans {
			for i := span.Start; i < span.End; i++ {
				metadata, exists := m.ruleMetadata[i]
				if !exists {
					continue
				}
				step := api.ExplainStep{ID: fmt.Sprintf("inactive/%d", len(steps)), Parent: profileName(other), Stage: "configuration", Expression: metadata.expression, Sources: metadata.sources, Status: "inactive", Match: "unknown", Reason: "different_ingress_policy"}
				if metadata.end > i {
					step.Outbound = names[m.matches[metadata.end-1].Outbound]
				}
				steps = append(steps, step)
			}
		}
	}
	return steps
}

func (b *RoutingMatcherBuilder) applyRules(rules []*config_parser.RoutingRule, owner string) error {
	for _, rule := range rules {
		start := uint32(len(b.rules))
		if err := b.rulesBuilder.Apply([]*config_parser.RoutingRule{rule}); err != nil {
			return err
		}
		b.rememberRule(start, rule, owner)
	}
	return nil
}

func cloneSources(sources []config_parser.RuleSource) []config_parser.RuleSource {
	return slices.Clone(sources)
}
