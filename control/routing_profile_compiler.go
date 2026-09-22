/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"slices"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type resolvedRoutingBlock struct {
	spans []routingSpan
}

func (b *resolvedRoutingBlock) appendSpan(span routingSpan) error {
	length := span.len()
	if spanExecutionLen(b.spans) > consts.MaxMatchSetLen-length {
		return fmt.Errorf("executes too many match sets: more than %d", consts.MaxMatchSetLen)
	}
	b.spans = appendSpan(b.spans, span)
	return nil
}

func (b *resolvedRoutingBlock) appendBlock(other resolvedRoutingBlock) error {
	otherLength := spanExecutionLen(other.spans)
	if spanExecutionLen(b.spans) > consts.MaxMatchSetLen-otherLength {
		return fmt.Errorf("executes too many match sets: more than %d", consts.MaxMatchSetLen)
	}
	for _, span := range other.spans {
		b.spans = appendSpan(b.spans, span)
	}
	return nil
}

type routingRuleSetKey struct {
	name, condition string
}

type routingCompiler struct {
	builder  *RoutingMatcherBuilder
	sets     map[string]config.RoutingRuleSet
	resolved map[routingRuleSetKey]resolvedRoutingBlock
	preamble routingSpan
	epilogue routingSpan
}

// compileRouting consumes prepared rules only: external data and optimizer
// passes finish before construction, and BPF writes remain deferred to activation.
func (p *preparedRules) compileRouting(outbounds map[string]uint8, bpf *BPFState, ifmgr *network.InterfaceManager) (*RoutingMatcherBuilder, error) {
	builder := newRoutingMatcherBuilder(outbounds, bpf, ifmgr)
	preamble, err := builder.addControlPlaneFragment(p)
	if err != nil {
		return nil, err
	}
	sets := make(map[string]config.RoutingRuleSet, len(p.routing.RuleSets))
	for _, set := range p.routing.RuleSets {
		sets[set.Name] = set
	}
	compiler := routingCompiler{builder: builder, sets: sets, resolved: make(map[routingRuleSetKey]resolvedRoutingBlock), preamble: preamble}
	compiler.epilogue, err = compiler.compileRuleBatch(p.lateRoutes)
	if err != nil {
		return nil, err
	}
	if err := compiler.compile(p.routing); err != nil {
		return nil, err
	}
	builder.routing.end = len(builder.rules)
	builder.kernelLpmLen = len(builder.simulatedLpmTries)
	if err := builder.addDestinationPredicates(p.destinations); err != nil {
		return nil, err
	}
	if err := builder.validate(); err != nil {
		return nil, err
	}
	return builder, nil
}

func (c *routingCompiler) compile(routingConfig *config.Routing) error {
	// Default and interfaces select policies. Compile each selected name once,
	// independent of how many bindings refer to it.
	profileNames := []string{routingConfig.Default}
	bindings := map[string][]string{routingConfig.Default: nil}
	for _, binding := range routingConfig.Interfaces {
		if _, selected := bindings[binding.Policy]; !selected {
			profileNames = append(profileNames, binding.Policy)
		}
		bindings[binding.Policy] = append(bindings[binding.Policy], binding.Name)
	}

	allocator := routingProfileIDAllocator{}
	if c.builder.bpf != nil {
		allocator = c.builder.bpf.routingProfileIDs
	}
	profileIDPlan, err := allocator.plan(profileNames)
	if err != nil {
		return err
	}
	c.builder.profileIDPlan = &profileIDPlan

	c.builder.defaultProfileID = profileIDPlan.ids[routingConfig.Default]
	policies := make(map[string]config.RoutingPolicy, len(routingConfig.Policies))
	for _, policy := range routingConfig.Policies {
		policies[policy.Name] = policy
	}
	for _, name := range profileNames {
		if err := c.addProfile(profileIDPlan.ids[name], bindings[name], policies[name]); err != nil {
			return err
		}
	}
	for _, policy := range routingConfig.Policies {
		if _, selected := bindings[policy.Name]; selected {
			continue
		}
		validator := c.newValidator()
		if err := validator.addProfile(0, nil, policy); err != nil {
			return err
		}
		if err := validator.builder.validate(); err != nil {
			return err
		}
		if _, err := validator.builder.BuildUserspace(); err != nil {
			return err
		}
	}
	return c.validateUnusedRuleSets(routingConfig.RuleSets)
}

func (c *routingCompiler) addProfile(id uint32, interfaceNames []string, policy config.RoutingPolicy) error {
	body, err := c.resolveStatements(policy.Name, policy.Statements, nil)
	if err != nil {
		return err
	}
	block := resolvedRoutingBlock{}
	if err := block.appendSpan(c.preamble); err != nil {
		return err
	}
	if err := block.appendBlock(body); err != nil {
		return fmt.Errorf("routing policy %q: %w", policy.Name, err)
	}
	if err := block.appendSpan(c.epilogue); err != nil {
		return fmt.Errorf("routing policy %q: %w", policy.Name, err)
	}
	fallback, err := c.builder.parseFallback(policy.Fallback)
	if err != nil {
		return fmt.Errorf("routing policy %q fallback: %w", policy.Name, err)
	}
	fallbackSpan, err := c.builder.addFallback(fallback)
	if err != nil {
		return fmt.Errorf("routing policy %q fallback: %w", policy.Name, err)
	}
	if err := block.appendSpan(fallbackSpan); err != nil {
		return fmt.Errorf("routing policy %q: %w", policy.Name, err)
	}
	c.builder.profiles = append(c.builder.profiles, routingProfile{
		ID:             id,
		InterfaceNames: slices.Clone(interfaceNames),
		Spans:          block.spans,
	})
	return nil
}

func (c *routingCompiler) resolveSet(name string, condition []*config_parser.Function) (resolvedRoutingBlock, error) {
	// Quote values in the key so regexes and other literals cannot collide with
	// function/parameter separators. Prepared predicates are immutable.
	var signature strings.Builder
	for _, f := range condition {
		signature.WriteString(f.String(true, true, false))
		signature.WriteString("&&")
	}
	key := routingRuleSetKey{name: name, condition: signature.String()}
	if block, ok := c.resolved[key]; ok {
		return block, nil
	}
	set, ok := c.sets[name]
	if !ok {
		return resolvedRoutingBlock{}, fmt.Errorf("undefined routing rule_set %q", name)
	}
	block, err := c.resolveStatements(set.Name, set.Statements, condition)
	if err != nil {
		return resolvedRoutingBlock{}, err
	}
	if len(block.spans) == 0 && len(condition) != 0 {
		if err := validateEmptyRoutingUse(condition); err != nil {
			return resolvedRoutingBlock{}, fmt.Errorf("routing rule_set %q condition: %w", name, err)
		}
	}
	// Empty fragments consume no instructions, but conditional DAGs can still
	// create exponentially many distinct specializations. Bound those too.
	if len(c.resolved) >= consts.MaxMatchSetLen {
		return resolvedRoutingBlock{}, fmt.Errorf("too many routing rule_set condition variants: limit %d", consts.MaxMatchSetLen)
	}
	c.resolved[key] = block
	return block, nil
}

func (c *routingCompiler) resolveStatements(name string, statements []config.RoutingStatement, condition []*config_parser.Function) (resolvedRoutingBlock, error) {
	var block resolvedRoutingBlock
	var localRules []*config_parser.RoutingRule
	flush := func() error {
		if len(localRules) == 0 {
			return nil
		}
		span, err := c.compileRuleBatch(localRules)
		if err != nil {
			return fmt.Errorf("compile routing block %q: %w", name, err)
		}
		localRules = nil
		if err := block.appendSpan(span); err != nil {
			return fmt.Errorf("routing block %q %w", name, err)
		}
		return nil
	}

	for _, statement := range statements {
		switch statement.Kind {
		case config.RoutingStatementRule:
			rule := statement.Rule
			if len(condition) != 0 {
				rule = &config_parser.RoutingRule{
					AndFunctions: slices.Concat(condition, rule.AndFunctions),
					Outbound:     rule.Outbound,
				}
			}
			localRules = append(localRules, rule)
		case config.RoutingStatementUse:
			if err := flush(); err != nil {
				return resolvedRoutingBlock{}, err
			}
			called, err := c.resolveSet(statement.Use, slices.Concat(condition, statement.Condition))
			if err != nil {
				return resolvedRoutingBlock{}, fmt.Errorf("routing block %q: %w", name, err)
			}
			if err := block.appendBlock(called); err != nil {
				return resolvedRoutingBlock{}, fmt.Errorf("routing block %q %w", name, err)
			}
		default:
			return resolvedRoutingBlock{}, fmt.Errorf("routing block %q contains an unknown statement", name)
		}
	}
	if err := flush(); err != nil {
		return resolvedRoutingBlock{}, err
	}
	return block, nil
}

// Even an empty referenced fragment must validate its condition, without
// publishing predicates or interface subscriptions into the active program.
func validateEmptyRoutingUse(condition []*config_parser.Function) error {
	b := newRoutingMatcherBuilder(map[string]uint8{"direct": uint8(consts.OutboundDirect)}, nil, nil)
	if err := b.rulesBuilder.ApplyPredicate(condition, &routing.Outbound{Name: "direct"}); err != nil {
		return err
	}
	b.routing.end = len(b.rules)
	if err := b.validate(); err != nil {
		return err
	}
	_, err := b.BuildUserspace()
	return err
}

func (c *routingCompiler) compileRuleBatch(rules []*config_parser.RoutingRule) (routingSpan, error) {
	start := uint32(len(c.builder.rules))
	if err := c.builder.rulesBuilder.Apply(rules); err != nil {
		return routingSpan{}, err
	}
	if len(c.builder.rules) > consts.MaxMatchSetLen {
		return routingSpan{}, fmt.Errorf("too many physical routing match sets: %d > %d", len(c.builder.rules), consts.MaxMatchSetLen)
	}
	return routingSpan{Start: start, End: uint32(len(c.builder.rules))}, nil
}

// Validate unused definitions without adding their match sets, interface
// subscriptions or connectivity requirements to the active policy.
func (c *routingCompiler) validateUnusedRuleSets(ruleSets []config.RoutingRuleSet) error {
	reachable := make(map[string]bool, len(c.resolved))
	for key := range c.resolved {
		reachable[key.name] = true
	}
	for _, set := range ruleSets {
		if reachable[set.Name] {
			continue
		}
		validator := c.newValidator()
		if _, err := validator.resolveSet(set.Name, nil); err != nil {
			return err
		}
		if err := validator.builder.validate(); err != nil {
			return err
		}
		if _, err := validator.builder.BuildUserspace(); err != nil {
			return err
		}
	}
	return nil
}

func (c *routingCompiler) newValidator() *routingCompiler {
	return &routingCompiler{
		builder: newRoutingMatcherBuilder(c.builder.outboundName2Id, nil, c.builder.ifmgr),
		sets:    c.sets, resolved: make(map[routingRuleSetKey]resolvedRoutingBlock),
	}
}

// Resolve external data during parallel preparation, while its context is
// alive. Ordered use statements delimit optimizer batches, so rules
// cannot move across a reusable fragment boundary. The source AST is retained.
func prepareRoutingConfig(source *config.Routing, reader *routing.DatReaderOptimizer) (*config.Routing, error) {
	if err := source.Validate(); err != nil {
		return nil, err
	}
	result := *source
	result.RuleSets = slices.Clone(source.RuleSets)
	result.Policies = slices.Clone(source.Policies)
	prepare := func(name string, statements []config.RoutingStatement) ([]config.RoutingStatement, error) {
		var result []config.RoutingStatement
		for i := 0; i < len(statements); {
			if statements[i].Kind != config.RoutingStatementRule {
				statement := statements[i]
				if len(statement.Condition) != 0 {
					normalized, err := routing.ApplyRulesOptimizers([]*config_parser.RoutingRule{{AndFunctions: statement.Condition}},
						&routing.AliasOptimizer{}, reader, &routing.MergeAndSortRulesOptimizer{}, &routing.DeduplicateParamsOptimizer{})
					if err != nil {
						return nil, fmt.Errorf("prepare routing block %q use %q: %w", name, statement.Use, err)
					}
					statement.Condition = normalized[0].AndFunctions
				}
				result = append(result, statement)
				i++
				continue
			}
			var rules []*config_parser.RoutingRule
			for i < len(statements) && statements[i].Kind == config.RoutingStatementRule {
				rules = append(rules, statements[i].Rule)
				i++
			}
			optimized, err := routing.ApplyRulesOptimizers(rules, &routing.AliasOptimizer{}, reader,
				&routing.MergeAndSortRulesOptimizer{}, &routing.DeduplicateParamsOptimizer{})
			if err != nil {
				return nil, fmt.Errorf("prepare routing block %q: %w", name, err)
			}
			for _, rule := range optimized {
				result = append(result, config.RoutingStatement{Kind: config.RoutingStatementRule, Rule: rule})
			}
		}
		return result, nil
	}
	var err error
	for i := range result.RuleSets {
		set := &result.RuleSets[i]
		if set.Statements, err = prepare(set.Name, set.Statements); err != nil {
			return nil, err
		}
	}
	for i := range result.Policies {
		policy := &result.Policies[i]
		if policy.Statements, err = prepare(policy.Name, policy.Statements); err != nil {
			return nil, err
		}
	}
	return &result, nil
}
