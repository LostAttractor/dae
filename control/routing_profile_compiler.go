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
	if span.len() == 0 {
		return nil
	}
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
	validationOutbounds map[string]uint8
	builder             *RoutingMatcherBuilder
	sets                map[string]config.RoutingRuleSet
	setKinds            map[string]config.RoutingRuleSetKind
	resolved            map[routingRuleSetKey]resolvedRoutingBlock
	flows               map[routingRuleSetKey]resolvedFlowBlock
	shared              sharedRoutingPrograms
	profileDestinations map[uint32][]*destinationFragment
	flowEnd             routingSpan
}

// compileRouting consumes prepared rules only: external data and optimizer
// passes finish before construction, and BPF writes remain deferred to activation.
func (p *preparedRules) compileRouting(outbounds map[string]uint8, bpf *BPFState, ifmgr *network.InterfaceManager) (*RoutingMatcherBuilder, error) {
	builder := newRoutingMatcherBuilder(outbounds, bpf, ifmgr)
	sets := make(map[string]config.RoutingRuleSet, len(p.routing.RuleSets))
	for _, set := range p.routing.RuleSets {
		sets[set.Name] = set
	}
	kinds, err := p.routing.RuleSetKinds()
	if err != nil {
		return nil, err
	}
	compiler := routingCompiler{
		builder: builder, sets: sets, setKinds: kinds,
		resolved:            make(map[routingRuleSetKey]resolvedRoutingBlock),
		flows:               make(map[routingRuleSetKey]resolvedFlowBlock),
		profileDestinations: make(map[uint32][]*destinationFragment),
		validationOutbounds: p.validationOutbounds,
	}
	if err := compiler.compileShared(p); err != nil {
		return nil, err
	}
	if err := compiler.compile(p.routing); err != nil {
		return nil, err
	}
	if err := compiler.finish(); err != nil {
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

	// A handoff's generation selects the interpreter, so IDs need only be
	// unique within this configuration. Zero means userspace default routing.
	c.builder.defaultProfileID = 1
	policies := make(map[string]config.RoutingPolicy, len(routingConfig.Policies))
	for _, policy := range routingConfig.Policies {
		policies[policy.Name] = policy
	}
	for i, name := range profileNames {
		if err := c.addProfile(uint32(i+1), bindings[name], policies[name]); err != nil {
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
		if err := validator.finish(); err != nil {
			return err
		}
		if _, err := validator.builder.BuildUserspace(); err != nil {
			return err
		}
		c.builder.rememberInactive(validator.builder, "policy/"+policy.Name)
	}
	return c.validateUnusedRuleSets(routingConfig.RuleSets)
}

func (c *routingCompiler) addProfile(id uint32, interfaceNames []string, policy config.RoutingPolicy) error {
	flow, err := c.resolveFlowStatements(policy.Name, policy.Rules)
	if err != nil {
		return fmt.Errorf("routing policy %q rules: %w", policy.Name, err)
	}
	body, err := c.resolveStatements(policy.Name, policy.Statements)
	if err != nil {
		return err
	}
	var block resolvedRoutingBlock
	appendBlock := func(next resolvedRoutingBlock) error {
		if err := block.appendBlock(next); err != nil {
			return fmt.Errorf("routing policy %q: %w", policy.Name, err)
		}
		return nil
	}
	for _, next := range []resolvedRoutingBlock{
		{spans: []routingSpan{c.shared.bypass}},
		flow.capture,
		c.shared.destinations.capture,
		{spans: []routingSpan{c.shared.request}},
		flow.controls,
		{spans: []routingSpan{c.shared.http}},
	} {
		if err := appendBlock(next); err != nil {
			return err
		}
	}
	if len(flow.controls.spans) != 0 || c.shared.http.len() != 0 {
		if c.flowEnd.len() == 0 {
			start := uint32(len(c.builder.rules))
			c.builder.rules = append(c.builder.rules, bpfMatchSet{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionFlowEnd)})
			c.flowEnd = routingSpan{Start: start, End: start + 1, Phase: routingPhaseFlow}
		}
		if err := block.appendSpan(c.flowEnd); err != nil {
			return err
		}
	}
	for _, next := range []resolvedRoutingBlock{{spans: []routingSpan{c.shared.early}}, body, {spans: []routingSpan{c.shared.late}}} {
		if err := appendBlock(next); err != nil {
			return err
		}
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
	c.builder.profiles = append(c.builder.profiles, routingProfile{ID: id, Name: policy.Name, InterfaceNames: slices.Clone(interfaceNames), Spans: block.spans})
	c.profileDestinations[id] = slices.Concat(flow.destinations, c.shared.destinations.destinations)
	return nil
}

func routingSetKey(name string, condition []*config_parser.Function) routingRuleSetKey {
	var signature strings.Builder
	for _, f := range condition {
		signature.WriteString(f.String(true, true, false))
		signature.WriteString("&&")
	}
	return routingRuleSetKey{name: name, condition: signature.String()}
}

func (c *routingCompiler) routingProgram() ruleSetCompiler[resolvedRoutingBlock] {
	return ruleSetCompiler[resolvedRoutingBlock]{
		kind: "routing", cache: c.resolved,
		compile: func(rules []*config_parser.RoutingRule, name string) (resolvedRoutingBlock, error) {
			span, err := c.compileRuleBatch(rules, name)
			var block resolvedRoutingBlock
			if err == nil {
				err = block.appendSpan(span)
			}
			return block, err
		},
		condition: c.builder.conditionalBlock,
		append:    (*resolvedRoutingBlock).appendBlock,
	}
}

func (c *routingCompiler) resolveSet(name string, condition []*config_parser.Function) (resolvedRoutingBlock, error) {
	return c.resolveRuleSet(c.routingProgram(), name, condition)
}

func (c *routingCompiler) resolveStatements(name string, statements []config.RoutingStatement) (resolvedRoutingBlock, error) {
	return c.resolveBlockStatements(c.routingProgram(), name, statements)
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

func (c *routingCompiler) compileRuleBatch(rules []*config_parser.RoutingRule, owner string) (routingSpan, error) {
	start := uint32(len(c.builder.rules))
	if err := c.builder.applyRules(rules, owner); err != nil {
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
	for key := range c.flows {
		reachable[key.name] = true
	}
	for _, set := range ruleSets {
		if reachable[set.Name] {
			continue
		}
		validator := c.newValidator()
		var err error
		if c.setKinds[set.Name] == config.RoutingRuleSetFlow {
			_, err = validator.resolveFlowSet(set.Name, nil)
		} else {
			_, err = validator.resolveSet(set.Name, nil)
		}
		if err != nil {
			return err
		}
		if err := validator.finish(); err != nil {
			return err
		}
		if _, err := validator.builder.BuildUserspace(); err != nil {
			return err
		}
		c.builder.rememberInactive(validator.builder, "rule_set/"+set.Name)
	}
	return nil
}

func (c *routingCompiler) newValidator() *routingCompiler {
	outbounds := c.validationOutbounds
	if outbounds == nil {
		outbounds = c.builder.outboundName2Id
	}
	return &routingCompiler{
		builder: newRoutingMatcherBuilder(outbounds, nil, c.builder.ifmgr),
		sets:    c.sets, setKinds: c.setKinds, resolved: make(map[routingRuleSetKey]resolvedRoutingBlock),
		flows: make(map[routingRuleSetKey]resolvedFlowBlock), profileDestinations: make(map[uint32][]*destinationFragment),
	}
}

// Resolve external data during parallel preparation, while its context is
// alive. Ordered use statements delimit optimizer batches, so rules
// cannot move across a reusable fragment boundary. The source AST is retained.
func prepareRoutingConfig(source *config.Routing, reader *routing.DatReaderOptimizer) (*config.Routing, error) {
	if err := source.Validate(); err != nil {
		return nil, err
	}
	kinds, err := source.RuleSetKinds()
	if err != nil {
		return nil, err
	}
	result := *source
	result.RuleSets = slices.Clone(source.RuleSets)
	result.Policies = slices.Clone(source.Policies)
	prepare := func(name string, statements []config.RoutingStatement, flow bool) ([]config.RoutingStatement, error) {
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
			optimizers := []routing.RulesOptimizer{&routing.AliasOptimizer{}, reader}
			if !flow {
				optimizers = append(optimizers, &routing.MergeAndSortRulesOptimizer{})
			}
			optimizers = append(optimizers, &routing.DeduplicateParamsOptimizer{})
			optimized, err := routing.ApplyRulesOptimizers(rules, optimizers...)
			if err != nil {
				return nil, fmt.Errorf("prepare routing block %q: %w", name, err)
			}
			for _, rule := range optimized {
				result = append(result, config.RoutingStatement{Kind: config.RoutingStatementRule, Rule: rule})
			}
		}
		return result, nil
	}
	for i := range result.RuleSets {
		set := &result.RuleSets[i]
		if set.Statements, err = prepare(set.Name, set.Statements, kinds[set.Name] == config.RoutingRuleSetFlow); err != nil {
			return nil, err
		}
	}
	for i := range result.Policies {
		policy := &result.Policies[i]
		if policy.Rules, err = prepare(policy.Name+".rules", policy.Rules, true); err != nil {
			return nil, err
		}
		if policy.Statements, err = prepare(policy.Name, policy.Statements, false); err != nil {
			return nil, err
		}
	}
	return &result, nil
}
