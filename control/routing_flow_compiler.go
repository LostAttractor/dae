// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"slices"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// A shared fragment has one physical capture program and one exact target
// program. Policies reference it in their own order; neither implies global scope.
type destinationFragment struct {
	rules          routing.DestinationRewrites
	owner, section string
	predicates     []destinationPredicate
}

type resolvedFlowBlock struct {
	capture, controls resolvedRoutingBlock
	destinations      []*destinationFragment
}

func (b *resolvedFlowBlock) append(other resolvedFlowBlock) error {
	if err := b.capture.appendBlock(other.capture); err != nil {
		return err
	}
	if err := b.controls.appendBlock(other.controls); err != nil {
		return err
	}
	b.destinations = append(b.destinations, other.destinations...)
	return nil
}

// Only system bypass and plugin declarations are implicitly shared. Handwritten
// rules enter through resolveFlowStatements for the selected policy.
type sharedRoutingPrograms struct {
	bypass, request, http, early, late routingSpan
	destinations                       resolvedFlowBlock
}

func (c *routingCompiler) compileShared(p *preparedRules) error {
	b := c.builder
	start := uint32(len(b.rules))
	if err := b.applyRules(p.bypass, "api_bypass"); err != nil {
		return err
	}
	for i := start; i < uint32(len(b.rules)); i++ {
		if b.rules[i].Action == uint8(consts.MatchActionRoute) {
			b.rules[i].Flags |= matchFlagBypass
		}
	}
	c.shared.bypass = routingSpan{Start: start, End: uint32(len(b.rules)), Phase: routingPhaseIngress, Global: true}
	var err error
	c.shared.destinations, err = c.compileDestinations(p.destinations, "destination", "", true)
	if err != nil {
		return err
	}
	if p.capture != nil {
		c.shared.request, err = c.compileHTTPCapture(p.capture.requestRouting, captureHTTP|captureHTTPRequest, routingPhaseIngress)
		if err != nil {
			return err
		}
		c.shared.http, err = c.compileHTTPCapture(p.capture.http, captureHTTP, routingPhaseFlow)
		if err != nil {
			return err
		}
	}
	c.shared.early, err = c.compileRuleBatch(p.earlyRoutes, "plugin_early")
	if err != nil {
		return err
	}
	c.shared.early.Global = true
	c.shared.late, err = c.compileRuleBatch(p.lateRoutes, "plugin_late")
	c.shared.late.Global = true
	return err
}

func (c *routingCompiler) compileHTTPCapture(scopes []plugin.Scope, flags uint8, phase routingPhase) (routingSpan, error) {
	start := uint32(len(c.builder.rules))
	name := "http"
	if flags&captureHTTPRequest != 0 {
		name = "http_request"
	}
	for _, predicate := range mitmCapturePredicates(scopes) {
		rule := &config_parser.RoutingRule{AndFunctions: predicate, Outbound: config_parser.Function{Name: "capture", Params: []*config_parser.Param{{Val: name}}}}
		if err := c.builder.applyFlowEffect(rule, consts.MatchActionCapture, flags, "flow_control", ""); err != nil {
			return routingSpan{}, fmt.Errorf("HTTP capture: %w", err)
		}
	}
	return routingSpan{Start: start, End: uint32(len(c.builder.rules)), Phase: phase, Global: true}, nil
}

func (b *RoutingMatcherBuilder) applyFlowEffect(rule *config_parser.RoutingRule, action consts.MatchAction, flags uint8, owner, section string) error {
	start := uint32(len(b.rules))
	if err := b.rulesBuilder.ApplyPredicate(rule.AndFunctions, &routing.Outbound{Name: "direct"}); err != nil {
		return err
	}
	tail := &b.rules[len(b.rules)-1]
	tail.Action = uint8(action)
	tail.Flags |= flags << matchCaptureShift
	b.rememberRule(start, rule, owner, section)
	return nil
}

func (c *routingCompiler) compileDestinations(rules routing.DestinationRewrites, owner, section string, global bool) (resolvedFlowBlock, error) {
	var block resolvedFlowBlock
	if len(rules) == 0 {
		return block, nil
	}
	start := uint32(len(c.builder.rules))
	for _, rule := range rules {
		if err := c.builder.applyFlowEffect(destinationDiagnosticRule(rule), consts.MatchActionCapture, captureDestination, owner, section); err != nil {
			return block, fmt.Errorf("destination capture: %w", err)
		}
	}
	if err := block.capture.appendSpan(routingSpan{Start: start, End: uint32(len(c.builder.rules)), Phase: routingPhaseIngress, Global: global}); err != nil {
		return block, err
	}
	fragment := &destinationFragment{rules: rules, owner: owner, section: section}
	c.destinationFragments = append(c.destinationFragments, fragment)
	block.destinations = []*destinationFragment{fragment}
	return block, nil
}

func (c *routingCompiler) compileFlowBatch(rules []*config_parser.RoutingRule, owner string) (resolvedFlowBlock, error) {
	plan, err := (config.Rules{Rules: rules}).Plan()
	if err != nil {
		return resolvedFlowBlock{}, err
	}
	block, err := c.compileDestinations(plan.Destinations, owner, "rules", false)
	if err != nil {
		return block, err
	}
	start := uint32(len(c.builder.rules))
	for _, rule := range plan.Controls {
		metadata := &config_parser.RoutingRule{AndFunctions: rule.Filter, Outbound: config_parser.Function{Name: diagnosticAction(uint8(rule.Action))}, Sources: rule.Sources}
		if err := c.builder.applyFlowEffect(metadata, rule.Action, 0, owner, "rules"); err != nil {
			return block, err
		}
	}
	if len(c.builder.rules) > consts.MaxMatchSetLen {
		return block, fmt.Errorf("too many physical routing match sets: %d > %d", len(c.builder.rules), consts.MaxMatchSetLen)
	}
	err = block.controls.appendSpan(routingSpan{Start: start, End: uint32(len(c.builder.rules)), Phase: routingPhaseFlow})
	return block, err
}

func (c *routingCompiler) resolveFlowSet(name string, condition []*config_parser.Function) (resolvedFlowBlock, error) {
	key := routingSetKey(name, condition)
	if block, ok := c.flows[key]; ok {
		return block, nil
	}
	set, ok := c.sets[name]
	if !ok {
		return resolvedFlowBlock{}, fmt.Errorf("undefined routing rule_set %q", name)
	}
	block, err := c.resolveFlowStatements(name, set.Statements, condition)
	if err != nil {
		return block, err
	}
	if len(block.capture.spans)+len(block.controls.spans) == 0 && len(condition) != 0 {
		if err := validateEmptyRoutingUse(condition); err != nil {
			return block, fmt.Errorf("routing rule_set %q condition: %w", name, err)
		}
	}
	if len(c.resolved)+len(c.flows) >= consts.MaxMatchSetLen {
		return block, fmt.Errorf("too many routing rule_set condition variants: limit %d", consts.MaxMatchSetLen)
	}
	c.flows[key] = block
	return block, nil
}

func (c *routingCompiler) resolveFlowStatements(name string, statements []config.RoutingStatement, condition []*config_parser.Function) (resolvedFlowBlock, error) {
	var block resolvedFlowBlock
	var local []*config_parser.RoutingRule
	flush := func() error {
		if len(local) == 0 {
			return nil
		}
		batch, err := c.compileFlowBatch(local, name)
		if err != nil {
			return fmt.Errorf("compile flow block %q: %w", name, err)
		}
		local = nil
		return block.append(batch)
	}
	for _, statement := range statements {
		switch statement.Kind {
		case config.RoutingStatementRule:
			rule := statement.Rule
			if len(condition) != 0 {
				rule = &config_parser.RoutingRule{AndFunctions: slices.Concat(condition, rule.AndFunctions), Outbound: rule.Outbound, Sources: cloneSources(rule.Sources)}
			}
			local = append(local, rule)
		case config.RoutingStatementUse:
			if err := flush(); err != nil {
				return block, err
			}
			called, err := c.resolveFlowSet(statement.Use, slices.Concat(condition, statement.Condition))
			if err != nil {
				return block, fmt.Errorf("flow block %q: %w", name, err)
			}
			if err := block.append(called); err != nil {
				return block, err
			}
		default:
			return block, fmt.Errorf("flow block %q contains an unknown statement", name)
		}
	}
	if err := flush(); err != nil {
		return block, err
	}
	return block, nil
}

// Exact destination programs are appended after the entire kernel pool. Shared
// fragments compile once; each profile receives its ordered predicate references.
func (c *routingCompiler) finish() error {
	b := c.builder
	b.routing.end = len(b.rules)
	b.kernelLpmLen = len(b.simulatedLpmTries)
	for _, fragment := range c.destinationFragments {
		var err error
		fragment.predicates, err = b.addDestinationPredicates(fragment.rules, fragment.owner, fragment.section)
		if err != nil {
			return err
		}
	}
	for i := range b.profiles {
		profile := &b.profiles[i]
		for _, fragment := range c.profileDestinations[profile.ID] {
			profile.Destination.predicates = append(profile.Destination.predicates, fragment.predicates...)
		}
	}
	return b.validate()
}
