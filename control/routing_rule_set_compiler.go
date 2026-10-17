// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// Rule sets share reference resolution, batching and variant accounting. Each
// program owns its block representation and phase-specific condition semantics.
type ruleSetCompiler[B any] struct {
	kind      string
	cache     map[routingRuleSetKey]B
	compile   func([]*config_parser.RoutingRule, string) (B, error)
	condition func(B, []*config_parser.Function, string) (B, error)
	append    func(*B, B) error
}

func (c *routingCompiler) resolveRuleSet[B any](program ruleSetCompiler[B], name string, condition []*config_parser.Function) (B, error) {
	key := routingSetKey(name, condition)
	if block, ok := program.cache[key]; ok {
		return block, nil
	}
	var block B
	set, ok := c.sets[name]
	if !ok {
		return block, fmt.Errorf("undefined routing rule_set %q", name)
	}
	var err error
	if len(condition) == 0 {
		block, err = c.resolveBlockStatements(program, set.Name, set.Statements)
	} else {
		block, err = c.resolveRuleSet(program, name, nil)
		if err == nil {
			block, err = program.condition(block, condition, name)
		}
	}
	if err != nil {
		return block, err
	}
	if len(c.resolved)+len(c.flows) >= consts.MaxMatchSetLen {
		return block, fmt.Errorf("too many routing rule_set condition variants: limit %d", consts.MaxMatchSetLen)
	}
	program.cache[key] = block
	return block, nil
}

func (c *routingCompiler) resolveBlockStatements[B any](program ruleSetCompiler[B], name string, statements []config.RoutingStatement) (B, error) {
	var block B
	var local []*config_parser.RoutingRule
	appendBlock := func(batch B) error {
		if err := program.append(&block, batch); err != nil {
			return fmt.Errorf("%s block %q %w", program.kind, name, err)
		}
		return nil
	}
	flush := func() error {
		if len(local) == 0 {
			return nil
		}
		batch, err := program.compile(local, name)
		if err != nil {
			return fmt.Errorf("compile %s block %q: %w", program.kind, name, err)
		}
		local = nil
		return appendBlock(batch)
	}
	for _, statement := range statements {
		switch statement.Kind {
		case config.RoutingStatementRule:
			local = append(local, statement.Rule)
		case config.RoutingStatementUse:
			if err := flush(); err != nil {
				return block, err
			}
			called, err := c.resolveRuleSet(program, statement.Use, statement.Condition)
			if err != nil {
				return block, fmt.Errorf("%s block %q: %w", program.kind, name, err)
			}
			if err := appendBlock(called); err != nil {
				return block, err
			}
		default:
			return block, fmt.Errorf("%s block %q contains an unknown statement", program.kind, name)
		}
	}
	err := flush()
	return block, err
}
