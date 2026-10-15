// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// conditionalBlock prepends a condition that jumps past the body on a miss.
// The body stays shared; only the entry depends on the use site's condition.
func (b *RoutingMatcherBuilder) conditionalBlock(body resolvedRoutingBlock, condition []*config_parser.Function, name string) (resolvedRoutingBlock, error) {
	if len(condition) == 0 {
		return body, nil
	}
	if len(body.spans) == 0 {
		return body, validateEmptyRoutingUse(condition)
	}
	start := uint32(len(b.rules))
	if err := b.rulesBuilder.ApplyPredicate(condition, &routing.Outbound{Name: "direct"}); err != nil {
		return resolvedRoutingBlock{}, err
	}
	b.rememberRule(start, &config_parser.RoutingRule{
		AndFunctions: condition,
		Outbound:     config_parser.Function{Name: "use", Params: []*config_parser.Param{{Val: name}}},
	}, name, "routing")
	b.setConditionalJump(uint32(len(b.rules)-1), spanExecutionLen(body.spans))
	var block resolvedRoutingBlock
	if err := block.appendSpan(routingSpan{Start: start, End: uint32(len(b.rules)), Phase: body.spans[0].Phase}); err != nil {
		return block, err
	}
	err := block.appendBlock(body)
	return block, err
}

func (b *RoutingMatcherBuilder) setConditionalJump(tail uint32, bodyLength int) {
	b.rules[tail].Action = uint8(consts.MatchActionConditionalJump)
	b.rules[tail].Mark = uint32(bodyLength) + 1
}

// Conditional blocks must be nested or disjoint and stay within one phase.
// This lets both interpreters track ambiguity with a single end position.
func validateRoutingBlocks(rules []bpfMatchSet, spans []routingSpan) error {
	type scope struct {
		end   uint32
		phase routingPhase
	}
	var scopes []scope
	previous := consts.MatchActionRoute
	cursor := newRoutingCursor(spans)
	for cursor.span < len(spans) {
		position := cursor.position
		for len(scopes) != 0 && position >= scopes[len(scopes)-1].end {
			if previous == consts.MatchActionOr || previous == consts.MatchActionAnd {
				return fmt.Errorf("conditional routing block ends inside a rule at %d", position)
			}
			scopes = scopes[:len(scopes)-1]
		}
		phase := spans[cursor.span].Phase
		if len(scopes) != 0 && phase != scopes[len(scopes)-1].phase {
			return fmt.Errorf("conditional routing block crosses phases at %d", position)
		}
		match := rules[cursor.instruction]
		action := consts.MatchAction(match.Action)
		if action == consts.MatchActionOr || action == consts.MatchActionAnd || action == consts.MatchActionConditionalJump {
			if match.Mark == 0 || match.Mark > cursor.length-position {
				return fmt.Errorf("invalid routing jump at position %d: %d", position, match.Mark)
			}
		}
		if action == consts.MatchActionConditionalJump {
			end := position + match.Mark
			if len(scopes) != 0 && end > scopes[len(scopes)-1].end {
				return fmt.Errorf("overlapping conditional routing blocks at %d", position)
			}
			scopes = append(scopes, scope{end, phase})
		}
		previous = action
		cursor.advance(1)
	}
	return nil
}
