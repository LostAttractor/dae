// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/internal/routingabi"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type _bpfPortRange struct {
	PortStart uint16
	PortEnd   uint16
}

func (r _bpfPortRange) Encode() (b [16]byte) {
	binary.LittleEndian.PutUint16(b[:2], r.PortStart)
	binary.LittleEndian.PutUint16(b[2:], r.PortEnd)
	return b
}

func ParsePortRange(b []byte) (portStart, portEnd uint16) {
	portStart = binary.LittleEndian.Uint16(b[:2])
	portEnd = binary.LittleEndian.Uint16(b[2:])
	return portStart, portEnd
}

const (
	matchFlagNot         uint8 = routingabi.MATCH_FLAG_NOT
	matchFlagMust        uint8 = routingabi.MATCH_FLAG_MUST
	matchFlagSkipNoalive uint8 = routingabi.MATCH_FLAG_SKIP_NOALIVE
	matchCaptureShift          = routingabi.MATCH_CAPTURE_SHIFT
	matchFlagBypass      uint8 = routingabi.MATCH_FLAG_BYPASS
)

func routingMatchFlags(not, must, skipNoalive bool) (flags uint8) {
	if not {
		flags |= matchFlagNot
	}
	if must {
		flags |= matchFlagMust
	}
	if skipNoalive {
		flags |= matchFlagSkipNoalive
	}
	return flags
}

// Logical instructions carry no routing result. Only a rule tail may set a
// packet mark, must flag or connectivity condition.
func (b *RoutingMatcherBuilder) matchSet(kind consts.MatchType, not bool, outbound *routing.Outbound) (bpfMatchSet, error) {
	set := bpfMatchSet{Type: uint8(kind), Flags: routingMatchFlags(not, false, false)}
	switch outbound.Name {
	case consts.OutboundLogicalOr.String():
		set.Action = uint8(consts.MatchActionOr)
	case consts.OutboundLogicalAnd.String():
		set.Action = uint8(consts.MatchActionAnd)
	default:
		id, ok := b.outboundName2Id[outbound.Name]
		if !ok {
			return bpfMatchSet{}, fmt.Errorf("outbound (group) %v not found; please define it in section \"group\"", strconv.Quote(outbound.Name))
		}
		if outbound.SkipWhileNoalive {
			if kind == consts.MatchType_Fallback {
				return bpfMatchSet{}, fmt.Errorf("skip_while_noalive cannot be used on fallback: skipping fallback leaves traffic unroutable")
			}
			if id == uint8(consts.OutboundDirect) || id == uint8(consts.OutboundBlock) {
				return bpfMatchSet{}, fmt.Errorf("skip_while_noalive cannot be used on outbound %v: built-in outbounds do not participate in connectivity checks", outbound.Name)
			}
		}
		set.Outbound, set.Mark = id, outbound.Mark
		set.Flags = routingMatchFlags(not, outbound.Must, outbound.SkipWhileNoalive)
	}
	return set, nil
}

func (b *RoutingMatcherBuilder) addMatch(f *config_parser.Function, kind consts.MatchType, value [16]byte, outbound *routing.Outbound) error {
	set, err := b.matchSet(kind, f.Not, outbound)
	if err != nil {
		return err
	}
	set.Value = value
	b.rememberMatch(len(b.rules), f)
	b.rules = append(b.rules, set)
	return nil
}

func (b *RoutingMatcherBuilder) addMatches[T any](f *config_parser.Function, kind consts.MatchType, values []T, outbound *routing.Outbound, encode func(T) [16]byte) error {
	tail, err := b.matchSet(kind, f.Not, outbound)
	if err != nil {
		return err
	}
	for i, value := range values {
		set := bpfMatchSet{Type: uint8(kind), Action: uint8(consts.MatchActionOr), Flags: routingMatchFlags(f.Not, false, false)}
		if i == len(values)-1 {
			set = tail
		}
		set.Value = encode(value)
		b.rememberMatch(len(b.rules), f)
		b.rules = append(b.rules, set)
	}
	return nil
}

// Rules are emitted contiguously; profile spans splice only between rules.
// Thus relative tail distances remain valid when a fragment is shared, moved
// or repeated. Logical instructions never commit their Mark field to a packet.
func encodeRoutingJumps(rules []bpfMatchSet) error {
	// AND misses go to ruleEnd; OR hits go to clauseTail to apply NOT/action.
	ruleEnd, clauseTail := -1, -1
	for i := len(rules) - 1; i >= 0; i-- {
		rule := &rules[i]
		switch consts.MatchAction(rule.Action) {
		case consts.MatchActionAnd:
			if ruleEnd <= i {
				return fmt.Errorf("missing routing rule tail at match set %d", i)
			}
			rule.Mark = uint32(ruleEnd - i)
			clauseTail = i
		case consts.MatchActionOr:
			if clauseTail <= i {
				return fmt.Errorf("missing routing clause tail at match set %d", i)
			}
			rule.Mark = uint32(clauseTail - i)
		default:
			ruleEnd, clauseTail = i+1, i
			if rule.Action == uint8(consts.MatchActionConditionalJump) {
				// Shared bodies need not follow their entry in the physical pool.
				// Validate the target in each profile's execution order instead.
				if rule.Mark <= 1 || rule.Mark > uint32(consts.MaxMatchSetLen) {
					return fmt.Errorf("invalid conditional routing jump at match set %d: %d", i, rule.Mark)
				}
				ruleEnd = i + int(rule.Mark)
			}
		}
	}
	return nil
}
