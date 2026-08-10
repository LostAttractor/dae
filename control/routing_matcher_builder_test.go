/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestRoutingMatcherBuilderRejectsSkipWhileNoaliveOnBuiltins(t *testing.T) {
	outboundName2ID := map[string]uint8{
		consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
		consts.OutboundBlock.String():  uint8(consts.OutboundBlock),
	}

	for _, outboundName := range []string{consts.OutboundDirect.String(), consts.OutboundBlock.String()} {
		t.Run(outboundName, func(t *testing.T) {
			rules := []*config_parser.RoutingRule{{
				AndFunctions: []*config_parser.Function{{
					Name:   consts.Function_DestPort,
					Params: []*config_parser.Param{{Val: "80"}},
				}},
				Outbound: config_parser.Function{
					Name:   outboundName,
					Params: []*config_parser.Param{{Val: consts.OutboundParam_SkipWhileNoalive}},
				},
			}}

			_, err := NewRoutingMatcherBuilder(rules, outboundName2ID, nil, consts.OutboundDirect.String(), nil)
			if err == nil {
				t.Fatal("expected configuration error")
			}
			if !strings.Contains(err.Error(), "skip_while_noalive cannot be used on outbound "+outboundName) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRoutingMatcherBuilderCriticalOutbounds(t *testing.T) {
	const (
		criticalID = uint8(consts.OutboundUserDefinedMin) + iota
		skipOnlyID
		mixedID
		unusedID
		fallbackID
	)
	rule := func(port, outbound string, skip bool) *config_parser.RoutingRule {
		var params []*config_parser.Param
		if skip {
			params = []*config_parser.Param{{Val: consts.OutboundParam_SkipWhileNoalive}}
		}
		return &config_parser.RoutingRule{
			AndFunctions: []*config_parser.Function{{
				Name:   consts.Function_DestPort,
				Params: []*config_parser.Param{{Val: port}},
			}},
			Outbound: config_parser.Function{Name: outbound, Params: params},
		}
	}

	builder, err := NewRoutingMatcherBuilder(
		[]*config_parser.RoutingRule{
			rule("80", "critical", false),
			rule("81", "skip-only", true),
			rule("82", "mixed", true),
			rule("83", "mixed", false),
		},
		map[string]uint8{
			"critical":  criticalID,
			"skip-only": skipOnlyID,
			"mixed":     mixedID,
			"unused":    unusedID,
			"fallback":  fallbackID,
		},
		nil,
		"fallback",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	critical := builder.criticalOutbounds(int(fallbackID) + 1)
	tests := []struct {
		name string
		id   uint8
		want bool
	}{
		{name: "ordinary rule", id: criticalID, want: true},
		{name: "skip-only rules", id: skipOnlyID},
		{name: "mixed rules", id: mixedID, want: true},
		{name: "unreferenced", id: unusedID},
		{name: "fallback", id: fallbackID, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := critical[tt.id]; got != tt.want {
				t.Fatalf("criticalOutbounds()[%d] = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}
