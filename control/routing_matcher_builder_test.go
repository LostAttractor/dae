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
