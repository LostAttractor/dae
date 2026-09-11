/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestPrepareRoutingRulesPreparesEveryTreeWithoutMutatingConfig(t *testing.T) {
	routingRule := ruleWithFunctionAlias("ip")
	routingConfig := testRoutingConfig([]*config_parser.RoutingRule{routingRule}, "direct")
	prepared, err := prepareRoutingRules(context.Background(), routingConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := prepared.routing.Policies[0].Statements[0].Rule.AndFunctions[0].Name; got != consts.Function_DestIp {
		t.Fatalf("prepared routing function = %q, want %q", got, consts.Function_DestIp)
	}
	if routingRule.AndFunctions[0].Name != "ip" {
		t.Fatal("rule preparation mutated the source configuration")
	}
}

func ruleWithFunctionAlias(name string) *config_parser.RoutingRule {
	return &config_parser.RoutingRule{
		AndFunctions: []*config_parser.Function{{
			Name:   name,
			Params: []*config_parser.Param{{Val: "192.0.2.0/24"}},
		}},
		Outbound: config_parser.Function{Name: "direct"},
	}
}
