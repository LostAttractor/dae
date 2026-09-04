/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestPrepareRoutingRulesPreparesEveryTreeWithoutMutatingConfig(t *testing.T) {
	routingRule := ruleWithFunctionAlias("ip")
	requestRule := ruleWithFunctionAlias("ip")
	responseRule := ruleWithFunctionAlias(consts.Function_ResponseIp)
	routingConfig := &config.Routing{Rules: []*config_parser.RoutingRule{routingRule}}
	dnsConfig := &config.Dns{Routing: config.DnsRouting{
		Request:  config.DnsRequestRouting{Rules: []*config_parser.RoutingRule{requestRule}},
		Response: config.DnsResponseRouting{Rules: []*config_parser.RoutingRule{responseRule}},
	}}

	prepared, err := prepareRoutingRules(context.Background(), routingConfig, dnsConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := prepared.routing[0].AndFunctions[0].Name; got != consts.Function_DestIp {
		t.Fatalf("prepared routing function = %q, want %q", got, consts.Function_DestIp)
	}
	if got := prepared.dnsRequest[0].AndFunctions[0].Name; got != consts.Function_DestIp {
		t.Fatalf("prepared DNS request function = %q, want %q", got, consts.Function_DestIp)
	}
	if got := prepared.dnsResponse[0].AndFunctions[0].Name; got != consts.Function_ResponseIp {
		t.Fatalf("prepared DNS response function = %q, want %q", got, consts.Function_ResponseIp)
	}
	if routingRule.AndFunctions[0].Name != "ip" || requestRule.AndFunctions[0].Name != "ip" {
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
