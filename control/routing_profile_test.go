/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestEncodeRoutingProfiles(t *testing.T) {
	profiles := []routingProfile{
		{ID: 70007, Spans: []routingSpan{{Start: 2, End: 5}}},
		{ID: 70011, Spans: []routingSpan{{Start: 5, End: 7}, {Start: 1, End: 2}, {Start: 5, End: 7}, {Start: uint32(consts.MaxMatchSetLen - 1), End: uint32(consts.MaxMatchSetLen)}}},
	}
	ids, values := encodeRoutingProfiles(profiles)
	if !slices.Equal(ids, []uint32{70007, 70011}) {
		t.Fatalf("profile IDs = %v", ids)
	}
	for i, want := range [][]uint16{{2, 3, 4}, {5, 6, 1, 5, 6, uint16(consts.MaxMatchSetLen - 1)}} {
		if values[i].Length != uint32(len(want)) || !slices.Equal(values[i].Steps[:values[i].Length], want) {
			t.Fatalf("profile %d = %+v, want steps %v", ids[i], values[i], want)
		}
	}
}

func TestStructuredRoutingSharesRuleSetAcrossProfiles(t *testing.T) {
	parsed := parseStructuredTestConfig(t, `rule_set {
 common { dport(80) -> direct }
 unused { dport(81) -> block }
 }
 policy {
 main { use: common
 fallback: direct }
 lan { use: common
 fallback: block }
 unused { dport(90) -> block
 fallback: direct }
 }
 default: main
 interface { eth0: lan
 eth1: lan
 wg0: main }`)
	conf := &parsed.Routing

	builder, err := compileTestRouting(preparedRules{routing: conf}, map[string]uint8{
		consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
		consts.OutboundBlock.String():  uint8(consts.OutboundBlock),
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(builder.profiles) != 2 || builder.defaultProfileID != builder.profileIDPlan.ids["main"] || !slices.Equal(builder.profiles[0].InterfaceNames, []string{"wg0"}) || !slices.Equal(builder.profiles[1].InterfaceNames, []string{"eth0", "eth1"}) {
		t.Fatalf("selected policies were not deduplicated: %+v", builder.profiles)
	}

	if len(builder.rules) != 3 {
		t.Fatalf("physical match sets = %d, want one shared rule and two fallbacks", len(builder.rules))
	}
	if builder.profiles[0].Spans[0].Start != builder.profiles[1].Spans[0].Start {
		t.Fatalf("common rule_set was not shared: default=%v lan=%v", builder.profiles[0].Spans, builder.profiles[1].Spans)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.IPv4Unspecified()
	match := func(ifindex, profileID uint32, dport uint16) consts.OutboundIndex {
		outbound, _, _, err := matcher.match(routingInput{
			src:       netip.AddrPortFrom(addr, 12345),
			dst:       netip.AddrPortFrom(addr, dport),
			l4proto:   consts.L4ProtoType_TCP,
			ifindex:   ifindex,
			profileID: profileID,
		})
		if err != nil {
			t.Fatal(err)
		}
		return outbound
	}
	if got := match(0, 0, 81); got != consts.OutboundDirect {
		t.Fatalf("default fallback = %v, want direct", got)
	}
	if got := match(7, builder.profileIDPlan.ids["lan"], 81); got != consts.OutboundBlock {
		t.Fatalf("lan fallback = %v, want block", got)
	}
	if got := match(7, builder.profileIDPlan.ids["lan"], 80); got != consts.OutboundDirect {
		t.Fatalf("shared rule = %v, want direct", got)
	}
}

func TestRoutingPolicyFallbackIdentity(t *testing.T) {
	markedFallback := func(lastMark string) *config_parser.Function {
		params := make([]*config_parser.Param, 6)
		for i := range params {
			params[i] = &config_parser.Param{Key: consts.OutboundParam_Mark, Val: "1"}
		}
		params[len(params)-1].Val = lastMark
		return &config_parser.Function{Name: consts.OutboundDirect.String(), Params: params}
	}
	conf := &config.Routing{
		Policies: []config.RoutingPolicy{
			{Fallback: markedFallback("2")},
			{Name: "lan", Fallback: markedFallback("3")},
		},
		Interfaces: []config.RoutingInterface{{Name: "eth0", Policy: "lan"}},
	}

	builder, err := compileTestRouting(preparedRules{routing: conf}, map[string]uint8{
		consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(builder.rules) != 2 {
		t.Fatalf("physical match sets = %d, want two semantically distinct fallbacks", len(builder.rules))
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.IPv4Unspecified()
	matchMark := func(ifindex, profileID uint32) uint32 {
		_, mark, _, err := matcher.match(routingInput{
			src:       netip.AddrPortFrom(addr, 1),
			dst:       netip.AddrPortFrom(addr, 1),
			l4proto:   consts.L4ProtoType_TCP,
			ifindex:   ifindex,
			profileID: profileID,
		})
		if err != nil {
			t.Fatal(err)
		}
		return mark
	}
	if got := matchMark(0, 0); got != 2 {
		t.Fatalf("default fallback mark = %d, want mark 2", got)
	}
	if got := matchMark(7, builder.profileIDPlan.ids["lan"]); got != 3 {
		t.Fatalf("interface fallback mark = %d, want 3", got)
	}
}

func TestStructuredRoutingStopsDAGExpansionAtLimit(t *testing.T) {
	baseRule := &config_parser.RoutingRule{
		AndFunctions: []*config_parser.Function{{
			Name:   consts.Function_DestPort,
			Params: []*config_parser.Param{{Val: "80"}},
		}},
		Outbound: config_parser.Function{Name: consts.OutboundDirect.String()},
	}
	sets := []config.RoutingRuleSet{{
		Name: "set0",
		Statements: []config.RoutingStatement{{
			Kind: config.RoutingStatementRule,
			Rule: baseRule,
		}},
	}}
	for i := 1; i <= 11; i++ {
		previous := sets[i-1].Name
		sets = append(sets, config.RoutingRuleSet{
			Name: "set" + strconv.Itoa(i),
			Statements: []config.RoutingStatement{
				{Kind: config.RoutingStatementUse, Use: previous},
				{Kind: config.RoutingStatementUse, Use: previous},
			},
		})
	}
	conf := &config.Routing{
		RuleSets: sets,
		Policies: []config.RoutingPolicy{{
			Statements: []config.RoutingStatement{{Kind: config.RoutingStatementUse, Use: sets[len(sets)-1].Name}},
			Fallback:   &config_parser.Function{Name: consts.OutboundDirect.String()},
		}},
	}
	_, err := compileTestRouting(preparedRules{routing: conf}, map[string]uint8{
		consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
	}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "executes too many match sets") {
		t.Fatalf("error = %v, want execution length limit", err)
	}
}

func TestRoutingProfileIDsRemainStableAcrossReloadOrder(t *testing.T) {
	allocator := routingProfileIDAllocator{}
	first, err := allocator.plan([]string{"lan", "wan"})
	if err != nil {
		t.Fatal(err)
	}
	allocator = first

	second, err := allocator.plan([]string{"guest", "wan", "lan"})
	if err != nil {
		t.Fatal(err)
	}
	if second.ids["lan"] != first.ids["lan"] || second.ids["wan"] != first.ids["wan"] {
		t.Fatalf("existing profile IDs changed: first=%v second=%v", first, second)
	}
	if second.ids["guest"] == first.ids["lan"] || second.ids["guest"] == first.ids["wan"] {
		t.Fatalf("new profile reused an existing ID: first=%v second=%v", first, second)
	}
	allocator = second

	third, err := allocator.plan([]string{"lan", "guest"})
	if err != nil {
		t.Fatal(err)
	}
	if third.ids["lan"] != first.ids["lan"] || third.ids["guest"] != second.ids["guest"] {
		t.Fatalf("profile IDs changed after removal: second=%v third=%v", second, third)
	}
}

func TestRoutingProfileIDsRejectExhaustion(t *testing.T) {
	allocator := routingProfileIDAllocator{next: uint64(^uint32(0))}
	last, err := allocator.plan([]string{"last"})
	if err != nil {
		t.Fatal(err)
	}
	if last.ids["last"] != ^uint32(0) {
		t.Fatalf("last profile ID = %d", last.ids["last"])
	}
	allocator = last
	known, err := allocator.plan([]string{"last"})
	if err != nil || known.ids["last"] != ^uint32(0) {
		t.Fatalf("existing profile after exhaustion = %v, %v", known.ids, err)
	}
	if _, err := allocator.plan([]string{"new"}); err == nil {
		t.Fatal("expected profile ID exhaustion error")
	}
}

func TestStructuredRoutingValidatesUnusedRuleSets(t *testing.T) {
	conf := &config.Routing{
		RuleSets: []config.RoutingRuleSet{{
			Name: "unused",
			Statements: []config.RoutingStatement{{
				Kind: config.RoutingStatementRule,
				Rule: &config_parser.RoutingRule{
					AndFunctions: []*config_parser.Function{{
						Name:   consts.Function_DestPort,
						Params: []*config_parser.Param{{Val: "80"}},
					}},
					Outbound: config_parser.Function{Name: "missing-outbound"},
				},
			}},
		}},
		Policies: []config.RoutingPolicy{{Fallback: &config_parser.Function{Name: consts.OutboundDirect.String()}}},
	}
	_, err := compileTestRouting(preparedRules{routing: conf}, map[string]uint8{
		consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
	}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "missing-outbound") {
		t.Fatalf("error = %v, want unused rule-set outbound validation", err)
	}
}

func TestStructuredRoutingFullyValidatesUnusedRuleSets(t *testing.T) {
	tests := []struct {
		name string
		rule *config_parser.RoutingRule
		want string
	}{
		{
			name: "invalid outbound option",
			rule: &config_parser.RoutingRule{
				AndFunctions: []*config_parser.Function{{
					Name:   consts.Function_DestPort,
					Params: []*config_parser.Param{{Val: "80"}},
				}},
				Outbound: config_parser.Function{
					Name:   consts.OutboundDirect.String(),
					Params: []*config_parser.Param{{Val: consts.OutboundParam_SkipWhileNoalive}},
				},
			},
			want: "skip_while_noalive cannot be used on outbound direct",
		},
		{
			name: "invalid domain regex",
			rule: &config_parser.RoutingRule{
				AndFunctions: []*config_parser.Function{{
					Name: consts.Function_Domain,
					Params: []*config_parser.Param{{
						Key: string(consts.RoutingDomainKey_Regex),
						Val: "(",
					}},
				}},
				Outbound: config_parser.Function{Name: consts.OutboundDirect.String()},
			},
			want: "failed to compile regex",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := &config.Routing{
				RuleSets: []config.RoutingRuleSet{{
					Name: "unused",
					Statements: []config.RoutingStatement{{
						Kind: config.RoutingStatementRule,
						Rule: tt.rule,
					}},
				}},
				Policies: []config.RoutingPolicy{{Fallback: &config_parser.Function{Name: consts.OutboundDirect.String()}}},
			}
			_, err := compileTestRouting(preparedRules{routing: conf}, map[string]uint8{
				consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
			}, nil, nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestPolicySelectionAcrossDefaultSwitchAndRebinding(t *testing.T) {
	conf := parseStructuredTestConfig(t, `policy {
 main { fallback: direct(mark: 10) }
 other { fallback: direct(mark: 20) }
 unused { fallback: direct }
 }
 default: main
 interface { eth0: main
 eth1: other }`)
	state := &BPFState{}
	first, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0}, state, nil)
	if err != nil {
		t.Fatal(err)
	}
	state.routingProfileIDs = *first.profileIDPlan
	mainID, otherID := first.defaultProfileID, first.profileIDPlan.ids["other"]
	if mainID == 0 || mainID == otherID {
		t.Fatalf("invalid identities: %v", first.profileIDPlan.ids)
	}
	if _, exists := first.profileIDPlan.ids["unused"]; exists {
		t.Fatal("unused policy consumed an ID")
	}
	conf.Routing.Default = "other"
	conf.Routing.Interfaces = []config.RoutingInterface{{Name: "wg0", Policy: "main"}, {Name: "eth0", Policy: "other"}}
	slices.Reverse(conf.Routing.Policies)
	second, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0}, state, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.defaultProfileID != otherID || second.profileIDPlan.ids["main"] != mainID || len(second.profiles) != 2 {
		t.Fatalf("identities changed: %v", second.profileIDPlan.ids)
	}
	matcher, err := second.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[uint32]uint32{0: 20, mainID: 10, otherID: 20} {
		_, mark, _, err := matcher.match(routingInput{src: netip.MustParseAddrPort("192.0.2.1:1234"), dst: netip.MustParseAddrPort("198.51.100.1:443"), l4proto: consts.L4ProtoType_TCP, profileID: id})
		if err != nil || mark != want {
			t.Fatalf("profile %d: mark=%d err=%v", id, mark, err)
		}
	}
}

func TestPolicyUseOrderAndFallbackPosition(t *testing.T) {
	conf := parseStructuredTestConfig(t, `rule_set {
 first { dport(80) -> direct(mark: 1) }
 second { dport(80,81) -> direct(mark: 2) }
 nested { use: first, second }
 }
 fallback: direct(mark: 4)
 dport(22) -> direct(mark: 3)
 use: nested
 dport(80,82) -> direct(mark: 5)`)
	builder, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	for port, want := range map[uint16]uint32{22: 3, 80: 1, 81: 2, 82: 5, 443: 4} {
		_, mark, _, err := matcher.match(routingInput{src: netip.MustParseAddrPort("192.0.2.1:1234"), dst: netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), port), l4proto: consts.L4ProtoType_TCP})
		if err != nil || mark != want {
			t.Fatalf("port %d: mark=%d err=%v, want %d", port, mark, err, want)
		}
	}
}

func TestUnusedPoliciesAreFullyValidated(t *testing.T) {
	for _, body := range []string{
		"fallback: missing",
		"fallback: direct(skip_while_noalive)",
		"domain(regex: '(') -> direct\nfallback: direct",
		"dport(70000) -> direct\nfallback: direct",
	} {
		conf := parseStructuredTestConfig(t, "fallback: direct\npolicy { unused { "+body+" } }")
		if _, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0}, nil, nil); err == nil {
			t.Fatalf("accepted invalid unused policy: %s", body)
		}
	}
}
