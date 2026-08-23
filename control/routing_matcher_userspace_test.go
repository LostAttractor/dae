/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func buildIfnameRoutingMatcher(t *testing.T) (*RoutingMatcher, *RoutingMatcherBuilder) {
	t.Helper()

	builder, err := NewRoutingMatcherBuilder(
		[]*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name:   consts.Function_IfName,
				Params: []*config_parser.Param{{Val: "test0"}},
			}},
			Outbound: config_parser.Function{Name: "matched"},
		}},
		map[string]uint8{
			"matched":  uint8(consts.OutboundUserDefinedMin),
			"fallback": uint8(consts.OutboundDirect),
		},
		nil,
		"fallback",
		nil,
	)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilder: %v", err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("BuildUserspace: %v", err)
	}
	return matcher, builder
}

func matchIfindex(t *testing.T, matcher *RoutingMatcher, ifindex uint32) consts.OutboundIndex {
	t.Helper()

	addr := make([]byte, 16)
	outbound, _, _, err := matcher.Match(
		addr,
		addr,
		0,
		0,
		consts.IpVersion_4,
		consts.L4ProtoType_TCP,
		"",
		[16]uint8{},
		ifindex,
		0,
		make([]byte, 16),
	)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	return outbound
}

func TestRoutingMatcherDynamicIfname(t *testing.T) {
	matcher, builder := buildIfnameRoutingMatcher(t)

	if got := matchIfindex(t, matcher, 7); got != consts.OutboundDirect {
		t.Fatalf("unresolved ifname selected outbound %v, want %v", got, consts.OutboundDirect)
	}
	builder.storeIfindex(0, 7)
	if got := matchIfindex(t, matcher, 7); got != consts.OutboundUserDefinedMin {
		t.Fatalf("resolved ifname selected outbound %v, want %v", got, consts.OutboundUserDefinedMin)
	}
	builder.storeIfindex(0, 0)
	if got := matchIfindex(t, matcher, 7); got != consts.OutboundDirect {
		t.Fatalf("deleted ifname selected outbound %v, want %v", got, consts.OutboundDirect)
	}
}

func TestRoutingMatcherConcurrentIfnameUpdate(t *testing.T) {
	matcher, builder := buildIfnameRoutingMatcher(t)

	const iterations = 10_000
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			builder.storeIfindex(0, uint32(i%2+7))
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		addr := make([]byte, 16)
		mac := make([]byte, 16)
		for i := 0; i < iterations; i++ {
			outbound, _, _, err := matcher.Match(
				addr,
				addr,
				0,
				0,
				consts.IpVersion_4,
				consts.L4ProtoType_TCP,
				"",
				[16]uint8{},
				7,
				0,
				mac,
			)
			if err != nil {
				t.Errorf("Match: %v", err)
				return
			}
			if outbound != consts.OutboundUserDefinedMin && outbound != consts.OutboundDirect {
				t.Errorf("unexpected outbound %v", outbound)
				return
			}
		}
	}()
	close(start)
	wg.Wait()
}

func newSkipWhileNoaliveMatcher(usable *bool, gotArgs *struct {
	outbound  uint8
	l4proto   consts.L4ProtoType
	ipVersion consts.IpVersionType
}) *RoutingMatcher {
	m := &RoutingMatcher{
		rulesMu: new(sync.RWMutex),
		matches: []bpfMatchSet{
			{
				Type:             uint8(consts.MatchType_Port),
				Value:            _bpfPortRange{PortStart: 80, PortEnd: 80}.Encode(),
				Outbound:         uint8(consts.OutboundUserDefinedMin),
				SkipWhileNoalive: true,
			},
			{
				Type:     uint8(consts.MatchType_Fallback),
				Outbound: uint8(consts.OutboundDirect),
			},
		},
	}
	if usable != nil {
		m.outboundUsable = func(outbound uint8, l4proto consts.L4ProtoType, ipVersion consts.IpVersionType) bool {
			if gotArgs != nil {
				gotArgs.outbound = outbound
				gotArgs.l4proto = l4proto
				gotArgs.ipVersion = ipVersion
			}
			if l4proto != consts.L4ProtoType_TCP || ipVersion != consts.IpVersion_4 {
				panic("matcher passed the wrong network type")
			}
			return *usable
		}
	}
	return m
}

func matchDport80(t *testing.T, m *RoutingMatcher) consts.OutboundIndex {
	t.Helper()
	addr := make([]byte, 16)
	outbound, _, _, err := m.Match(
		addr, addr,
		12345, 80,
		consts.IpVersion_4,
		consts.L4ProtoType_TCP,
		"",
		[16]uint8{},
		0, 0,
		make([]byte, 16),
	)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	return outbound
}

func TestRoutingMatcherSkipWhileNoalive(t *testing.T) {
	usable := true
	var gotArgs struct {
		outbound  uint8
		l4proto   consts.L4ProtoType
		ipVersion consts.IpVersionType
	}

	// Group usable: the rule hits.
	m := newSkipWhileNoaliveMatcher(&usable, &gotArgs)
	if outbound := matchDport80(t, m); outbound != consts.OutboundUserDefinedMin {
		t.Fatalf("expected group outbound %v, got %v", consts.OutboundUserDefinedMin, outbound)
	}
	if gotArgs.outbound != uint8(consts.OutboundUserDefinedMin) ||
		gotArgs.l4proto != consts.L4ProtoType_TCP ||
		gotArgs.ipVersion != consts.IpVersion_4 {
		t.Fatalf("outboundUsable called with wrong args: %+v", gotArgs)
	}

	// Group not usable: the rule is skipped and fallback hits.
	usable = false
	if outbound := matchDport80(t, m); outbound != consts.OutboundDirect {
		t.Fatalf("expected fallback direct %v, got %v", consts.OutboundDirect, outbound)
	}

	// No state source (e.g. tests): every group is considered usable.
	m = newSkipWhileNoaliveMatcher(nil, nil)
	if outbound := matchDport80(t, m); outbound != consts.OutboundUserDefinedMin {
		t.Fatalf("expected group outbound %v, got %v", consts.OutboundUserDefinedMin, outbound)
	}
}

func TestRoutingMatcherSkipWhileNoaliveOnDirect(t *testing.T) {
	// The builder rejects this configuration. Keep manually constructed
	// matchers defensive as direct/block have no connectivity state.
	usable := false
	m := &RoutingMatcher{
		rulesMu: new(sync.RWMutex),
		matches: []bpfMatchSet{
			{
				Type:             uint8(consts.MatchType_Port),
				Value:            _bpfPortRange{PortStart: 80, PortEnd: 80}.Encode(),
				Outbound:         uint8(consts.OutboundDirect),
				SkipWhileNoalive: true,
			},
			{
				Type:     uint8(consts.MatchType_Fallback),
				Outbound: uint8(consts.OutboundUserDefinedMin),
			},
		},
		outboundUsable: func(outbound uint8, l4proto consts.L4ProtoType, ipVersion consts.IpVersionType) bool {
			return usable
		},
	}
	if outbound := matchDport80(t, m); outbound != consts.OutboundDirect {
		t.Fatalf("expected direct %v, got %v", consts.OutboundDirect, outbound)
	}
}
