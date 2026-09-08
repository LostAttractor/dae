/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func buildInterfaceRoutingMatcher(t *testing.T) (*RoutingMatcher, *RoutingMatcherBuilder) {
	t.Helper()

	builder, err := compileTestRouting(preparedRules{routing: testRoutingConfig([]*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{{
			Name:   consts.Function_Interface,
			Params: []*config_parser.Param{{Val: "test0"}},
		}},
		Outbound: config_parser.Function{Name: "matched"},
	}},
		"fallback")}, map[string]uint8{
		"matched":  uint8(consts.OutboundUserDefinedMin),
		"fallback": uint8(consts.OutboundDirect),
	},
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("compile routing: %v", err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("BuildUserspace: %v", err)
	}
	return matcher, builder
}

func matchIfindex(t *testing.T, matcher *RoutingMatcher, ifindex uint32) consts.OutboundIndex {
	t.Helper()

	addr := netip.IPv4Unspecified()
	outbound, _, _, err := matcher.match(routingInput{
		src:     netip.AddrPortFrom(addr, 0),
		dst:     netip.AddrPortFrom(addr, 0),
		l4proto: consts.L4ProtoType_TCP,
		ifindex: ifindex,
	})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	return outbound
}

func TestRoutingMatcherDynamicInterface(t *testing.T) {
	matcher, builder := buildInterfaceRoutingMatcher(t)

	if got := matchIfindex(t, matcher, 0); got != consts.OutboundDirect {
		t.Fatalf("daemon download matched an unresolved interface: outbound %v", got)
	}

	if got := matchIfindex(t, matcher, 7); got != consts.OutboundDirect {
		t.Fatalf("unresolved interface selected outbound %v, want %v", got, consts.OutboundDirect)
	}
	if err := builder.updateIfindex(0, 7, false); err != nil {
		t.Fatal(err)
	}
	if got := matchIfindex(t, matcher, 7); got != consts.OutboundUserDefinedMin {
		t.Fatalf("resolved interface selected outbound %v, want %v", got, consts.OutboundUserDefinedMin)
	}
	if err := builder.updateIfindex(0, 0, false); err != nil {
		t.Fatal(err)
	}
	if got := matchIfindex(t, matcher, 7); got != consts.OutboundDirect {
		t.Fatalf("deleted interface selected outbound %v, want %v", got, consts.OutboundDirect)
	}
}

func TestRoutingMatcherConcurrentInterfaceUpdate(t *testing.T) {
	matcher, builder := buildInterfaceRoutingMatcher(t)

	const iterations = 10_000
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			if err := builder.updateIfindex(0, uint32(i%2+7), false); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		addr := netip.IPv4Unspecified()
		for i := 0; i < iterations; i++ {
			outbound, _, _, err := matcher.match(routingInput{
				src:     netip.AddrPortFrom(addr, 0),
				dst:     netip.AddrPortFrom(addr, 0),
				l4proto: consts.L4ProtoType_TCP,
				ifindex: 7,
			})
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

func TestRoutingMatcherRejectsRemovedInterfaceFunctions(t *testing.T) {
	for _, name := range []string{"ifindex", "ifname"} {
		t.Run(name, func(t *testing.T) {
			_, err := compileTestRouting(preparedRules{routing: testRoutingConfig([]*config_parser.RoutingRule{{
				AndFunctions: []*config_parser.Function{{Name: name, Params: []*config_parser.Param{{Val: "1"}}}},
				Outbound:     config_parser.Function{Name: "matched"},
			}},
				config.FunctionOrString("direct"))}, map[string]uint8{"matched": uint8(consts.OutboundUserDefinedMin)},
				nil,
				nil,
			)
			if err == nil {
				t.Fatalf("removed function %q was accepted", name)
			}
		})
	}
}

func newSkipWhileNoaliveMatcher(usable *bool, gotArgs *struct {
	outbound  uint8
	l4proto   consts.L4ProtoType
	ipVersion consts.IpVersionType
}) *RoutingMatcher {
	m := &RoutingMatcher{
		rulesMu:  new(sync.RWMutex),
		profiles: map[uint32][]routingSpan{0: {{End: 2}}},
		matches: []bpfMatchSet{
			{
				Type:     uint8(consts.MatchType_Port),
				Value:    _bpfPortRange{PortStart: 80, PortEnd: 80}.Encode(),
				Outbound: uint8(consts.OutboundUserDefinedMin),
				Flags:    matchFlagSkipNoalive,
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
	addr := netip.IPv4Unspecified()
	outbound, _, _, err := m.match(routingInput{
		src:     netip.AddrPortFrom(addr, 12345),
		dst:     netip.AddrPortFrom(addr, 80),
		l4proto: consts.L4ProtoType_TCP,
	})
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
