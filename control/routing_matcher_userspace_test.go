/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func newSkipWhileNoaliveMatcher(usable *bool, gotArgs *struct {
	outbound  uint8
	l4proto   consts.L4ProtoType
	ipVersion consts.IpVersionType
}) *RoutingMatcher {
	m := &RoutingMatcher{
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
	// skip_while_noalive on direct/block must be a no-op: they do not
	// participate in connectivity checks and are always usable.
	usable := false
	m := &RoutingMatcher{
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
