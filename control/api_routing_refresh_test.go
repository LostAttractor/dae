// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestAPIAddressRefreshKeepsStaticPredicates(t *testing.T) {
	rules := preparedRules{routing: testRoutingConfig(planRulesForTest(t, "dip(192.0.2.1) -> block"), &config_parser.Function{Name: "proxy"})}
	// Reserve a dynamic slot even before a wildcard listener has any addresses.
	rules.bypassAPI(8081, nil)
	matcher, _ := routingMatcherForTest(t, rules)
	plane := &ControlPlane{core: &controlPlaneCore{}, routingMatcher: matcher, routingState: matcher.routingState}
	original := *matcher
	original.routingState = matcher.routingState.snapshot()
	for _, host := range []string{"192.0.2.1", "2001:db8::1", "192.0.2.2", ""} {
		plane.apiListen = ""
		if host != "" {
			plane.apiListen = netip.AddrPortFrom(netip.MustParseAddr(host), 8081).String()
		}
		if err := plane.RefreshAPIRouting(t.Context()); err != nil {
			t.Fatal(err)
		}
		if current, err := plane.APIRoutingCurrent(); !current || err != nil {
			t.Fatalf("refreshed addresses are stale: %v, %v", current, err)
		}
		for _, address := range []string{"192.0.2.1", "192.0.2.2", "2001:db8::1"} {
			for _, port := range []uint16{8081, 8082} {
				for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
					input := routingInput{src: netip.MustParseAddrPort("198.51.100.1:40000"), dst: netip.AddrPortFrom(netip.MustParseAddr(address), port), l4proto: proto}
					want := consts.OutboundUserDefinedMin
					if address == "192.0.2.1" {
						want = consts.OutboundBlock
					}
					before, _, _, err := original.match(input)
					if before != want || err != nil {
						t.Fatalf("refresh mutated the earlier diagnostic snapshot: %v, %v", before, err)
					}
					if address == host && port == 8081 && proto == consts.L4ProtoType_TCP {
						want = consts.OutboundDirect
					}
					got, _, _, err := matcher.match(input)
					if got != want || err != nil {
						t.Fatalf("host=%s destination=%s/%v got=%v err=%v, want=%v", host, input.dst, proto, got, err, want)
					}
				}
			}
		}
	}
	previous := slices.Clone(plane.apiBypass)
	plane.apiListen = "192.0.2.1:8081"
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := plane.RefreshAPIRouting(ctx); !errors.Is(err, context.Canceled) || !slices.Equal(previous, plane.apiBypass) {
		t.Fatalf("canceled refresh changed accepted addresses: %v", err)
	}
}

func TestAPIAddressSlotDoesNotShareStaticTrie(t *testing.T) {
	rules := preparedRules{routing: testRoutingConfig(planRulesForTest(t, "dip(192.0.2.1) -> block"), &config_parser.Function{Name: "proxy"})}
	rules.bypassAPI(8081, []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.1"), Mask: net.CIDRMask(32, 32)}})
	matcher, _ := routingMatcherForTest(t, rules)
	plane := &ControlPlane{core: &controlPlaneCore{}, routingMatcher: matcher, routingState: matcher.routingState,
		apiListen: "192.0.2.2:8081", apiBypass: rules.apiBypass}
	if err := plane.RefreshAPIRouting(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		destination string
		want        consts.OutboundIndex
	}{
		{"192.0.2.1:8081", consts.OutboundBlock},
		{"192.0.2.2:8081", consts.OutboundDirect},
		{"192.0.2.2:8082", consts.OutboundUserDefinedMin},
	} {
		got, _, _, err := matcher.match(routingInput{src: netip.MustParseAddrPort("198.51.100.1:40000"),
			dst: netip.MustParseAddrPort(test.destination), l4proto: consts.L4ProtoType_TCP})
		if got != test.want || err != nil {
			t.Fatalf("refresh changed a shared static predicate at %s: %v, %v; want %v", test.destination, got, err, test.want)
		}
	}
}

func TestAPIAddressRefreshConcurrentReaders(t *testing.T) {
	rules := preparedRules{routing: testRoutingConfig(nil, &config_parser.Function{Name: "proxy"})}
	rules.bypassAPI(8081, nil)
	matcher, _ := routingMatcherForTest(t, rules)
	plane := &ControlPlane{core: &controlPlaneCore{}, routingMatcher: matcher, routingState: matcher.routingState}
	var workers sync.WaitGroup
	workers.Go(func() {
		for i := range 200 {
			plane.apiListen = "192.0.2.1:8081"
			if i%2 == 0 {
				plane.apiListen = "192.0.2.2:8081"
			}
			if err := plane.RefreshAPIRouting(t.Context()); err != nil {
				t.Error(err)
				return
			}
		}
	})
	for range 4 {
		workers.Go(func() {
			for range 200 {
				input := routingInput{src: netip.MustParseAddrPort("198.51.100.1:40000"), dst: netip.MustParseAddrPort("192.0.2.1:8081"), l4proto: consts.L4ProtoType_TCP}
				got, _, _, err := matcher.match(input)
				if err != nil || got != consts.OutboundDirect && got != consts.OutboundUserDefinedMin {
					t.Errorf("concurrent API route = %v, %v", got, err)
					return
				}
				_ = matcher.snapshot()
			}
		})
	}
	workers.Wait()
}
