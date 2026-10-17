// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
)

func TestBuiltRoutingOwnsInterfaceBindings(t *testing.T) {
	first, builder := buildInterfaceRoutingMatcher(t)
	second, err := builder.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	if err := first.updateIfindex(0, 7, false); err != nil {
		t.Fatal(err)
	}
	if matchIfindex(t, first, 7) != consts.OutboundUserDefinedMin || matchIfindex(t, second, 7) != consts.OutboundDirect {
		t.Fatal("independent builds share interface bindings")
	}
	if builder.rules[0].Value != [16]byte{} {
		t.Fatal("runtime binding mutated compilation")
	}
	builder.rules[0].Outbound = uint8(consts.OutboundBlock)
	if matchIfindex(t, first, 7) != consts.OutboundUserDefinedMin {
		t.Fatal("compiler mutated an installed program")
	}
}

func TestBuiltRoutingOwnsClientMembership(t *testing.T) {
	builder, first := buildClientMatcher(t, clientRule("work", false, "proxy"))
	second, err := builder.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	if err := first.SetClientMembers("work", [][6]byte{mac}, false); err != nil {
		t.Fatal(err)
	}
	requireClientRoute(t, first, mac, 443, consts.OutboundUserDefinedMin)
	requireClientRoute(t, second, mac, 443, consts.OutboundDirect)
	if len(builder.simulatedLpmTries[builder.clientSetSlots["work"]]) != 0 {
		t.Fatal("membership mutated compilation")
	}
}

func TestDestinationSnapshotOwnsInterfaceBindings(t *testing.T) {
	live, builder := destinationTestMatcher(t, "interface(test0) -> dnat(198.51.100.20)")
	update := func(index uint32) {
		for _, patch := range builder.interfaceRulePatches {
			if err := live.updateIfindex(patch.matchIndex, index, false); err != nil {
				t.Error(err)
			}
		}
	}
	update(7)
	frozen := live.snapshotDestinations()
	p := &RouteParam{Src: netip.MustParseAddrPort("192.0.2.1:40000"), Dest: netip.MustParseAddrPort("192.0.2.2:443"), routingResult: &routingResult{Ifindex: 7}, networkType: *common.NetworkTCP4.NetworkType()}
	var worker sync.WaitGroup
	worker.Go(func() {
		for range 1000 {
			update(9)
			update(7)
		}
	})
	for range 1000 {
		got, err := frozen.matchDestination(p)
		if err != nil || got != netip.MustParseAddrPort("198.51.100.20:443") {
			t.Errorf("live interface update changed UDP lifetime: %s, %v", got, err)
			break
		}
	}
	worker.Wait()
}
