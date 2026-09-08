//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
)

func routingDomainRule(id uint32, action consts.MatchAction, outbound consts.OutboundIndex) bpftestMatchSet {
	rule := bpftestMatchSet{Type: uint8(consts.MatchType_DomainSet), Action: uint8(action), Outbound: uint8(outbound)}
	binary.NativeEndian.PutUint32(rule.Value[:4], id)
	return rule
}

func routingPortRule(port uint16, action consts.MatchAction, outbound consts.OutboundIndex) bpftestMatchSet {
	rule := bpftestMatchSet{Type: uint8(consts.MatchType_Port), Action: uint8(action), Outbound: uint8(outbound)}
	binary.NativeEndian.PutUint16(rule.Value[:2], port)
	binary.NativeEndian.PutUint16(rule.Value[2:4], port)
	return rule
}

func installRoutingFlow(t testing.TB, obj *bpftestObjects, rules []bpftestMatchSet) {
	t.Helper()
	profile := bpftestRoutingProfile{Length: uint32(len(rules))}
	ruleEnd, subruleEnd := -1, -1
	for i := len(rules) - 1; i >= 0; i-- {
		rule := rules[i]
		switch consts.MatchAction(rule.Action) {
		case consts.MatchActionOr:
			if subruleEnd <= i {
				t.Fatalf("OR fixture at %d has no subrule tail", i)
			}
			rule.Mark = uint32(subruleEnd - i)
		case consts.MatchActionAnd:
			if ruleEnd <= i {
				t.Fatalf("AND fixture at %d has no rule tail", i)
			}
			rule.Mark = uint32(ruleEnd - i + 1)
			subruleEnd = i
		default:
			ruleEnd, subruleEnd = i, i
		}
		profile.Steps[i] = uint16(i)
		if err := obj.RoutingMap.Update(uint32(i), rule, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	if err := obj.RoutingProfileMap.Update(uint32(0), profile, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
}

func routingFlowPacket(t testing.TB, obj *bpftestObjects) (packet, ctx []byte, key bpftestTuplesKey) {
	t.Helper()
	status, packet, ctx, err := runBpfProgram(obj.TestpktgenMacMatch, make([]byte, 4096-256-320), make([]byte, 256))
	if err != nil || status != 0 {
		t.Fatalf("generate TCP SYN: status=%d err=%v", status, err)
	}
	key = bpftestTuplesKey{L4proto: 6}
	key.Sip.U6Addr8 = netip.AddrFrom4([4]byte(packet[26:30])).As16()
	key.Dip.U6Addr8 = netip.AddrFrom4([4]byte(packet[30:34])).As16()
	key.Sport = binary.NativeEndian.Uint16(packet[34:36])
	key.Dport = binary.NativeEndian.Uint16(packet[36:38])
	return packet, ctx, key
}
