// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"golang.org/x/sys/unix"
)

func clientRule(name string, not bool, outbound string, extra ...*config_parser.Function) *config_parser.RoutingRule {
	return &config_parser.RoutingRule{
		AndFunctions: append([]*config_parser.Function{{
			Name: consts.Function_Client, Not: not, Params: []*config_parser.Param{{Val: name}},
		}}, extra...),
		Outbound: config_parser.Function{Name: outbound},
	}
}

func buildClientMatcher(t *testing.T, rules ...*config_parser.RoutingRule) (*RoutingMatcherBuilder, *RoutingMatcher) {
	t.Helper()
	optimized, err := routing.ApplyRulesOptimizers(rules, &routing.MergeAndSortRulesOptimizer{}, &routing.DeduplicateParamsOptimizer{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewRoutingMatcherBuilder(optimized, map[string]uint8{
		"proxy": uint8(consts.OutboundUserDefinedMin), "direct": uint8(consts.OutboundDirect), "block": uint8(consts.OutboundBlock),
	}, nil, "direct", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := b.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	return b, m
}

func matchClient(m *RoutingMatcher, mac [6]byte, port uint16) (consts.OutboundIndex, error) {
	var address, sourceMAC [16]byte
	copy(sourceMAC[10:], mac[:])
	outbound, _, _, err := m.Match(address[:], address[:], 12345, port, consts.IpVersion_4,
		consts.L4ProtoType_TCP, "", [16]byte{}, 0, 0, sourceMAC[:])
	return outbound, err
}

func requireClientRoute(t *testing.T, m *RoutingMatcher, mac [6]byte, port uint16, want consts.OutboundIndex) {
	t.Helper()
	if got, err := matchClient(m, mac, port); err != nil || got != want {
		t.Fatalf("MAC %x port %d route = %v, %v; want %v", mac, port, got, err, want)
	}
}

func TestClientMembershipUpdatesSharedMACMatches(t *testing.T) {
	mac := [6]byte{2, 1, 2, 3, 4, 5}
	const name = "游戏 加速"
	b, m := buildClientMatcher(t,
		clientRule(name, false, "proxy", &config_parser.Function{Name: consts.Function_DestPort, Params: []*config_parser.Param{{Val: "443"}}}),
		clientRule(name, false, "block"),
		&config_parser.RoutingRule{
			AndFunctions: []*config_parser.Function{{Name: consts.Function_Mac, Params: []*config_parser.Param{{Val: "02:01:02:03:04:07"}}}},
			Outbound:     config_parser.Function{Name: "proxy"},
		},
	)
	if !slices.Equal(b.ClientSets(), []string{name}) || len(b.simulatedLpmTries) != 2 {
		t.Fatalf("expected one dynamic and one static MAC set: %v, %d slots", b.ClientSets(), len(b.simulatedLpmTries))
	}
	requireClientRoute(t, m, mac, 443, consts.OutboundDirect)
	staticMAC := [6]byte{2, 1, 2, 3, 4, 7}
	requireClientRoute(t, m, staticMAC, 443, consts.OutboundUserDefinedMin)
	if err := b.SetClientMembers(m, name, [][6]byte{mac}, false); err != nil {
		t.Fatal(err)
	}
	requireClientRoute(t, m, mac, 443, consts.OutboundUserDefinedMin)
	requireClientRoute(t, m, mac, 80, consts.OutboundBlock)
	requireClientRoute(t, m, [6]byte{}, 443, consts.OutboundDirect)
	requireClientRoute(t, m, [6]byte{2, 1, 2, 3, 4, 6}, 443, consts.OutboundDirect)

	if err := b.SetClientMembers(m, name, nil, false); err != nil {
		t.Fatal(err)
	}
	requireClientRoute(t, m, mac, 443, consts.OutboundDirect)
	requireClientRoute(t, m, staticMAC, 443, consts.OutboundUserDefinedMin)
}

func TestClientEmptyAndNegatedSetsKeepRuleSemantics(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	b, m := buildClientMatcher(t, clientRule("first", true, "proxy"), clientRule("second", true, "proxy"))
	if !slices.Equal(b.ClientSets(), []string{"first", "second"}) || len(b.rules) != 3 {
		t.Fatalf("negated client rules were merged: sets %v, rules %+v", b.ClientSets(), b.rules)
	}
	requireClientRoute(t, m, mac, 443, consts.OutboundUserDefinedMin)
	if err := b.SetClientMembers(m, "first", [][6]byte{mac}, false); err != nil {
		t.Fatal(err)
	}
	// !first does not match, but !second must still match its empty set.
	requireClientRoute(t, m, mac, 443, consts.OutboundUserDefinedMin)
	if err := b.SetClientMembers(m, "second", [][6]byte{mac}, false); err != nil {
		t.Fatal(err)
	}
	requireClientRoute(t, m, mac, 443, consts.OutboundDirect)
}

func TestClientSetRejectsInvalidSyntax(t *testing.T) {
	for _, params := range [][]*config_parser.Param{
		nil, {{Val: ""}}, {{Val: " "}}, {{Val: "first"}, {Val: "second"}}, {{Key: "set", Val: "gaming"}},
		{{Val: "a/b"}}, {{Val: "a\nb"}}, {{Val: strings.Repeat("x", 129)}},
	} {
		rule := clientRule("", false, "proxy")
		rule.AndFunctions[0].Params = params
		if _, err := NewRoutingMatcherBuilder([]*config_parser.RoutingRule{rule}, map[string]uint8{
			"proxy": uint8(consts.OutboundUserDefinedMin), "direct": uint8(consts.OutboundDirect),
		}, nil, "direct", nil, nil, nil); err == nil {
			t.Errorf("accepted invalid client parameters: %+v", params)
		}
	}
}

func TestClientMembershipConcurrentMatching(t *testing.T) {
	b, m := buildClientMatcher(t, clientRule("gaming", false, "proxy"))
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	var workers sync.WaitGroup
	workers.Go(func() {
		for i := 0; i < 1000; i++ {
			members := [][6]byte{mac}
			if i%2 == 0 {
				members = nil
			}
			if err := b.SetClientMembers(m, "gaming", members, false); err != nil {
				t.Error(err)
				return
			}
		}
	})
	for range 4 {
		workers.Go(func() {
			for range 1000 {
				got, err := matchClient(m, mac, 443)
				if err != nil || got != consts.OutboundDirect && got != consts.OutboundUserDefinedMin {
					t.Errorf("concurrent match = %v, %v", got, err)
					return
				}
			}
		})
	}
	workers.Wait()
}

func attachClientKernelMaps(t *testing.T, b *RoutingMatcherBuilder) *ebpf.Map {
	t.Helper()
	innerSpec := &ebpf.MapSpec{Type: ebpf.LPMTrie, KeySize: uint32(unsafe.Sizeof(_bpfLpmKey{})), ValueSize: 4,
		MaxEntries: 8, Flags: unix.BPF_F_NO_PREALLOC}
	template, err := ebpf.NewMap(innerSpec)
	if errors.Is(err, unix.EPERM) {
		t.Skip("creating an eBPF map requires privileges")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = template.Close() })
	outer, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.ArrayOfMaps, KeySize: 4, ValueSize: 4,
		MaxEntries: uint32(len(b.clientSetSlots)), InnerMap: innerSpec})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outer.Close() })
	b.bpf = &bpfState{bpfObjects: &bpfObjects{bpfMaps: bpfMaps{UnusedLpmType: template, LpmArrayMap: outer}}}
	return outer
}

func TestClientMembershipSwapsKernelMap(t *testing.T) {
	b, m := buildClientMatcher(t, clientRule("gaming", false, "proxy"))
	outer := attachClientKernelMaps(t, b)
	mac := [6]byte{2, 1, 2, 3, 4, 5}
	key := cidrToBpfLpmKey(sourceMacPrefixes([][6]byte{mac})[0])
	for _, enabled := range []bool{false, true, false} {
		var members [][6]byte
		if enabled {
			members = [][6]byte{mac}
		}
		if err := b.SetClientMembers(m, "gaming", members, true); err != nil {
			t.Fatal(err)
		}
		var inner *ebpf.Map
		if err := outer.Lookup(uint32(0), &inner); err != nil {
			t.Fatal(err)
		}
		var value uint32
		err := inner.Lookup(key, &value)
		inner.Close()
		if enabled && (err != nil || value != 1) || !enabled && !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("kernel membership %v = %d, %v", enabled, value, err)
		}
	}
	// File reload uses the same live kernel update, and a failed replacement
	// must preserve both the userspace decision and the accepted settings.
	path := filepath.Join(t.TempDir(), "runtime-state.json")
	store, err := settings.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	plane := &ControlPlane{settings: store, routingMatcherBuilder: b, routingMatcher: m, kernelActive: true}
	if err := os.WriteFile(path, []byte(`{"selectors":{},"clients":{"gaming":["02:01:02:03:04:05"]},"mitm":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if changed, err := plane.ReloadRuntimeSettings(); !changed || err != nil {
		t.Fatal(changed, err)
	}
	var inner *ebpf.Map
	if err := outer.Lookup(uint32(0), &inner); err != nil {
		t.Fatal(err)
	}
	var value uint32
	err = inner.Lookup(key, &value)
	inner.Close()
	if err != nil || value != 1 {
		t.Fatalf("reloaded kernel membership = %d, %v", value, err)
	}
	if err := os.WriteFile(path, []byte(`{"selectors":{},"clients":{},"mitm":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	outer.Close()
	if changed, err := plane.ReloadRuntimeSettings(); changed || err == nil {
		t.Fatal("reload through a closed outer map succeeded", changed, err)
	}
	if !slices.Equal(store.Members("gaming"), [][6]byte{mac}) {
		t.Fatal("failed kernel reload changed accepted settings")
	}
	requireClientRoute(t, m, mac, 443, consts.OutboundUserDefinedMin)
}
