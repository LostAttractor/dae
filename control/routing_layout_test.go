// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
)

func TestRoutingMapLayouts(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	match := bpfMatchSet{}
	if unsafe.Sizeof(match) != 24 || unsafe.Offsetof(match.Mark) != 16 || unsafe.Offsetof(match.Flags) != 22 || unsafe.Offsetof(match.Action) != 23 {
		t.Fatalf("unexpected match_set ABI: %+v", match)
	}
	if spec.Maps["routing_map"].ValueSize != 24 {
		t.Fatal("routing_map does not use the compact match_set ABI")
	}
	profile := spec.Maps["routing_profile_map"]
	if spec.Maps["routing_interface_map"].MaxEntries != maxRoutingInterfaces {
		t.Fatal("kernel interface capacity differs from the Go compiler limit")
	}
	if profile.Type != ebpf.Hash || profile.Flags != unix.BPF_F_NO_PREALLOC || profile.KeySize != 4 ||
		profile.ValueSize != 4+2*uint32(consts.MaxMatchSetLen) || profile.ValueSize != uint32(unsafe.Sizeof(bpfRoutingProfile{})) ||
		profile.MaxEntries != maxRoutingInterfaces+1 {
		t.Fatalf("unexpected profile map: %+v", profile)
	}
	if spec.Maps["routing_profile_step_map"] != nil {
		t.Fatal("obsolete profile step map is still allocated")
	}

}

func newRoutingLayoutTestMap(t *testing.T, name string, maxEntries uint32) *ebpf.Map {
	t.Helper()
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	ms := spec.Maps[name]
	ms.Pinning = ebpf.PinNone
	ms.MaxEntries = maxEntries
	m, err := ebpf.NewMap(ms)
	if errors.Is(err, unix.EPERM) {
		t.Skip("creating an eBPF map requires privileges")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func TestRoutingProfilesUsePrivateGenerations(t *testing.T) {
	var previous *ebpf.Map
	for generation := uint32(1); generation <= 3; generation++ {
		profiles := newRoutingLayoutTestMap(t, "routing_profile_map", maxRoutingInterfaces+1)
		interfaces := newRoutingLayoutTestMap(t, "routing_interface_map", maxRoutingInterfaces)
		b := &RoutingMatcherBuilder{routingState: &routingState{bpf: &BPFState{bpfObjects: &bpfObjects{RoutingProfileMap: profiles, RoutingInterfaceMap: interfaces}}}}
		b.profiles = []routingProfile{{ID: 0, Spans: []routingSpan{{Start: 0, End: 1}}}}
		for i := uint32(1); i <= maxRoutingInterfaces; i++ {
			b.profiles = append(b.profiles, routingProfile{ID: generation*70000 + i,
				Spans: []routingSpan{{Start: generation, End: generation + 1}}})
		}
		if err := b.uploadRoutingProfiles(); err != nil {
			t.Fatal(err)
		}
		var key uint32
		if err := interfaces.NextKey(nil, &key); !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("stale interface binding: %v", err)
		}
		var value bpfRoutingProfile
		for _, p := range b.profiles {
			if err := profiles.Lookup(p.ID, &value); err != nil || value.Length != 1 || value.Steps[0] != uint16(p.Spans[0].Start) {
				t.Fatalf("generation %d, profile %d: %v, %+v", generation, p.ID, err, value)
			}
		}
		if generation > 1 {
			if err := profiles.Lookup((generation-1)*70000+1, &value); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("retired profile still exists: %v", err)
			}
			if err := previous.Lookup((generation-1)*70000+1, &value); err != nil {
				t.Fatalf("candidate changed old projection: %v", err)
			}
		}
		if err := interfaces.Update(uint32(7), generation*70000+1, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		previous = profiles
	}
}
