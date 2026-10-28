// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
)

// Neither UDP flow nor route-cache timers may retain retired programs under continuous traffic.
func TestUDPConnStateReleasesRetiredGeneration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("BPF privileges required")
	}
	for _, direction := range []string{"forward", "replies only"} {
		t.Run(direction, func(t *testing.T) {
			r := NewRuntime()
			t.Cleanup(func() { _ = r.Close() })
			load := func(generation uint32) *bpfObjects {
				spec, err := loadBpf()
				if err != nil {
					t.Fatal(err)
				}
				for _, m := range spec.Maps {
					m.Pinning = ebpf.PinNone
				}
				obj := new(bpfObjects)
				if err := spec.LoadAndAssign(obj, &ebpf.CollectionOptions{MapReplacements: r.shared}); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = obj.Close() })
				if err := obj.RoutingGeneration.Set(generation); err != nil {
					t.Fatal(err)
				}
				builder, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", ""))
				builder.bpf = &BPFState{bpfObjects: obj}
				if err := builder.BuildKernspace(); err != nil {
					t.Fatal(err)
				}
				return obj
			}
			retired := load(1)
			if err := r.retainMaps(retired); err != nil {
				t.Fatal(err)
			}
			current := load(2)
			source := netip.MustParseAddrPort("192.168.1.2:40000")
			target := netip.MustParseAddrPort("203.0.113.1:443")
			packet, _ := routingKernelPacket(source, target, consts.L4ProtoType_UDP)
			reply, _ := routingKernelPacket(target, source, consts.L4ProtoType_UDP)
			classify := func(program *ebpf.Program, packet []byte) {
				t.Helper()
				verdict, err := program.Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256), Repeat: 1})
				if err != nil || verdict != ^uint32(0) {
					t.Fatalf("UDP verdict=%d err=%v, want direct", verdict, err)
				}
			}
			classify(retired.LanIngressL2, packet)
			key := udpSourceKey(source)
			var cached bpfUdpRoutingCacheValue
			if err := retired.UdpRoutingCacheMap.Lookup(&key, &cached); err != nil || cached.Result.Generation != 1 {
				t.Fatalf("initial route cache=%+v, err=%v", cached, err)
			}
			before := cached.CachedUntil
			classify(retired.LanEgressL2, reply)
			if err := retired.UdpRoutingCacheMap.Lookup(&key, &cached); err != nil || cached.Result.Generation != 1 || cached.CachedUntil <= before {
				t.Fatalf("same-generation reply did not renew the route cache: %+v, err=%v", cached, err)
			}
			info, err := retired.LanIngressL2.Info()
			if err != nil {
				t.Fatal(err)
			}
			id, ok := info.ID()
			if !ok {
				t.Fatal("program IDs unavailable")
			}
			alive := func() bool {
				program, err := ebpf.NewProgramFromID(id)
				if errors.Is(err, os.ErrNotExist) {
					return false
				}
				if err != nil {
					t.Fatal(err)
				}
				program.Close()
				return true
			}
			if err := retired.Close(); err != nil {
				t.Fatal(err)
			}
			if !alive() {
				t.Fatal("route cache timer did not hold its program")
			}
			if direction == "replies only" {
				for range 2 {
					classify(current.LanEgressL2, reply)
				}
				if err := current.UdpRoutingCacheMap.Lookup(&key, &cached); !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("reply retained the retired route cache: %+v, err=%v", cached, err)
				}
			} else {
				classify(current.LanIngressL2, packet)
				if err := current.UdpRoutingCacheMap.Lookup(&key, &cached); err != nil || cached.Result.Generation != 2 {
					t.Fatalf("forward packet did not replace the route cache: %+v, err=%v", cached, err)
				}
			}
			for deadline := time.Now().Add(5 * time.Second); alive(); time.Sleep(10 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatal("retired generation's program outlived the handover of its UDP state")
				}
			}
		})
	}
}
