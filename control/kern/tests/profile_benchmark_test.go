//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
)

// Every profile shares the physical rules. Select the last profile so sparse
// stable IDs and a populated profile table are exercised on the packet path.
func BenchmarkRoutingProfiles(b *testing.B) {
	for _, count := range []int{1, 16, 257} {
		for _, rules := range []int{128, 1024} {
			b.Run(fmt.Sprintf("profiles=%d/rules=%d", count, rules), func(b *testing.B) {
				obj, err := loadTestObjects(b)
				if err != nil {
					b.Fatal(err)
				}
				var selectedID uint32
				for i := 1; i < count; i++ {
					selectedID = uint32(70000 + i)
					profile := bpftestRoutingProfile{Length: uint32(rules)}
					for step := 0; step < rules; step++ {
						profile.Steps[step] = uint16(step)
					}
					if err := obj.RoutingProfileMap.Update(selectedID, profile, ebpf.UpdateAny); err != nil {
						b.Fatal(err)
					}
				}
				if err := obj.RoutingInterfaceMap.Update(uint32(0), selectedID, ebpf.UpdateAny); err != nil {
					b.Fatal(err)
				}
				benchmarkUDPRoutingCache(b, obj, rules, false)
			})
		}
	}
}
