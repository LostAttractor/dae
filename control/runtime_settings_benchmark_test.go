// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net"
	"testing"

	"github.com/daeuniverse/dae/component/settings"
)

// Measure the real userspace apply path when only MITM changes and client
// memberships are unchanged. This excludes disk persistence and kernel writes.
func BenchmarkMITMSettingsUnchangedMembers(b *testing.B) {
	for _, count := range []int{0, 64, 1024, 4096} {
		b.Run(fmt.Sprintf("members=%d", count), func(b *testing.B) {
			members := make([]string, count)
			for i := range count {
				members[i] = net.HardwareAddr{2, 0, 0, 0, byte(i >> 8), byte(i)}.String()
			}
			before := settings.Snapshot{Clients: map[string][]string{"gaming": members}, MITM: map[string]bool{}}
			after := settings.Snapshot{Clients: before.Clients, MITM: map[string]bool{"02:00:00:01:00:01": true}}
			plane := &ControlPlane{routingState: &routingState{clientSetSlots: map[string]int{"gaming": 0}}}
			persist := func() error { return nil }
			b.ReportAllocs()
			for b.Loop() {
				if err := plane.applyRuntimeSettings(before, after, persist); err != nil {
					b.Fatal(err)
				}
				before, after = after, before
			}
		})
	}
}
