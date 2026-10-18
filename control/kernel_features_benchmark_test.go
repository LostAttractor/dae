// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

// Compare the old production-collection preflight with the attachment probes.
// All maps are private and unpinned, and no program is attached to the host.
// Parsing, namespace setup and actual attachment checks are outside this timer.
func BenchmarkKernelPreflightCollection(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("BPF privileges required")
	}
	production, err := loadBPFSpec()
	if err != nil {
		b.Fatal(err)
	}
	currentTask, err := probeBPFCurrentTask()
	if err != nil {
		b.Fatal(err)
	}
	// Nonzero values retain the same verifier branches as startup. These
	// interface IDs are never used because the benchmark only loads programs.
	if err := production.Variables["PARAM"].Set(bpfDaeParam{
		ControlPlanePid: uint32(os.Getpid()), Dae0Ifindex: 1, Dae0peerIfindex: 2,
		Dae0peerMac: [6]uint8{2, 0, 0, 0, 0, 1}, HasBpfGetCurrentTask: currentTask,
	}); err != nil {
		b.Fatal(err)
	}
	for _, spec := range production.Maps {
		spec.Pinning = ebpf.PinNone
	}
	for _, scenario := range []struct {
		name string
		spec *ebpf.CollectionSpec
	}{{"production", production}, {"probe", kernelProbeSpec(production)}} {
		b.Run(scenario.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				collection, err := ebpf.NewCollection(scenario.spec)
				if err != nil {
					b.Fatal(err)
				}
				collection.Close()
			}
			b.ReportMetric(float64(len(scenario.spec.Programs)), "programs/op")
			b.ReportMetric(float64(len(scenario.spec.Maps)), "maps/op")
		})
	}
}
