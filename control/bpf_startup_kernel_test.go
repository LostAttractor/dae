// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/rlimit"
)

// Load the entire production collection, including process-name cgroup hooks.
// Classifier-only tests use the zero-valued PARAM and prune those programs, so
// they cannot catch verifier failures in the current-task process-name path.
// These maps are private and none of the programs are attached to the host.
func TestBPFStartupVerifierLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for isolated BPF verifier tests")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	for _, currentTask := range []uint8{0, 1} {
		t.Run(fmt.Sprintf("current_task=%d", currentTask), func(t *testing.T) {
			if currentTask != 0 {
				if err := features.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetCurrentTask); err != nil {
					if errors.Is(err, ebpf.ErrNotSupported) {
						t.Skip("kernel uses the current-comm fallback")
					}
					t.Fatal(err)
				}
			}
			spec, err := loadBpf()
			if err != nil {
				t.Fatal(err)
			}
			if err := spec.Variables["PARAM"].Set(bpfDaeParam{
				ControlPlanePid:      uint32(os.Getpid()),
				HasBpfGetCurrentTask: currentTask,
				SoMarkFromDae:        0x100,
			}); err != nil {
				t.Fatal(err)
			}
			for _, m := range spec.Maps {
				m.Pinning = ebpf.PinNone
			}
			collection, err := ebpf.NewCollection(spec)
			if err != nil {
				if verifier, ok := errors.AsType[*ebpf.VerifierError](err); ok {
					t.Logf("%+v", verifier)
				}
				t.Fatal(err)
			}
			defer collection.Close()
		})
	}
}
