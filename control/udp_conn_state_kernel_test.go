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

// A UDP flow state's timer holds the program that set its callback. Packets
// classified by a newer generation take the timer over, so a long-lived flow
// does not keep a retired generation's programs and maps alive.
func TestUDPConnStateReleasesRetiredGeneration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("BPF privileges required")
	}
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
		return obj
	}
	retired := load(1)
	if err := r.retainMaps(retired); err != nil {
		t.Fatal(err)
	}
	current := load(2)
	packet, _ := routingKernelPacket(netip.MustParseAddrPort("192.168.1.2:40000"), netip.MustParseAddrPort("203.0.113.1:443"), consts.L4ProtoType_UDP)
	classify := func(program *ebpf.Program) {
		t.Helper()
		if _, err := program.Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256), Repeat: 1}); err != nil {
			t.Fatal(err)
		}
	}
	classify(retired.LanIngressL2)
	info, err := retired.LanIngressL2.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, ok := info.ID()
	if !ok {
		t.Skip("program IDs unavailable")
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
		t.Fatal("flow state timer did not hold its program")
	}
	classify(current.LanIngressL2)
	for deadline := time.Now().Add(5 * time.Second); alive(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("retired generation's program outlived the handover of its flow state")
		}
	}
}
