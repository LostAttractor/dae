// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

type cancelOnInfo struct {
	link.Link
	cancel context.CancelFunc
}

func (l cancelOnInfo) Info() (*link.Info, error) {
	l.cancel()
	return l.Link.Info()
}

func TestReplacementGuardBundleKernel(t *testing.T) {
	if os.Getenv("DAE_TEST_ISOLATED") != "1" {
		t.Skip("requires isolated network/mount namespaces and BPF privileges")
	}
	names := []string{"udp_conn_state_map", "udp_routing_cache_map", "daemon_identity_map"}
	spec, err := parsedBPFSpec()
	if err != nil {
		t.Fatal(err)
	}
	program := func(names []string) (*ebpf.Program, []*ebpf.Map) {
		t.Helper()
		var maps []*ebpf.Map
		var instructions asm.Instructions
		for _, name := range names {
			mapSpec := spec.Maps[name].Copy()
			mapSpec.Pinning = ebpf.PinNone
			m, err := ebpf.NewMap(mapSpec)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { m.Close() })
			maps = append(maps, m)
			instructions = append(instructions, asm.LoadMapPtr(asm.R1, m.FD()))
		}
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 2), asm.Return())
		p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SchedCLS, License: "GPL", Instructions: instructions})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { p.Close() })
		return p, maps
	}
	attach := func(p *ebpf.Program, name string) (link.Link, ReplacementLink) {
		t.Helper()
		device := &netlink.Dummy{Name: name}
		if err := netlink.LinkAdd(device); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { netlink.LinkDel(device) })
		l, err := link.AttachTCX(link.TCXOptions{Interface: device.Index, Attach: ebpf.AttachTCXIngress, Program: p})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		info, err := l.Info()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { removeReplacementGuard(replacementGuardDirectory(info.ID)) })
		return l, ReplacementLink{Kind: "host", Ifindex: device.Index, Role: uint8(hostTCXLanIngress), ID: uint32(info.ID)}
	}
	p, maps := program(names)
	old, oldDescriptor := attach(p, "guard-bundle0")
	next, nextDescriptor := attach(p, "guard-bundle1")
	oldDirectory := replacementGuardDirectory(link.ID(oldDescriptor.ID))
	if added, err := pinReplacementGuard(old, hostTCXLanIngress); err != nil || !added {
		t.Fatalf("pin bundle: created=%v err=%v", added, err)
	}
	if added, err := pinReplacementGuard(old, hostTCXLanIngress); err != nil || added {
		t.Fatalf("existing bundle: created=%v err=%v", added, err)
	}
	missing := filepath.Join(oldDirectory, names[1])
	if err := os.Remove(missing); err != nil {
		t.Fatal(err)
	}
	if _, err := pinReplacementGuard(old, hostTCXLanIngress); err == nil {
		t.Fatal("partial existing bundle accepted")
	}
	if _, err := os.Stat(filepath.Join(oldDirectory, "link")); err != nil {
		t.Fatalf("incomplete bundle lost its guard: %v", err)
	}
	if err := maps[1].Pin(missing); err != nil {
		t.Fatal(err)
	}
	for i, name := range names {
		pinned, err := ebpf.LoadPinnedMap(filepath.Join(oldDirectory, name), nil)
		if err != nil {
			t.Fatal(err)
		}
		info, err := pinned.Info()
		if err != nil {
			t.Fatal(err)
		}
		id, _ := info.ID()
		original, err := maps[i].Info()
		if err != nil {
			t.Fatal(err)
		}
		want, _ := original.ID()
		if id != want {
			t.Fatalf("%s pin refers to map %d, want %d", name, id, want)
		}
		pinned.Close()
	}
	// The invalid state map makes Block fail after creating its new bundle.
	r := NewRuntime()
	r.shared["exited_map"] = maps[0]
	r.kernelLinks.frozen = true
	snapshot := &ReplacementSnapshot{runtime: r, frozen: true, Links: []ReplacementLink{oldDescriptor, nextDescriptor}, links: []link.Link{old, next}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	snapshot.links[1] = cancelOnInfo{next, cancel}
	if err := snapshot.Block(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation during the last guard pin reached StopIngress: %v", err)
	}
	if _, err := os.Stat(replacementGuardDirectory(link.ID(nextDescriptor.ID))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled Block kept its new guard: %v", err)
	}
	snapshot.links[1] = next
	if err := snapshot.Block(t.Context()); err == nil {
		t.Fatal("invalid stopping map accepted")
	}
	snapshot.Release()
	if err := errors.Join(old.Close(), next.Close()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(oldDirectory, "link")); err != nil {
		t.Fatalf("rollback removed original guard: %v", err)
	}
	if _, err := os.Stat(replacementGuardDirectory(link.ID(nextDescriptor.ID))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback left new guard bundle: %v", err)
	}
	// A map pin failure must remove its link and all previously pinned maps.
	bad, _ := program([]string{"udp_conn_state_map", "udp_conn_state_map"})
	badLink, badDescriptor := attach(bad, "guard-bundle2")
	if _, err := pinReplacementGuard(badLink, hostTCXLanIngress); err == nil {
		t.Fatal("conflicting map pins accepted")
	}
	if _, err := os.Stat(replacementGuardDirectory(link.ID(badDescriptor.ID))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed pin left a partial bundle: %v", err)
	}
	for _, m := range maps {
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		m, err := ebpf.LoadPinnedMap(filepath.Join(oldDirectory, name), nil)
		if err != nil {
			t.Fatalf("%s lost after all process FDs closed: %v", name, err)
		}
		m.Close()
	}
	if err := removeReplacementGuard(oldDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed guard left a map pin: %v", err)
	}
}
