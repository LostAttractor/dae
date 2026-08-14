//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestCreateNetkitPairIntegration(t *testing.T) {
	if os.Getenv("DAE_NETKIT_TEST") != "1" {
		t.Skip("set DAE_NETKIT_TEST=1 to enable")
	}
	if os.Geteuid() != 0 {
		t.Skip("root is required")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hostNs, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer hostNs.Close()
	peerNs, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer peerNs.Close()
	defer netns.Set(hostNs)
	if err := netns.Set(hostNs); err != nil {
		t.Fatal(err)
	}

	name := fmt.Sprintf("dnk%d", os.Getpid())
	peerName := fmt.Sprintf("dnp%d", os.Getpid())
	if err := createNetkitPair(name, peerName); err != nil {
		t.Fatal(err)
	}
	primary, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(primary) })

	primaryNetkit, ok := primary.(*netlink.Netkit)
	if !ok {
		t.Fatalf("primary type = %T, want *netlink.Netkit", primary)
	}
	if primaryNetkit.Mode != netlink.NETKIT_MODE_L2 || !primaryNetkit.IsPrimary() {
		t.Fatalf("primary mode = %d, primary = %v", primaryNetkit.Mode, primaryNetkit.IsPrimary())
	}
	if primaryNetkit.Policy != netlink.NETKIT_POLICY_FORWARD || primaryNetkit.PeerPolicy != netlink.NETKIT_POLICY_FORWARD {
		t.Fatalf("primary policies = (%d, %d), want forward", primaryNetkit.Policy, primaryNetkit.PeerPolicy)
	}
	if !primaryNetkit.SupportsScrub() || primaryNetkit.Scrub != netlink.NETKIT_SCRUB_DEFAULT || primaryNetkit.PeerScrub != netlink.NETKIT_SCRUB_DEFAULT {
		t.Fatalf("primary scrub = (%d, %d), supported = %v", primaryNetkit.Scrub, primaryNetkit.PeerScrub, primaryNetkit.SupportsScrub())
	}
	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetNsFd(peer, int(peerNs)); err != nil {
		t.Fatal(err)
	}
	if err := netns.Set(peerNs); err != nil {
		t.Fatal(err)
	}
	peer, err = netlink.LinkByName(peerName)
	if err != nil {
		t.Fatal(err)
	}
	peerNetkit, ok := peer.(*netlink.Netkit)
	if !ok {
		t.Fatalf("peer type = %T, want *netlink.Netkit", peer)
	}
	if peerNetkit.Mode != netlink.NETKIT_MODE_L2 || peerNetkit.IsPrimary() {
		t.Fatalf("peer mode = %d, primary = %v", peerNetkit.Mode, peerNetkit.IsPrimary())
	}
	if peerNetkit.Policy != netlink.NETKIT_POLICY_FORWARD || peerNetkit.PeerPolicy != netlink.NETKIT_POLICY_FORWARD {
		t.Fatalf("peer policies = (%d, %d), want forward", peerNetkit.Policy, peerNetkit.PeerPolicy)
	}
	if !peerNetkit.SupportsScrub() || peerNetkit.Scrub != netlink.NETKIT_SCRUB_DEFAULT || peerNetkit.PeerScrub != netlink.NETKIT_SCRUB_DEFAULT {
		t.Fatalf("peer scrub = (%d, %d), supported = %v", peerNetkit.Scrub, peerNetkit.PeerScrub, peerNetkit.SupportsScrub())
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	if err := netns.Set(hostNs); err != nil {
		t.Fatal(err)
	}

	skLookupProg := newTestProgram(t, ebpf.SkLookup, ebpf.AttachSkLookup, 1)
	skLookupLink, err := link.AttachNetNs(int(peerNs), skLookupProg)
	if err != nil {
		t.Fatalf("attach SK_LOOKUP to peer netns: %v", err)
	}
	t.Cleanup(func() { _ = skLookupLink.Close() })

	primaryProg := newTestProgram(t, ebpf.SchedCLS, ebpf.AttachNetkitPrimary, 0)
	primaryLink, err := link.AttachNetkit(link.NetkitOptions{
		Interface: primary.Attrs().Index,
		Program:   primaryProg,
		Attach:    ebpf.AttachNetkitPrimary,
	})
	if err != nil {
		t.Fatalf("attach Netkit primary to %s: %v", primary.Attrs().Name, err)
	}
	t.Cleanup(func() { _ = primaryLink.Close() })

	peerProg := newTestProgram(t, ebpf.SchedCLS, ebpf.AttachNetkitPeer, 0)
	peerLink, err := link.AttachNetkit(link.NetkitOptions{
		Interface: primary.Attrs().Index,
		Program:   peerProg,
		Attach:    ebpf.AttachNetkitPeer,
	})
	if err != nil {
		t.Fatalf("attach Netkit peer through %s: %v", primary.Attrs().Name, err)
	}
	t.Cleanup(func() { _ = peerLink.Close() })
}

func TestInternalNetkitProgramSpecs(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		programType ebpf.ProgramType
		attachType  ebpf.AttachType
	}{
		{"tproxy_dae0peer_ingress", ebpf.SchedCLS, ebpf.AttachNetkitPrimary},
		{"tproxy_dae0_ingress", ebpf.SchedCLS, ebpf.AttachNetkitPeer},
		{"tproxy_sk_lookup", ebpf.SkLookup, ebpf.AttachSkLookup},
	}
	for _, test := range tests {
		program := spec.Programs[test.name]
		if program == nil {
			t.Fatalf("program %s not found", test.name)
		}
		if program.Type != test.programType || program.AttachType != test.attachType {
			t.Errorf("program %s type/attach = %v/%v, want %v/%v", test.name, program.Type, program.AttachType, test.programType, test.attachType)
		}
	}
}

func newTestProgram(t *testing.T, programType ebpf.ProgramType, attachType ebpf.AttachType, ret int32) *ebpf.Program {
	t.Helper()
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       programType,
		AttachType: attachType,
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, ret),
			asm.Return(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = program.Close() })
	return program
}
