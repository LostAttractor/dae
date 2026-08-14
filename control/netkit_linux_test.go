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
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func requireNetkitIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("DAE_NETKIT_TEST") != "1" {
		t.Skip("set DAE_NETKIT_TEST=1 to enable")
	}
	if os.Geteuid() != 0 {
		t.Skip("root is required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
}

func assertNetkit(t *testing.T, link netlink.Link, wantPrimary bool) {
	t.Helper()
	netkit, ok := link.(*netlink.Netkit)
	if !ok {
		t.Fatalf("link type = %T, want *netlink.Netkit", link)
	}
	if netkit.Mode != netlink.NETKIT_MODE_L2 || netkit.IsPrimary() != wantPrimary {
		t.Fatalf("netkit mode = %d, primary = %v; want mode = %d, primary = %v", netkit.Mode, netkit.IsPrimary(), netlink.NETKIT_MODE_L2, wantPrimary)
	}
	if netkit.Policy != netlink.NETKIT_POLICY_FORWARD || netkit.PeerPolicy != netlink.NETKIT_POLICY_FORWARD {
		t.Fatalf("netkit policies = (%d, %d), want forward", netkit.Policy, netkit.PeerPolicy)
	}
	if !netkit.SupportsScrub() || netkit.Scrub != netlink.NETKIT_SCRUB_DEFAULT || netkit.PeerScrub != netlink.NETKIT_SCRUB_DEFAULT {
		t.Fatalf("netkit scrub = (%d, %d), supported = %v", netkit.Scrub, netkit.PeerScrub, netkit.SupportsScrub())
	}
}

func TestCreateNetkitPairIntegration(t *testing.T) {
	requireNetkitIntegration(t)

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
	assertNetkit(t, primary, true)
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
	assertNetkit(t, peer, false)

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

func TestNetkitAndTCXProgramSpecs(t *testing.T) {
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
		{"lan_ingress_l2", ebpf.SchedCLS, ebpf.AttachNone},
		{"lan_ingress_l3", ebpf.SchedCLS, ebpf.AttachNone},
		{"tproxy_wan_ingress_l2", ebpf.SchedCLS, ebpf.AttachNone},
		{"tproxy_wan_ingress_l3", ebpf.SchedCLS, ebpf.AttachNone},
		{"lan_egress_l2", ebpf.SchedCLS, ebpf.AttachNone},
		{"lan_egress_l3", ebpf.SchedCLS, ebpf.AttachNone},
		{"tproxy_wan_egress_l2", ebpf.SchedCLS, ebpf.AttachNone},
		{"tproxy_wan_egress_l3", ebpf.SchedCLS, ebpf.AttachNone},
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

func TestHostTCXAttachOrderAndCleanup(t *testing.T) {
	requireNetkitIntegration(t)

	name := fmt.Sprintf("dtx%d", os.Getpid())
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(dummy) })
	linkIndex := dummy.Attrs().Index
	lanIngress := newTestProgram(t, ebpf.SchedCLS, ebpf.AttachTCXIngress, -1)
	wanIngress := newTestProgram(t, ebpf.SchedCLS, ebpf.AttachTCXIngress, -1)
	lanEgress := newTestProgram(t, ebpf.SchedCLS, ebpf.AttachTCXEgress, -1)
	wanEgress := newTestProgram(t, ebpf.SchedCLS, ebpf.AttachTCXEgress, -1)
	foreignIngress := newTestProgram(t, ebpf.SchedCLS, ebpf.AttachTCXIngress, -1)
	foreignEgress := newTestProgram(t, ebpf.SchedCLS, ebpf.AttachTCXEgress, -1)
	foreignIngressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: linkIndex,
		Program:   foreignIngress,
		Attach:    ebpf.AttachTCXIngress,
		Anchor:    link.Tail(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = foreignIngressLink.Close() })
	foreignEgressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: linkIndex,
		Program:   foreignEgress,
		Attach:    ebpf.AttachTCXEgress,
		Anchor:    link.Tail(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = foreignEgressLink.Close() })
	core := &controlPlaneCore{}
	t.Cleanup(func() { _ = core.closeHostTCXLinks(linkIndex) })

	if err := core.migrateHostTCXPrograms(dummy,
		hostTCXProgram{role: hostTCXLanIngress, program: lanIngress},
		hostTCXProgram{role: hostTCXLanEgress, program: lanEgress},
	); err != nil {
		t.Fatal(err)
	}
	if err := core.migrateHostTCXPrograms(dummy,
		hostTCXProgram{role: hostTCXWanEgress, program: wanEgress},
		hostTCXProgram{role: hostTCXWanIngress, program: wanIngress},
	); err != nil {
		t.Fatal(err)
	}
	// Overlapping interface patterns must not stack duplicate role programs.
	if err := core.migrateHostTCXPrograms(dummy,
		hostTCXProgram{role: hostTCXLanIngress, program: lanIngress},
		hostTCXProgram{role: hostTCXWanIngress, program: wanIngress},
	); err != nil {
		t.Fatal(err)
	}

	assertTCXOrder(t, linkIndex, ebpf.AttachTCXIngress, foreignIngress, wanIngress, lanIngress)
	assertTCXOrder(t, linkIndex, ebpf.AttachTCXEgress, foreignEgress, lanEgress, wanEgress)
	assertNoClsact(t, dummy)

	if err := core.closeHostTCXLinks(linkIndex); err != nil {
		t.Fatal(err)
	}
	assertTCXOrder(t, linkIndex, ebpf.AttachTCXIngress, foreignIngress)
	assertTCXOrder(t, linkIndex, ebpf.AttachTCXEgress, foreignEgress)
	assertNoClsact(t, dummy)
}

func TestCleanupLegacyTCFiltersIntegration(t *testing.T) {
	requireNetkitIntegration(t)

	name := fmt.Sprintf("dtl%d", os.Getpid())
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(dummy) })
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: dummy.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}

	program := newTestProgram(t, ebpf.SchedCLS, ebpf.AttachNone, 0)
	newFilter := func(minor uint16, name string) *netlink.BpfFilter {
		return &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: dummy.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_EGRESS,
				Handle:    netlink.MakeHandle(0x2023, minor),
				Priority:  1,
				Protocol:  unix.ETH_P_ALL,
			},
			Fd:           program.FD(),
			Name:         name,
			DirectAction: true,
		}
	}
	legacy := newFilter(1, consts.AppName+"_wan_egress")
	foreign := newFilter(2, "foreign_wan_egress")
	if err := netlink.FilterAdd(legacy); err != nil {
		t.Fatal(err)
	}
	if err := netlink.FilterAdd(foreign); err != nil {
		t.Fatal(err)
	}
	if err := cleanupLegacyTCFiltersOnLink(dummy); err != nil {
		t.Fatal(err)
	}

	filters, err := netlink.FilterList(dummy, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		t.Fatal(err)
	}
	var legacyFound, foreignFound bool
	for _, filter := range filters {
		bpfFilter, ok := filter.(*netlink.BpfFilter)
		if !ok {
			continue
		}
		legacyFound = legacyFound || bpfFilter.Name == legacy.Name
		foreignFound = foreignFound || bpfFilter.Name == foreign.Name
	}
	if legacyFound || !foreignFound {
		t.Fatalf("legacy filter found = %v, foreign filter found = %v", legacyFound, foreignFound)
	}
}

func assertTCXOrder(t *testing.T, linkIndex int, attachType ebpf.AttachType, programs ...*ebpf.Program) {
	t.Helper()
	result, err := link.QueryPrograms(link.QueryOptions{Target: linkIndex, Attach: attachType})
	if err != nil {
		t.Fatal(err)
	}
	want := make([]ebpf.ProgramID, 0, len(programs))
	for _, program := range programs {
		info, err := program.Info()
		if err != nil {
			t.Fatal(err)
		}
		id, ok := info.ID()
		if !ok {
			t.Fatal("kernel did not return a BPF program ID")
		}
		want = append(want, id)
	}
	got := make([]ebpf.ProgramID, 0, len(result.Programs))
	for _, program := range result.Programs {
		got = append(got, program.ID)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("TCX program order = %v, want %v", got, want)
	}
}

func assertNoClsact(t *testing.T, device netlink.Link) {
	t.Helper()
	qdiscs, err := netlink.QdiscList(device)
	if err != nil {
		t.Fatal(err)
	}
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "clsact" {
			t.Fatal("TCX attachment created a clsact qdisc")
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
