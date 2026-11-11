// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/internal/routingabi"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestReplacementRetainsSocketIdentityHooksKernel(t *testing.T) {
	for _, mode := range []string{"clean", "cleanup-error"} {
		t.Run(mode, func(t *testing.T) {
			testReplacementIdentityHooks(t, mode == "cleanup-error")
		})
	}
}

func testReplacementIdentityHooks(t *testing.T, cleanupFailure bool) {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("DAE_TEST_ISOLATED") != "1" {
		t.Skip("requires root in isolated PID, network and mount namespaces")
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	load := func() *bpfObjects {
		t.Helper()
		spec, err := loadBpf()
		must(err)
		for _, m := range spec.Maps {
			m.Pinning = ebpf.PinNone
		}
		objects := new(bpfObjects)
		must(spec.LoadAndAssign(objects, nil))
		t.Cleanup(func() { _ = objects.Close() })
		return objects
	}
	old, next := load(), load()
	host := &netlink.Dummy{Name: "identity-host"}
	peer := &netlink.Dummy{Name: "identity-peer"}
	for _, device := range []*netlink.Dummy{host, peer} {
		must(netlink.LinkAdd(device))
		t.Cleanup(func() { _ = netlink.LinkDel(device) })
	}
	namespace, err := netns.Get()
	must(err)
	defer namespace.Close()
	ns := &DaeNetns{dae0: host, dae0peer: peer, hostNs: namespace, daeNs: namespace}
	ns.setupDone.Store(true)
	predecessor := NewRuntime()
	defer predecessor.Close()
	must(predecessor.retainMaps(old))
	predecessor.kernelLinks.privatePins = true
	must(predecessor.kernelLinks.preparePins(kernelPinPath()))
	must(predecessor.pinUDPTimers())
	oldTimerDirectories := runtimeTimerDirectories(t)
	predecessor.kernelLinks.netnsLinks, err = ns.attachPrograms(old.bpfPrograms)
	must(err)
	core := &controlPlaneCore{kernelLinks: &predecessor.kernelLinks, bpf: &BPFState{bpfObjects: old}}
	must(core.setupSkPidMonitor())
	must(core.setupExitHandler())
	exit, err := predecessor.kernelLinks.exitLink.Info()
	must(err)
	for _, role := range []hostTCXRole{hostTCXWanIngress, hostTCXWanEgress} {
		l, err := link.AttachTCX(link.TCXOptions{Interface: host.Index, Attach: role.attachType(), Program: role.program(&old.bpfPrograms, true)})
		must(err)
		predecessor.kernelLinks.hostTCXLinks = append(predecessor.kernelLinks.hostTCXLinks, hostTCXLink{linkIndex: host.Index, role: role, link: l, close: l.Close})
	}
	must(predecessor.publishReplacementPins())
	predecessor.kernelLinks.privatePins = false
	discardedSnapshot, err := predecessor.ExportReplacement(t.Context())
	must(err)
	unclaimedFiles := slices.Clone(discardedSnapshot.Files)
	borrowedLinks := slices.Clone(discardedSnapshot.links)
	state := predecessor.shared["exited_map"]
	predecessor.shared["exited_map"] = nil
	err = discardedSnapshot.Block(t.Context())
	predecessor.shared["exited_map"] = state
	if err == nil {
		t.Fatal("Block succeeded without ingress state")
	}
	discardedSnapshot.Release()
	for _, file := range unclaimedFiles {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("discarded snapshot kept an unclaimed FD: %v", err)
		}
	}
	for _, l := range borrowedLinks {
		if _, err := l.Info(); err != nil {
			t.Fatalf("Release closed a borrowed Runtime link: %v", err)
		}
	}
	snapshot, err := predecessor.ExportReplacement(t.Context())
	must(err)
	defer snapshot.Release()
	if snapshot.links[0] != predecessor.kernelLinks.hostTCXLinks[0].link {
		t.Fatal("snapshot did not borrow the Runtime link")
	}
	if len(snapshot.Links) != 2+netnsRoleCount+len(socketIdentityAttachTypes) || len(snapshot.Files) != len(snapshot.Links) {
		t.Fatalf("incomplete exported hooks: descriptors=%d files=%d", len(snapshot.Links), len(snapshot.Files))
	}
	for _, descriptor := range snapshot.Links {
		if descriptor.ID == uint32(exit.ID) {
			t.Fatal("exported the old process exit hook")
		}
	}
	must(snapshot.Block(t.Context()))
	if len(snapshot.links) != 0 {
		t.Fatal("blocked snapshot retained borrowed links")
	}
	files := snapshot.TakeFiles()
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	if snapshot.Files != nil || snapshot.TakeFiles() != nil {
		t.Fatal("TakeFiles retained ownership of exported FDs")
	}
	snapshot.Release()
	must(predecessor.Close())
	oldExit, err := link.NewFromID(exit.ID)
	must(err)
	must(oldExit.Close())
	must(old.DaemonIdentityMap.Update(uint32(0), uint64(0), ebpf.UpdateAny))
	must(RegisterDaemonIdentity())
	kernelPID, err := KernelProcessID()
	must(err)
	var registered uint64
	must(old.DaemonIdentityMap.Lookup(uint32(0), &registered))
	if registered != uint64(kernelPID) {
		t.Fatalf("old guard bootstrap identity = %d, want %d", registered, kernelPID)
	}
	for _, file := range files {
		if _, err := file.Stat(); err != nil {
			t.Fatalf("transferred FD did not survive Release and Runtime.Close: %v", err)
		}
	}
	discarded := NewRuntime()
	badFiles := slices.Clone(files)
	badFiles[len(badFiles)-1], badFiles[len(badFiles)-2] = badFiles[len(badFiles)-2], badFiles[len(badFiles)-1]
	before, err := os.ReadDir("/proc/self/fd")
	must(err)
	if err := discarded.ImportReplacement(snapshot.Links, badFiles); err == nil {
		t.Fatal("import accepted swapped attachment FDs")
	}
	after, err := os.ReadDir("/proc/self/fd")
	must(err)
	if discarded.staged || len(discarded.identityHooks) != 0 || len(discarded.kernelLinks.netnsLinks) != 0 || len(before) != len(after) {
		t.Fatal("failed import retained attachments or leaked FDs")
	}
	must(discarded.ImportReplacement(snapshot.Links, files))
	if !discarded.staged || !discarded.kernelLinks.privatePins || !discarded.kernelLinks.preparing {
		t.Fatal("import did not isolate kernel pins and freeze the replacement topology")
	}
	hooks := slices.Clone(discarded.identityHooks)
	must(discarded.Close())
	for _, hook := range hooks {
		if _, err := hook.Info(); err == nil {
			t.Fatal("Runtime.Close leaked a temporary identity hook FD")
		}
	}
	successor := NewRuntime()
	defer successor.Close()
	must(successor.ImportReplacement(snapshot.Links, files))
	descriptors := slices.Clone(snapshot.Links)
	for _, file := range files {
		must(file.Close())
	}
	if len(successor.identityHooks) != 5 || len(successor.kernelLinks.pidLinks) != 0 || successor.kernelLinks.exitLink != nil {
		t.Fatal("old identity or exit hooks became new runtime attachments")
	}
	owner := func(m *ebpf.Map, fd int, exists bool) uint32 {
		t.Helper()
		var value struct {
			PID  uint32
			Name [16]byte
		}
		err := m.Lookup(uint32(fd), &value)
		if !exists {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("private socket storage unexpectedly populated: %v", err)
			}
			return 0
		}
		must(err)
		if value.PID == 0 {
			t.Fatal("socket has no process identity")
		}
		return value.PID
	}
	socket := func() int {
		t.Helper()
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
		must(err)
		t.Cleanup(func() { _ = unix.Close(fd) })
		return fd
	}
	fd := socket()
	pid := owner(old.SocketOwnerMap, fd, true)
	owner(next.SocketOwnerMap, fd, false)
	if kernelPID != pid {
		t.Fatalf("map-free identity probe returned %d, socket hook recorded %d", kernelPID, pid)
	}
	if pid != uint32(os.Getpid()) {
		t.Logf("socket owner uses kernel PID %d, namespace os.Getpid() is %d", pid, os.Getpid())
	}
	dir, now := t.TempDir(), time.Now()
	finalRegistry, _ := newTestRegistry(16, time.Hour)
	finalRegistry.Upsert("final.example.", netip.MustParseAddr("192.0.2.1"), testBitmap(), 3600, now)
	persistTestRegistry(t, finalRegistry, dir, now)
	must(finalRegistry.Close())
	plane, projection := newReplacementRegistryPlane(t, dir)
	plane.core.kernelLinks, plane.core.bpf = &successor.kernelLinks, &BPFState{Runtime: successor, bpfObjects: next}
	plane.routingMatcher.bpf = plane.core.bpf
	plane.routingState = plane.routingMatcher.routingState
	plane.settings, err = settings.Open(filepath.Join(dir, "runtime-state.json"))
	must(err)
	t.Cleanup(plane.core.bpf.clearRoutingRegistrations)
	plane.wanInterface = []string{host.Name}
	successor.current = plane
	must(successor.retainMaps(next))
	must(successor.kernelLinks.preparePins(kernelPinPath()))
	must(successor.pinUDPTimers())
	must(successor.StopIngress())
	must(plane.core.setupSkPidMonitor())
	must(plane.core.setupExitHandler())
	if len(successor.kernelLinks.pidLinks) != 5 || len(successor.identityHooks) != 5 {
		t.Fatal("temporary old hooks prevented new private identity hooks")
	}
	fd = socket()
	if owner(old.SocketOwnerMap, fd, true) != owner(next.SocketOwnerMap, fd, true) {
		t.Fatal("old and new hooks disagree on socket owner")
	}
	for i, d := range successor.replacementDescriptors {
		if d.Kind == "host" {
			successor.replacementLinks[i].next = hostTCXRole(d.Role).program(&next.bpfPrograms, true)
		} else {
			successor.replacementLinks[i].next = next.namespacePrograms()[d.Role]
		}
	}
	programs := make([]ebpf.ProgramID, len(successor.replacementLinks))
	for i, attachment := range successor.replacementLinks {
		info, err := attachment.link.Info()
		must(err)
		programs[i] = info.Program
	}
	projections := 0
	plane.core.domainRegistry.kernel.update = func(ip netip.Addr, bump, routing []uint32) error {
		projections++
		if len(successor.replacementLinks) != len(programs) {
			t.Fatal("registry restored after replacement installation")
		}
		for i, attachment := range successor.replacementLinks {
			info, err := attachment.link.Info()
			must(err)
			if info.ID != link.ID(successor.replacementDescriptors[i].ID) || info.Program != programs[i] {
				t.Fatal("registry restored after an attachment changed")
			}
		}
		return projection.update(ip, bump, routing)
	}
	must(plane.PrepareKernel())
	must(plane.PrepareKernel())
	if projections != 1 || plane.core.domainRegistry.persist == nil || plane.core.domainRegistry.persist.enabled {
		t.Fatal("kernel preparation did not restore exactly once without enabling persistence")
	}
	requireDiskEvidence(t, diskEvidence(plane.core.domainRegistry), diskEvidence(finalRegistry))
	commitCtx, cancelCommit := context.WithCancelCause(t.Context())
	commitCause := errors.New("replacement deadline expired")
	cancelCommit(commitCause)
	if err := successor.CommitReplacement(commitCtx); !errors.Is(err, commitCause) {
		t.Fatalf("hostless commit ignored its canceled context: %v", err)
	}
	var status uint8
	must(successor.shared["exited_map"].Lookup(uint32(0), &status))
	if status != uint8(routingabi.DAEMON_STOPPING) || !successor.staged || len(successor.identityHooks) != 5 {
		t.Fatal("canceled commit released staging or the stopping barrier")
	}
	for _, d := range descriptors {
		if d.Kind != "host" || !hostTCXRole(d.Role).interceptsTraffic() {
			continue
		}
		guard, err := link.NewFromID(link.ID(d.ID))
		must(err)
		must(guard.Close())
	}
	must(netlink.LinkSetName(host, "identity-moved"))
	if err := successor.CommitReplacement(t.Context()); err == nil {
		t.Fatal("commit ignored interception interface changes before installation")
	}
	if len(successor.identityHooks) != 5 {
		t.Fatal("changed topology retired old socket identity hooks")
	}
	if directories := runtimeTimerDirectories(t); len(directories) != 2 {
		t.Fatalf("failed commit did not preserve both generations' timer pins: %v", directories)
	}
	must(netlink.LinkSetName(host, host.Name))
	must(InitSysctlManager())
	must(successor.CommitReplacement(t.Context()))
	if projections != 1 {
		t.Fatal("commit restored the registry again")
	}
	if !successor.kernelLinks.privatePins {
		t.Fatal("commit claimed canonical pins before READY")
	}
	if directories := runtimeTimerDirectories(t); len(directories) != 1 || slices.Contains(oldTimerDirectories, directories[0]) {
		t.Fatalf("successful commit did not retire only the old timer pins: %v", directories)
	}
	if cleanupFailure {
		for _, owned := range successor.kernelLinks.hostTCXLinks {
			if owned.role.interceptsTraffic() {
				info, err := owned.link.Info()
				must(err)
				// bpffs directories can make obsolete bundle removal fail after unpinning.
				must(os.MkdirAll(filepath.Join(replacementGuardDirectory(info.ID), "busy", "child"), 0700))
				break
			}
		}
	}
	must(successor.ConfirmReady(func() error { return nil }))
	must(successor.shared["exited_map"].Lookup(uint32(0), &status))
	if status != uint8(routingabi.DAEMON_ONLINE) || successor.kernelLinks.privatePins || successor.kernelLinks.preparing {
		t.Fatal("post-commit cleanup changed online state or prevented ownership transfer")
	}
	if len(successor.identityHooks) != 0 || len(successor.kernelLinks.pidLinks) != 5 {
		t.Fatal("commit kept old hooks or closed new identity hooks")
	}
	for _, d := range descriptors {
		if d.Kind == "netns" {
			continue
		}
		l, err := link.NewFromID(link.ID(d.ID))
		if err == nil {
			_ = l.Close()
			t.Fatalf("old %s attachment %d still alive after commit", d.Kind, d.ID)
		}
	}
	fd = socket()
	owner(old.SocketOwnerMap, fd, false)
	owner(next.SocketOwnerMap, fd, true)
	if oldExit, err := link.NewFromID(exit.ID); err == nil {
		oldExit.Close()
		t.Fatal("old identity exit hook survived guard retirement")
	}
	must(successor.Close())
	if _, err := os.Stat(kernelPinPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("claimed replacement did not clean canonical pins: %v", err)
	}
}

func TestFailedRecoveryDoesNotExpandGuardsKernel(t *testing.T) {
	if os.Getenv("DAE_TEST_ISOLATED") != "1" {
		t.Skip("requires isolated network/mount namespaces and BPF privileges")
	}
	var devices []*netlink.Dummy
	for _, name := range []string{"guard0", "guard1", "guard2"} {
		device := &netlink.Dummy{Name: name}
		if err := netlink.LinkAdd(device); err != nil {
			t.Fatal(err)
		}
		defer netlink.LinkDel(device)
		devices = append(devices, device)
	}
	attach := func(device *netlink.Dummy) link.Link {
		t.Helper()
		program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SchedCLS, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}})
		if err != nil {
			t.Fatal(err)
		}
		defer program.Close()
		l, err := link.AttachTCX(link.TCXOptions{Interface: device.Index, Attach: ebpf.AttachTCXIngress, Program: program})
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	for _, device := range devices[:2] {
		l := attach(device)
		if _, err := pinReplacementGuard(l, hostTCXLanIngress); err != nil {
			t.Fatal(err)
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
	}
	newRecovery := func(indices ...int) *Runtime {
		t.Helper()
		r := NewRuntime()
		t.Cleanup(func() { r.Close() })
		state, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 1, MaxEntries: 1})
		if err != nil {
			t.Fatal(err)
		}
		r.shared["exited_map"] = state
		for _, i := range indices {
			l := attach(devices[i])
			r.kernelLinks.hostTCXLinks = append(r.kernelLinks.hostTCXLinks, hostTCXLink{linkIndex: devices[i].Index, role: hostTCXLanIngress, link: l, close: l.Close})
		}
		return r
	}
	failed := newRecovery(0, 2)
	if err := failed.finishReplacementGuards(); err == nil {
		t.Fatal("missing original hook should reject recovery")
	}
	if err := failed.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(replacementGuardPath())
	if err != nil || len(entries) != 2 {
		t.Fatalf("failed attempt changed persistent guards: %v, %v", entries, err)
	}
	restored := newRecovery(0, 1)
	if err := restored.finishReplacementGuards(); err != nil {
		t.Fatalf("original interfaces cannot recover after failed attempt: %v", err)
	}
}

func TestReplacementGuardsKernel(t *testing.T) {
	if os.Getenv("DAE_TEST_ISOLATED") != "1" {
		t.Skip("requires isolated network/mount namespaces and BPF privileges")
	}
	program := func(kind ebpf.ProgramType, size uint32) *ebpf.Program {
		t.Helper()
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: size, MaxEntries: 1})
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close()
		p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: kind, License: "GPL", Instructions: asm.Instructions{asm.LoadMapPtr(asm.R1, m.FD()), asm.Mov.Imm(asm.R0, 2), asm.Return()}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.Close() })
		return p
	}
	device := &netlink.Dummy{Name: "replace-test"}
	if err := netlink.LinkAdd(device); err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(device)
	old, next, incompatible := program(ebpf.SchedCLS, 4), program(ebpf.SchedCLS, 16), program(ebpf.XDP, 8)
	state, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 1, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	r := NewRuntime()
	r.shared["exited_map"] = state
	r.kernelLinks.frozen = true
	s := &ReplacementSnapshot{runtime: r, frozen: true}
	defer s.Release()
	successor := NewRuntime()
	defer successor.Close()
	successor.staged, successor.kernelLinks.privatePins, successor.kernelLinks.preparing = true, true, true
	successor.current = &ControlPlane{core: &controlPlaneCore{closed: t.Context()}, lanInterface: []string{device.Name}, wanInterface: []string{device.Name}}
	for _, role := range []hostTCXRole{hostTCXLanIngress, hostTCXLanEgress, hostTCXWanIngress, hostTCXWanEgress} {
		previous := old
		if role >= hostTCXWanIngress {
			previous = program(ebpf.SchedCLS, 4)
		}
		l, err := link.AttachTCX(link.TCXOptions{Interface: device.Index, Attach: role.attachType(), Program: previous})
		if err != nil {
			t.Fatal(err)
		}
		info, err := l.Info()
		if err != nil {
			t.Fatal(err)
		}
		d := ReplacementLink{Kind: "host", Ifindex: device.Index, Ethernet: true, Role: uint8(role), ID: uint32(info.ID)}
		s.Links = append(s.Links, d)
		s.links = append(s.links, l)
		successor.replacementDescriptors = append(successor.replacementDescriptors, d)
		successor.replacementLinks = append(successor.replacementLinks, replacementAttachment{link: l, next: next})
		successor.kernelLinks.hostTCXLinks = append(successor.kernelLinks.hostTCXLinks, hostTCXLink{linkIndex: device.Index, role: role, link: l, program: next, close: l.Close})
	}
	if err := s.Block(t.Context()); err != nil {
		t.Fatal(err)
	}
	var value uint8
	if err := state.Lookup(uint32(0), &value); err != nil || value != routingabi.DAEMON_STOPPING {
		t.Fatalf("state=%d: %v", value, err)
	}
	successor.replacementLinks[1].next = incompatible
	if err := activateReplacementForTest(successor); err == nil {
		t.Fatal("incompatible program passed activation")
	}
	successor.replacementLinks[1].next = next
	// A detached reply anchor fails only after installing the first host link.
	if err := successor.replacementLinks[1].link.Detach(); err != nil {
		t.Fatal(err)
	}
	if err := activateReplacementForTest(successor); err == nil {
		t.Fatal("detached attachment succeeded")
	}
	if len(successor.replacementLinks) != 4 || len(successor.kernelLinks.hostTCXLinks) != 4 {
		t.Fatal("failed installation lost pending attachments or ownership")
	}
	if err := successor.CommitReplacement(t.Context()); err == nil {
		t.Fatal("partially installed replacement committed")
	}
	if err := successor.Close(); err != nil {
		t.Fatal(err)
	}
	s.Release()
	entries, err := os.ReadDir(replacementGuardPath())
	if err != nil || len(entries) != 3 {
		t.Fatalf("guards lost after closing all process FDs: %v, %v", entries, err)
	}
	// A normal restart must cover every old hook before removing any guard.
	recovered := program(ebpf.SchedCLS, 32)
	recovery := NewRuntime()
	recovery.shared["exited_map"] = state
	for _, role := range []hostTCXRole{hostTCXLanIngress, hostTCXWanEgress} {
		if role == hostTCXWanEgress {
			if err := recovery.finishReplacementGuards(); err == nil {
				t.Fatal("removed uncovered guard")
			}
		}
		l, err := link.AttachTCX(link.TCXOptions{Interface: device.Index, Attach: role.attachType(), Program: recovered})
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		recovery.kernelLinks.hostTCXLinks = append(recovery.kernelLinks.hostTCXLinks, hostTCXLink{linkIndex: device.Index, role: role, link: l, program: recovered, close: l.Close})
	}
	// The same hooks used only for replies do not protect captured traffic.
	recovery.kernelLinks.hostTCXLinks[0].role = hostTCXWanIngress
	recovery.kernelLinks.hostTCXLinks[1].role = hostTCXLanEgress
	if err := recovery.finishReplacementGuards(); err == nil {
		t.Fatal("reply-only programs replaced interception guards")
	}
	recovery.kernelLinks.hostTCXLinks[0].role = hostTCXLanIngress
	recovery.kernelLinks.hostTCXLinks[1].role = hostTCXWanEgress
	if err := recovery.finishReplacementGuards(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(replacementGuardPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("guards remain: %v", err)
	}
	if err := state.Lookup(uint32(0), &value); err != nil || value != routingabi.DAEMON_ONLINE {
		t.Fatalf("recovered state=%d: %v", value, err)
	}
}
