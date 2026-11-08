// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/internal/routingabi"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestHostTCXPinNames(t *testing.T) {
	for _, role := range []hostTCXRole{hostTCXLanIngress, hostTCXLanEgress, hostTCXWanIngress, hostTCXWanEgress} {
		index, actual, ok := parseHostTCXPinName(hostTCXPinName(27, role))
		if !ok || index != 27 || actual != role {
			t.Fatalf("pin name lost attachment identity: %d %d %v", index, actual, ok)
		}
	}
	for _, name := range []string{"", "tcx_0_0", "tcx_-1_0", "tcx_1_4", "tcx_1_256", "tcx_1_0_extra", "pid_1", "tcx_x_1"} {
		if _, _, ok := parseHostTCXPinName(name); ok {
			t.Fatalf("accepted invalid TCX pin %q", name)
		}
	}
}

func TestDaeLinkPinNames(t *testing.T) {
	for _, name := range []string{
		"exit", "exit_next", hostTCXPinName(27, hostTCXWanEgress),
		fmt.Sprintf("pid_%d", ebpf.AttachCGroupInetSockCreate),
		fmt.Sprintf("pid_%d", ebpf.AttachCGroupInet4Connect),
		fmt.Sprintf("pid_%d", ebpf.AttachCGroupInet6Connect),
		fmt.Sprintf("pid_%d", ebpf.AttachCGroupUDP4Sendmsg),
		fmt.Sprintf("pid_%d", ebpf.AttachCGroupUDP6Sendmsg),
	} {
		if !daeLinkPinName(name) {
			t.Fatalf("did not recognize dae link pin %q", name)
		}
	}
	for _, name := range []string{"user_link", "pid_9999", "pid_01", "tcx_01_0", "exit_backup"} {
		if daeLinkPinName(name) {
			t.Fatalf("accepted unknown link pin %q", name)
		}
	}
}

func TestRuntimeOfflineIsTerminal(t *testing.T) {
	r := NewRuntime()
	defer r.Close()
	for range 2 {
		if err := r.GoOffline(); err != nil {
			t.Fatal(err)
		}
		for _, abort := range []bool{false, true} {
			if err := r.Publish(nil, abort); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("offline runtime accepted publication: %v", err)
			}
		}
	}
}

func TestRuntimeCloseKeepsTimerPinsIfLinkReleaseFails(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "runtime_fixture", "udp_conn_state_map")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("could not release host link")
	r := NewRuntime()
	r.kernelLinks.pinPath = filepath.Join(root, "links")
	r.kernelLinks.ownHostTCXLink(hostTCXLink{linkIndex: 1, close: func() error { return failure }})
	if err := r.Close(); err == nil || err.Error() != failure.Error() {
		t.Fatalf("failed link release attempted timer pruning: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("failed link release removed timer ownership: %v", err)
	}
}

func TestPersistentDeviceRouteMapShape(t *testing.T) {
	spec, err := loadBPFSpec()
	if err != nil {
		t.Fatal(err)
	}
	outer := spec.Maps["device_routes_map"]
	if outer == nil || outer.Type != ebpf.ArrayOfMaps || outer.KeySize != 4 || outer.MaxEntries != 1 || outer.InnerMap == nil {
		t.Fatalf("persistent device route map changed: %+v", outer)
	}
	inner := outer.InnerMap
	if inner.Type != ebpf.Hash || inner.KeySize != 6 || inner.ValueSize != 16 || inner.MaxEntries != 65536 {
		t.Fatalf("persistent device route epoch table changed: %+v", inner)
	}
	var state bpfDeviceRouteState
	if unsafe.Sizeof(state) != 16 || unsafe.Offsetof(state.Epoch) != 0 || unsafe.Offsetof(state.Updating) != 8 {
		t.Fatal("persistent device route state layout changed")
	}
}

// Re-exec puts every Go thread, netns name, pin and runtime path in disposable
// namespaces before production setup can delete or replace any dae resource.
func TestPersistentKernelLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for isolated BPF persistence tests")
	}
	if os.Getenv("DAE_PERSISTENCE_ISOLATED") == "" {
		child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestPersistentKernelLifecycle$", "-test.v")
		child.Env = append(os.Environ(), "DAE_PERSISTENCE_ISOLATED=1")
		for _, kind := range []string{"net", "mnt"} {
			original, err := os.Readlink("/proc/self/ns/" + kind)
			if err != nil {
				t.Fatal(err)
			}
			child.Env = append(child.Env, "DAE_PERSISTENCE_HOST_"+kind+"="+original)
		}
		child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET | unix.CLONE_NEWNS}
		output, err := child.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated lifecycle test: %v\n%s", err, output)
		}
		t.Logf("%s", output)
		return
	}
	requirePersistentNamespaces(t)
	for _, mount := range []struct {
		source, target, kind string
		flags                uintptr
	}{
		{"", "/", "", unix.MS_REC | unix.MS_PRIVATE},
		{"tmpfs", "/run", "tmpfs", 0},
		{"bpf", consts.BpfPinRoot, "bpf", 0},
	} {
		if err := unix.Mount(mount.source, mount.target, mount.kind, mount.flags, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll("/run/netns", 0755); err != nil {
		t.Fatal(err)
	}
	device, echo, resetConnection := persistentNativeTCP(t)
	pin := filepath.Join(kernelPinPath(), "links", hostTCXPinName(device.Attrs().Index, hostTCXWanEgress))
	readLink := func() *link.Info {
		t.Helper()
		attached, err := link.LoadPinnedLink(pin, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer attached.Close()
		info, err := attached.Info()
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
	readExited := func() *ebpf.Map {
		t.Helper()
		m, err := ebpf.LoadPinnedMap(filepath.Join(consts.BpfPinRoot, "test_exited"), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = m.Close() })
		return m
	}
	start := func(phase string) (*exec.Cmd, io.WriteCloser) {
		t.Helper()
		child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestPersistentKernelProcess$")
		child.Env = append(os.Environ(), "DAE_PERSISTENCE_PHASE="+phase)
		child.Stderr = os.Stderr
		stdout, err := child.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdin, err := child.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { stdin.Close(); _ = child.Process.Kill(); _ = child.Wait() })
		reader := bufio.NewScanner(stdout)
		for reader.Scan() {
			if reader.Text() == "ready" {
				return child, stdin
			}
			t.Log(reader.Text())
		}
		t.Fatalf("kernel fixture did not become ready: %v", reader.Err())
		return nil, nil
	}
	assertClean := func() {
		t.Helper()
		if _, err := os.Stat(kernelPinPath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("normal Close retained dae pins: %v", err)
		}
		for _, attach := range []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress} {
			programs, err := link.QueryPrograms(link.QueryOptions{Target: device.Attrs().Index, Attach: attach})
			if err != nil || len(programs.Programs) != 0 {
				t.Fatalf("normal Close retained host attachments: %+v, %v", programs, err)
			}
		}
		if _, err := netlink.LinkByName(hostLinkName); !onlyLinkDisappearanceErrors(err) {
			t.Fatalf("normal Close retained its internal link: %v", err)
		}
		if _, err := os.Stat("/run/netns/" + NsName); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("normal Close retained its named namespace: %v", err)
		}
		if _, err := netlink.LinkByName("pin-uplink"); err != nil {
			t.Fatalf("normal Close deleted an ordinary interface: %v", err)
		}
	}
	timerIDs := func() map[string]ebpf.MapID {
		t.Helper()
		directories := runtimeTimerDirectories(t)
		if len(directories) != 1 {
			t.Fatalf("runtime timer directories = %v, want exactly one", directories)
		}
		ids := make(map[string]ebpf.MapID)
		for _, name := range udpTimerMapNames {
			m, err := ebpf.LoadPinnedMap(filepath.Join(directories[0], name), nil)
			if err != nil {
				t.Fatal(err)
			}
			info, err := m.Info()
			m.Close()
			if err != nil {
				t.Fatal(err)
			}
			ids[name], _ = info.ID()
		}
		return ids
	}
	assertOldUDPCache := func(expected bool) {
		t.Helper()
		directories := runtimeTimerDirectories(t)
		if len(directories) != 1 {
			t.Fatalf("runtime timer directories = %v, want exactly one", directories)
		}
		m, err := ebpf.LoadPinnedMap(filepath.Join(directories[0], "udp_routing_cache_map"), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close()
		var value bpfUdpRoutingCacheValue
		err = m.Lookup(udpSourceKey(netip.MustParseAddrPort("198.18.0.1:46001")), &value)
		if expected && err != nil || !expected && !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("old runtime UDP cache present=%v: %v", expected, err)
		}
	}

	normal, input := start("first")
	echo("online before normal stop")
	input.Close()
	if err := normal.Wait(); err != nil {
		t.Fatal(err)
	}
	assertClean()
	resetConnection()

	crashed, input := start("first")
	originalTimers := timerIDs()
	initial, oldExited := readLink(), readExited()
	identity, err := ebpf.LoadPinnedMap(filepath.Join(kernelPinPath(), "daemon_identity_map"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	echo("online before abnormal exit")
	assertOldUDPCache(true)
	if err := crashed.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = crashed.Wait()
	input.Close()
	waitExited(t, oldExited, routingabi.DAEMON_OFFLINE)
	var registered uint64
	if err := identity.Lookup(uint32(0), &registered); err != nil || registered != 0 {
		t.Fatalf("abnormal exit retained daemon identity: %d, %v", registered, err)
	}
	echo("after SIGKILL")
	if actual := readLink(); actual.ID != initial.ID || actual.Program != initial.Program {
		t.Fatal("abnormal exit lost its host classifier")
	}

	failed, input := start("unpublished")
	input.Close()
	if err := failed.Wait(); err != nil {
		t.Fatal(err)
	}
	if actual := readLink(); actual.ID != initial.ID || actual.Program != initial.Program {
		t.Fatal("a restart that never went online removed the crash fallback")
	}
	waitExited(t, oldExited, routingabi.DAEMON_OFFLINE)
	echo("after a restart that never went online")

	replacement, input := start("restart")
	for name, id := range timerIDs() {
		if id == originalTimers[name] {
			t.Fatalf("cold startup reused UDP runtime map %s", name)
		}
	}
	assertOldUDPCache(false)
	updated, currentExited := readLink(), readExited()
	if updated.ID != initial.ID || updated.Program == initial.Program {
		t.Fatalf("restart stacked or failed to update the inherited link: before=%+v after=%+v", initial, updated)
	}
	waitExited(t, currentExited, routingabi.DAEMON_ONLINE)
	waitExited(t, oldExited, routingabi.DAEMON_OFFLINE)
	echo("after cold takeover")
	input.Close()
	if err := replacement.Wait(); err != nil {
		t.Fatal(err)
	}
	assertClean()
	resetConnection()

	for attempt := range 2 {
		unpublished, input := start("unpublished")
		if directories := runtimeTimerDirectories(t); len(directories) != 1 {
			t.Fatalf("unpublished runtime accumulated orphaned timer pins: %v", directories)
		}
		if attempt == 0 {
			if err := unpublished.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = unpublished.Wait()
			input.Close()
			continue
		}
		input.Close()
		if err := unpublished.Wait(); err != nil {
			t.Fatal(err)
		}
		assertClean()
	}
	assertTimerPruningPreservesUnknownFiles(t)
	assertClean()
	assertFailedMapCleanupPreservesSequence(t)
	assertPinnedLinkCleanupPreservesUnknown(t, device.Attrs().Index)
}

func assertPinnedLinkCleanupPreservesUnknown(t *testing.T, ifindex int) {
	t.Helper()
	root, err := os.MkdirTemp(consts.BpfPinRoot, "link_cleanup_")
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "links")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	pinTCX := func(name string) {
		t.Helper()
		program := newTestProgram(t, ebpf.SchedCLS, ebpf.AttachTCXIngress, -1)
		attached, err := link.AttachTCX(link.TCXOptions{Interface: ifindex, Program: program, Attach: ebpf.AttachTCXIngress})
		if err != nil {
			t.Fatal(err)
		}
		defer attached.Close()
		if err := attached.Pin(filepath.Join(directory, name)); err != nil {
			t.Fatal(err)
		}
	}
	known := hostTCXPinName(ifindex, hostTCXLanIngress)
	pinTCX(known)
	pinTCX("user_link")
	trace, err := link.Tracepoint("sched", "sched_process_exit", newTestProgram(t, ebpf.TracePoint, 0, 0), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := trace.Pin(filepath.Join(directory, "exit_next")); err != nil {
		t.Fatal(err)
	}
	trace.Close()
	nonLink, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer nonLink.Close()
	nonLinkName := fmt.Sprintf("pid_%d", ebpf.AttachCGroupInetSockCreate)
	if err := nonLink.Pin(filepath.Join(directory, nonLinkName)); err != nil {
		t.Fatal(err)
	}
	exitNonLink, err := nonLink.Clone()
	if err != nil {
		t.Fatal(err)
	}
	defer exitNonLink.Close()
	if err := exitNonLink.Pin(filepath.Join(directory, "exit")); err != nil {
		t.Fatal(err)
	}
	candidate, err := link.Tracepoint("sched", "sched_process_exit", newTestProgram(t, ebpf.TracePoint, 0, 0), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&kernelLinks{pinPath: directory}).pinExitLink(candidate); err == nil {
		t.Fatal("exit hook replacement overwrote a non-link pin")
	}
	candidate.Close()
	sequence, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer sequence.Close()
	sequencePath := filepath.Join(root, "fallback_sequence_map")
	if err := sequence.Update(uint32(0), uint64(99), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := sequence.Pin(sequencePath); err != nil {
		t.Fatal(err)
	}
	r := NewRuntime()
	r.kernelLinks.pinPath = directory
	if err := r.Close(); err == nil {
		t.Fatal("Close accepted unknown or non-link pins")
	}
	if _, err := os.Stat(filepath.Join(directory, known)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Close retained a recognized TCX pin: %v", err)
	}
	for _, name := range []string{"user_link", "exit_next"} {
		attached, err := link.LoadPinnedLink(filepath.Join(directory, name), nil)
		if err != nil {
			t.Fatalf("Close removed a protected link %s: %v", name, err)
		}
		attached.Close()
	}
	for _, path := range []string{filepath.Join(directory, nonLinkName), filepath.Join(directory, "exit"), sequencePath} {
		m, err := ebpf.LoadPinnedMap(path, nil)
		if err != nil {
			t.Fatalf("Close removed a protected map %s: %v", path, err)
		}
		m.Close()
	}
	if err := removePinnedLink(filepath.Join(directory, "user_link")); err != nil {
		t.Fatal(err)
	}
	if err := nonLink.Unpin(); err != nil {
		t.Fatal(err)
	}
	if err := exitNonLink.Unpin(); err != nil {
		t.Fatal(err)
	}
	r = NewRuntime()
	r.kernelLinks.pinPath = directory
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Close retained recognized pins after removing the obstruction: %v", err)
	}
}

func assertFailedMapCleanupPreservesSequence(t *testing.T) {
	t.Helper()
	root, err := os.MkdirTemp(consts.BpfPinRoot, "sequence_cleanup_")
	if err != nil {
		t.Fatal(err)
	}
	sequence, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer sequence.Close()
	if err := sequence.Update(uint32(0), uint64(71), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	sequencePath := filepath.Join(root, "fallback_sequence_map")
	if err := sequence.Pin(sequencePath); err != nil {
		t.Fatal(err)
	}
	flows, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer flows.Close()
	flowPath := filepath.Join(root, "tcp_flow_map")
	if err := flows.Pin(flowPath); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(flowPath, flowPath, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(flowPath, unix.MNT_DETACH)
	r := NewRuntime()
	r.kernelLinks.pinPath = filepath.Join(root, "links")
	if err := r.Close(); err == nil {
		t.Fatal("cleanup unexpectedly unpinned a mounted flow map")
	}
	pinned, err := ebpf.LoadPinnedMap(sequencePath, nil)
	if err != nil {
		t.Fatalf("failed flow cleanup removed the fallback sequence: %v", err)
	}
	var value uint64
	err = pinned.Lookup(uint32(0), &value)
	pinned.Close()
	if err != nil || value != 71 {
		t.Fatalf("failed flow cleanup reset the fallback sequence: %d, %v", value, err)
	}
	if err := unix.Unmount(flowPath, 0); err != nil {
		t.Fatal(err)
	}
	r = NewRuntime()
	r.kernelLinks.pinPath = filepath.Join(root, "links")
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful cleanup retained fallback sequence pins: %v", err)
	}
}

func runtimeTimerDirectories(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(kernelPinPath())
	if err != nil {
		t.Fatal(err)
	}
	var directories []string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "runtime_") {
			directories = append(directories, filepath.Join(kernelPinPath(), entry.Name()))
		}
	}
	return directories
}

func assertTimerPruningPreservesUnknownFiles(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(kernelPinPath(), 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(kernelPinPath(), "runtime_unknown_")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"udp_conn_state_map", "unknown"} {
		if err := os.Mkdir(filepath.Join(directory, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	r := NewRuntime()
	r.kernelLinks.pinPath = filepath.Join(kernelPinPath(), "links")
	defer r.Close()
	if err := r.pruneUDPTimerPins(false); err == nil {
		t.Fatal("timer pruning accepted a non-map pin")
	}
	for _, name := range []string{"udp_conn_state_map", "unknown"} {
		path := filepath.Join(directory, name)
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			t.Fatalf("timer pruning modified unknown resource %s: %v", path, err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(directory); err != nil {
		t.Fatal(err)
	}
}

func persistentNativeTCP(t *testing.T) (netlink.Link, func(string), func()) {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	runtime.LockOSThread()
	host, err := netns.Get()
	must(err)
	defer host.Close()
	defer func() { must(netns.Set(host)); runtime.UnlockOSThread() }()
	must(netlink.LinkAdd(&netlink.Veth{Name: "pin-uplink", PeerName: "pin-client", HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 7}}))
	uplink, err := netlink.LinkByName("pin-uplink")
	must(err)
	must(netlink.LinkSetUp(uplink))
	address, err := netlink.ParseAddr("198.18.0.1/24")
	must(err)
	must(netlink.AddrAdd(uplink, address))
	peerLink, err := netlink.LinkByName("pin-client")
	must(err)
	peer, err := netns.New()
	must(err)
	t.Cleanup(func() { _ = peer.Close() })
	must(netns.Set(host))
	must(netlink.LinkSetNsFd(peerLink, int(peer)))
	must(netns.Set(peer))
	peerLink, err = netlink.LinkByName("pin-client")
	must(err)
	must(netlink.LinkSetUp(peerLink))
	address, err = netlink.ParseAddr("198.18.0.2/24")
	must(err)
	must(netlink.AddrAdd(peerLink, address))
	server, err := net.Listen("tcp4", "198.18.0.2:0")
	must(err)
	must(netns.Set(host))
	done := make(chan error, 1)
	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				done <- err
				return
			}
			_, _ = io.Copy(conn, conn)
			_ = conn.Close()
		}
	}()
	var client net.Conn
	var udpProbe uint16
	reset := func() {
		if client != nil {
			_ = client.Close()
			client = nil
		}
		udpProbe = 0
	}
	t.Cleanup(func() { reset(); _ = server.Close(); <-done })
	return uplink, func(stage string) {
		t.Helper()
		if client == nil {
			client, err = net.DialTimeout("tcp4", server.Addr().String(), 3*time.Second)
			must(err)
		}
		must(client.SetDeadline(time.Now().Add(3 * time.Second)))
		_, err := io.WriteString(client, stage)
		must(err)
		reply := make([]byte, len(stage))
		_, err = io.ReadFull(client, reply)
		if err != nil || string(reply) != stage {
			t.Fatalf("native TCP did not survive %s: %q, %v", stage, reply, err)
		}
		flows, err := ebpf.LoadPinnedMap(filepath.Join(kernelPinPath(), "tcp_flow_map"), nil)
		must(err)
		defer flows.Close()
		src := client.LocalAddr().(*net.TCPAddr).AddrPort()
		dst := client.RemoteAddr().(*net.TCPAddr).AddrPort()
		key := tuplesKey(src, dst, unix.IPPROTO_TCP)
		var flow bpfTcpFlowState
		if err := flows.Lookup(key, &flow); err != nil || flow.Mark != 37 || flow.RouteEpoch != 7 {
			t.Fatalf("native TCP lost its saved direct policy during %s: %+v, %v", stage, flow, err)
		}
		attached, err := link.LoadPinnedLink(filepath.Join(kernelPinPath(), "links", hostTCXPinName(uplink.Attrs().Index, hostTCXWanEgress)), nil)
		must(err)
		defer attached.Close()
		info, err := attached.Info()
		must(err)
		program, err := ebpf.NewProgramFromID(info.Program)
		must(err)
		defer program.Close()
		packet, _ := routingKernelPacket(src, dst, consts.L4ProtoType_TCP)
		copy(packet[6:12], uplink.Attrs().HardwareAddr)
		packet[len(packet)-7] = 0x10
		var contextOut [256]byte
		verdict, err := program.Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, len(contextOut)), ContextOut: &contextOut})
		mark := binary.NativeEndian.Uint32(contextOut[8:12])
		if err != nil || verdict != ^uint32(0) || mark != 37 {
			t.Fatalf("native TCP lost its forwarding mark during %s: verdict=%d mark=%d, %v", stage, verdict, mark, err)
		}
		udpProbe++
		packet, _ = routingKernelPacket(netip.AddrPortFrom(src.Addr(), 46000+udpProbe), netip.AddrPortFrom(dst.Addr(), 4444), consts.L4ProtoType_UDP)
		copy(packet[6:12], uplink.Attrs().HardwareAddr)
		verdict, err = program.Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, len(contextOut)), ContextOut: &contextOut})
		if err != nil || verdict != ^uint32(0) {
			t.Fatalf("new native UDP flow failed during %s: verdict=%d, %v", stage, verdict, err)
		}
	}, reset
}

func requirePersistentNamespaces(t *testing.T) {
	t.Helper()
	for _, kind := range []string{"net", "mnt"} {
		original := os.Getenv("DAE_PERSISTENCE_HOST_" + kind)
		current, err := os.Readlink("/proc/self/ns/" + kind)
		if err != nil || original == "" || current == original {
			t.Fatalf("persistence fixture is not in a private %s namespace: %v", kind, err)
		}
	}
}

func waitExited(t *testing.T, m *ebpf.Map, expected uint8) {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		var actual uint8
		if err := m.Lookup(uint32(0), &actual); err != nil {
			t.Fatal(err)
		}
		if actual == expected {
			return
		}
		select {
		case <-timer.C:
			t.Fatalf("exited state = %d, want %d", actual, expected)
		case <-ticker.C:
		}
	}
}

type offlineOrderSocket struct {
	net.Listener
	net.PacketConn
	exited *ebpf.Map
}

func (s *offlineOrderSocket) Close() error {
	var exited uint8
	if err := s.exited.Lookup(uint32(0), &exited); err != nil {
		return err
	}
	if exited != routingabi.DAEMON_OFFLINE {
		return errors.New("listener closed before kernel forwarding went offline")
	}
	return nil
}

func TestPersistentKernelProcess(t *testing.T) {
	phase := os.Getenv("DAE_PERSISTENCE_PHASE")
	if phase == "" || os.Getenv("DAE_PERSISTENCE_ISOLATED") == "" {
		t.Skip("isolated subprocess helper")
	}
	requirePersistentNamespaces(t)
	if err := RegisterDaemonIdentity(); err != nil {
		t.Fatal(err)
	}
	if phase == "restart" {
		identity, err := ebpf.LoadPinnedMap(filepath.Join(kernelPinPath(), "daemon_identity_map"), nil)
		if err != nil {
			t.Fatal(err)
		}
		var registered uint64
		err = identity.Lookup(uint32(0), &registered)
		identity.Close()
		if err != nil || registered != uint64(os.Getpid()) {
			t.Fatalf("bootstrap did not register its socket owner: %d, %v", registered, err)
		}
	}
	r := NewRuntime()
	preparation, err := PrepareControlPlane(t.Context(), r, 0x80)
	if err != nil {
		if verifier, ok := errors.AsType[*ebpf.VerifierError](err); ok {
			t.Fatalf("prepare kernel resources: %+v", verifier)
		}
		t.Fatal(err)
	}
	defer preparation.Close()
	manager := sysctl
	if err := NewRuntime().Close(); err != nil {
		t.Fatal(err)
	}
	if sysctl != manager {
		t.Fatal("unprepared Runtime closed another Runtime's sysctl manager")
	}
	if err := GetDaeNetns().Setup(); err != nil {
		t.Fatalf("unprepared Runtime closed another Runtime's namespace: %v", err)
	}
	bpf := preparation.bpf
	waitExited(t, bpf.ExitedMap, routingabi.DAEMON_STARTING)
	if err := r.Publish(nil, false); !errors.Is(err, ErrPublicationRejected) {
		t.Fatalf("published without ready listeners: %v", err)
	}
	if phase == "unpublished" {
		fmt.Println("ready")
		_, _ = io.Copy(io.Discard, os.Stdin)
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	mac := [6]byte{2, 0, 0, 0, 0, 7}
	interrupted := [6]byte{2, 0, 0, 0, 0, 8}
	if phase == "first" {
		r.deviceRoutes.device(mac).epoch = 7
		table, err := r.deviceRoutes.table(nil, false)
		if err != nil {
			t.Fatal(err)
		}
		defer table.Close()
		if err := table.Update(interrupted, bpfDeviceRouteState{Epoch: 9, Updating: 1}, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		if err := bpf.DeviceRoutesMap.Update(uint32(0), table, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	} else {
		if device := r.deviceRoutes.devices[mac]; device == nil || device.epoch != 7 {
			t.Fatalf("restart lost the epoch needed by existing direct connections: %+v", device)
		}
		if device := r.deviceRoutes.devices[interrupted]; device == nil || device.epoch != 10 {
			t.Fatalf("restart revived a connection from an interrupted route update: %+v", device)
		}
		var table *ebpf.Map
		if err := bpf.DeviceRoutesMap.Lookup(uint32(0), &table); err != nil {
			t.Fatal(err)
		}
		defer table.Close()
		var state bpfDeviceRouteState
		if err := table.Lookup(interrupted, &state); err != nil || state.Epoch != 10 || state.Updating != 0 {
			t.Fatalf("restart retained a stale device update gate: %+v, %v", state, err)
		}
	}
	matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "l4proto(tcp) -> direct(mark:37)"))
	matcher.bpf = bpf
	if err := matcher.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	core := &controlPlaneCore{kernelLinks: &r.kernelLinks, bpf: bpf}
	if err := core.setupExitHandler(); err != nil {
		t.Fatal(err)
	}
	device, err := netlink.LinkByName("pin-uplink")
	if err != nil {
		t.Fatal(err)
	}
	binder := &hostBinder{kernelLinks: &r.kernelLinks, bpf: bpf, closed: t.Context(), wanBindings: make(map[int]*wanBinding)}
	binder.setManualWan(device, "pin-uplink", true)
	if binder.reconcileWanWith(nil, nil, netlink.LinkByIndex) {
		t.Fatal("could not adopt the configured WAN attachment")
	}
	if err := r.pruneUDPTimerPins(true); err != nil {
		t.Fatal(err)
	}
	// This observation pin belongs to the fixture, outside dae's owned directory.
	statePin := filepath.Join(consts.BpfPinRoot, "test_exited")
	if err := os.Remove(statePin); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := bpf.ExitedMap.Pin(statePin); err != nil {
		t.Fatal(err)
	}
	if err := r.setExited(routingabi.DAEMON_ONLINE); err != nil {
		t.Fatal(err)
	}
	order := &offlineOrderSocket{exited: bpf.ExitedMap}
	r.listener = &Listener{tcpListener: order, packetConn: order}
	fmt.Println("ready")
	_, _ = io.Copy(io.Discard, os.Stdin)
	if err := bpf.bpfPrograms.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}
