// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/control/internal/splice"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type kernelCheck struct {
	name  string
	probe func() error
}

func runKernelChecks(ctx context.Context, checks ...kernelCheck) error {
	var failures []error
	for _, check := range checks {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		if err := check.probe(); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", check.name, err))
		}
	}
	return errors.Join(append(failures, ctx.Err())...)
}

func checkKernelVersion() error {
	version, err := internal.KernelVersion()
	if err != nil {
		return fmt.Errorf("get kernel version: %w", err)
	}
	if version.Less(consts.MinimumKernelVersion) {
		return fmt.Errorf("kernel %s requires an upgrade to Linux %s or newer", version, consts.MinimumKernelVersion)
	}
	return nil
}

// CheckKernelFeatures verifies the running kernel before startup resources are
// prepared. It loads the production collection with private, unpinned maps, then
// probes attachment APIs. Network probes live in an unnamed network namespace;
// cgroup probes only attach allow-only programs. All probe resources are closed.
func CheckKernelFeatures(ctx context.Context) error {
	return checkKernelFeatures(ctx, netlink.LinkAdd)
}

func checkKernelFeatures(ctx context.Context, addLink func(netlink.Link) error) error {
	started := time.Now()
	if err := runKernelChecks(ctx,
		kernelCheck{"kernel version", checkKernelVersion},
		kernelCheck{"BPF memory limit", rlimit.RemoveMemlock},
		kernelCheck{"kernel BTF (CONFIG_DEBUG_INFO_BTF)", func() error {
			_, err := btf.LoadKernelSpec()
			return err
		}},
	); err != nil {
		return fmt.Errorf("kernel preflight failed: %w", err)
	}
	// Use the same device selection and attachment path as normal startup.
	if err := withKernelProbeNamespace(addLink, func(ns *DaeNetns) error {
		return checkKernelFeaturesForLink(ctx, ns)
	}); err != nil {
		return fmt.Errorf("kernel preflight failed: %w", err)
	}
	log.WithField("duration", time.Since(started)).Info("Kernel feature checks passed")
	return nil
}

func checkKernelFeaturesForLink(ctx context.Context, ns *DaeNetns) error {
	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("kernel preflight: read embedded eBPF collection: %w", err)
	}
	currentTask, err := probeBPFCurrentTask()
	if err != nil {
		return fmt.Errorf("kernel preflight: %w", err)
	}
	// Nonzero constants keep the same verifier paths alive as normal startup.
	if err := spec.Variables["PARAM"].Set(bpfDaeParam{
		ControlPlanePid: uint32(os.Getpid()), Dae0Ifindex: uint32(ns.dae0.Attrs().Index), Dae0peerIfindex: uint32(ns.dae0peer.Attrs().Index),
		Dae0peerMac: [6]uint8(ns.dae0peer.Attrs().HardwareAddr), HasBpfGetCurrentTask: currentTask,
		SoMarkFromDae: 0x100,
	}); err != nil {
		return fmt.Errorf("kernel preflight: set eBPF constants: %w", err)
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("kernel preflight: production eBPF programs/maps/helpers: %w", explainBPFLoadError(err))
	}
	defer collection.Close()
	if err := runKernelChecks(ctx,
		kernelCheck{"BPF filesystem pinning", func() error { return probeBPFPinning(collection.Maps["exited_map"]) }},
		kernelCheck{"cgroup v2 hooks (CONFIG_CGROUP_BPF)", func() error { return probeCgroupHooks(ctx, spec) }},
		kernelCheck{"internal " + ns.dae0.Type() + " links, TCX and SK_LOOKUP", func() error {
			return probeNetworkFeatures(ctx, ns, collection)
		}},
		kernelCheck{"sched_process_exit tracepoint (CONFIG_PERF_EVENTS/CONFIG_BPF_EVENTS)", func() error {
			attached, err := link.Tracepoint("sched", "sched_process_exit", collection.Programs["handle_exit"], nil)
			if err != nil {
				return err
			}
			return attached.Close()
		}},
	); err != nil {
		return fmt.Errorf("kernel preflight failed (check kernel support, mounts and process capabilities): %w", err)
	}
	// Splice is an acceleration, not a requirement for the core datapath.
	optional, err := splice.New(nil, DefaultNatTimeoutTCPEstablished)
	if err != nil {
		log.WithError(err).Warn("Kernel preflight: optional TCP splice unavailable; using userspace relay")
	} else if optional != nil {
		if err := optional.Close(); err != nil {
			return fmt.Errorf("kernel preflight: close optional TCP splice probe: %w", err)
		}
	} else {
		log.Debug("Kernel preflight: optional TCP splice unavailable")
	}
	return ctx.Err()
}

func probeBPFPinning(m *ebpf.Map) (err error) {
	dir, err := os.MkdirTemp(consts.BpfPinRoot, "dae-check-")
	if err != nil {
		return fmt.Errorf("bpffs must be writable: %w", err)
	}
	defer func() { err = errors.Join(err, os.Remove(dir)) }()
	if err := m.Pin(filepath.Join(dir, "probe")); err != nil {
		return err
	}
	return m.Unpin()
}

func probeCgroupHooks(ctx context.Context, spec *ebpf.CollectionSpec) error {
	path, err := detectCgroupPath()
	if err != nil {
		return err
	}
	var checks []kernelCheck
	for _, name := range slices.Sorted(maps.Keys(spec.Programs)) {
		p := spec.Programs[name]
		if p.Type != ebpf.CGroupSock && p.Type != ebpf.CGroupSockAddr {
			continue
		}
		checks = append(checks, kernelCheck{name, func() error {
			// Do not populate socket identity maps or require a writable cgroup
			// mount merely to probe. Returning 1 preserves every socket verdict.
			probe, err := ebpf.NewProgram(&ebpf.ProgramSpec{
				Type: p.Type, AttachType: p.AttachType, License: "GPL",
				Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()},
			})
			if err != nil {
				return err
			}
			defer probe.Close()
			attached, err := link.AttachCgroup(link.CgroupOptions{Path: path, Attach: p.AttachType, Program: probe})
			if err != nil {
				return err
			}
			return attached.Close()
		}})
	}
	return runKernelChecks(ctx, checks...)
}

func withKernelProbeNamespace(addLink func(netlink.Link) error, probe func(*DaeNetns) error) error {
	result := make(chan error, 1)
	go func() {
		// Exiting while locked retires this thread and its namespace. Do not
		// unlock it: another goroutine must never inherit the probe namespace.
		runtime.LockOSThread()
		result <- probeInNetworkNamespace(addLink, probe)
	}()
	return <-result
}

func probeInNetworkNamespace(addLink func(netlink.Link) error, probe func(*DaeNetns) error) error {
	ns, err := netns.New()
	if err != nil {
		return fmt.Errorf("create isolated network namespace (CONFIG_NET_NS): %w", err)
	}
	defer ns.Close()
	loopback, err := netlink.LinkByIndex(consts.LoopbackIfIndex)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(loopback); err != nil {
		return fmt.Errorf("bring up probe loopback: %w", err)
	}
	if err := createDaeLinkPair("dae-check0", "dae-check1", addLink); err != nil {
		return err
	}
	device, err := netlink.LinkByName("dae-check0")
	if err != nil {
		return err
	}
	peer, err := netlink.LinkByName("dae-check1")
	if err != nil {
		return err
	}
	// Both endpoints are already prepared in this disposable namespace. They
	// use the same attachment method as the daemon without touching daens.
	prepared := &DaeNetns{dae0: device, dae0peer: peer, hostNs: ns, daeNs: ns}
	prepared.setupDone.Store(true)
	return probe(prepared)
}

func probeNetworkFeatures(ctx context.Context, ns *DaeNetns, collection *ebpf.Collection) error {
	checks := []kernelCheck{
		{"IPv4 policy routing (CONFIG_IP_MULTIPLE_TABLES)", func() error { return probePolicyRouting(unix.AF_INET) }},
		{"IPv4 transparent TCP/UDP sockets and SO_MARK", func() error { return probeTransparentSockets(unix.AF_INET) }},
		{"IPv6 transparent TCP/UDP sockets (CONFIG_IPV6)", func() error { return probeTransparentSockets(unix.AF_INET6) }},
		{"internal handoff and return paths", func() error {
			links, err := ns.attachPrograms(bpfPrograms{
				TproxySkLookup:        collection.Programs["tproxy_sk_lookup"],
				TproxyDae0peerIngress: collection.Programs["tproxy_dae0peer_ingress"],
				TproxyDae0Ingress:     collection.Programs["tproxy_dae0_ingress"],
			})
			return errors.Join(err, closeBpfLinks(links))
		}},
	}
	// The collection load verifies every host program. TCX attachment and
	// replacement use the same API for all of them; probe each direction once.
	for _, target := range []struct {
		name   string
		attach ebpf.AttachType
	}{
		{"lan_ingress_l2", ebpf.AttachTCXIngress},
		{"tproxy_wan_egress_l2", ebpf.AttachTCXEgress},
	} {
		checks = append(checks, kernelCheck{target.name, func() error {
			program := collection.Programs[target.name]
			attached, err := link.AttachTCX(link.TCXOptions{Interface: consts.LoopbackIfIndex, Program: program, Attach: target.attach, Anchor: link.Tail()})
			if err != nil {
				return err
			}
			return errors.Join(attached.Update(program), attached.Close())
		}})
	}
	if err := runKernelChecks(ctx, checks...); err != nil {
		return err
	}
	// Normal namespace setup tolerates missing IPv6 policy routing too.
	if err := probePolicyRouting(unix.AF_INET6); err != nil {
		log.WithError(err).Warn("Kernel preflight: IPv6 interception routing unavailable (CONFIG_IPV6_MULTIPLE_TABLES)")
	}
	return ctx.Err()
}

func probePolicyRouting(family int) error {
	destination := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	if family == unix.AF_INET6 {
		destination = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	}
	route := &netlink.Route{
		Scope: unix.RT_SCOPE_HOST, LinkIndex: consts.LoopbackIfIndex,
		Dst: destination, Table: 2023, Type: unix.RTN_LOCAL,
	}
	if err := netlink.RouteAdd(route); err != nil {
		return err
	}
	rule := netlink.NewRule()
	rule.Family, rule.Table = family, 2023
	rule.Mark, rule.Mask = consts.TproxyMark, new(consts.TproxyMark)
	return netlink.RuleAdd(rule)
}

func probeTransparentSockets(family int) error {
	level, option := unix.SOL_IP, unix.IP_TRANSPARENT
	if family == unix.AF_INET6 {
		level, option = unix.SOL_IPV6, unix.IPV6_TRANSPARENT
	}
	for _, kind := range []int{unix.SOCK_STREAM, unix.SOCK_DGRAM} {
		fd, err := unix.Socket(family, kind|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		err = errors.Join(
			unix.SetsockoptInt(fd, level, option, 1),
			unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, 0x100),
			unix.Close(fd),
		)
		if err != nil {
			return err
		}
	}
	return nil
}
