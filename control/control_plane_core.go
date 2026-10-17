/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/network"
)

type controlPlaneCore struct {
	*kernelLinks
	lifecycleMu sync.Mutex
	closeOnce   sync.Once
	closeErr    error
	quiesceOnce sync.Once
	quiesceErr  error

	cleanupMu  sync.Mutex
	cleanups   cleanupStack
	bpf        *BPFState
	hostBinder *hostBinder

	isReload bool

	// domainRegistry tracks every domain -> IP registration learned
	// from DNS. It is the single source of truth for domain_routing_map in
	// eBPF; every mutation atomically replaces the affected IP's combined
	// bump/routing value, so user space and BPF stay in sync.
	domainRegistry *DomainRegistry

	closed          context.Context
	close           context.CancelFunc
	ifmgr           *network.InterfaceScope
	ownedInterfaces *network.InterfaceManager
	netmon          *network.HostNetworkMonitor

	// outboundConnectivityMap stores actual outbound usability per network. It
	// mirrors the eBPF map for userspace skip_while_noalive evaluation. A zero
	// value also represents state that has not been reported yet.
	outboundConnectivityMap [consts.OutboundUserDefinedMax + 1][common.NetworkTypeCount]atomic.Bool
	outboundCallbackMu      sync.Mutex
	outboundRecovery        func()
	// Candidate checks update userspace immediately; PrepareKernel enables the
	// private BPF projection before its programs can be published.
	outboundConnectivityPublished bool
	pendingOutboundConnectivity   map[bpfOutboundConnectivityQuery]uint32
}

func newControlPlaneCore(
	bpf *BPFState,
	isReload bool,
) (*controlPlaneCore, error) {
	closed, toClose := context.WithCancel(context.Background())
	var source, ownedInterfaces *network.InterfaceManager
	var err error
	if bpf.Runtime != nil {
		source, err = bpf.Runtime.Interfaces()
	} else {
		source, err = network.NewInterfaceManager()
		ownedInterfaces = source
	}
	if err != nil {
		toClose()
		return nil, fmt.Errorf("initialize interface manager: %w", err)
	}
	ifmgr := source.NewScope()
	netmon, err := network.NewHostNetworkMonitor(ifmgr)
	if err != nil {
		toClose()
		err = errors.Join(fmt.Errorf("initialize host network monitor: %w", err), ifmgr.Close())
		if ownedInterfaces != nil {
			err = errors.Join(err, ownedInterfaces.Close())
		}
		return nil, err
	}
	core := &controlPlaneCore{
		kernelLinks:                 &bpf.kernelLinks,
		bpf:                         bpf,
		isReload:                    isReload,
		ifmgr:                       ifmgr,
		ownedInterfaces:             ownedInterfaces,
		netmon:                      netmon,
		closed:                      closed,
		close:                       toClose,
		pendingOutboundConnectivity: make(map[bpfOutboundConnectivityQuery]uint32),
	}
	core.hostBinder = &hostBinder{kernelLinks: &bpf.kernelLinks, bpf: bpf, ifmgr: ifmgr, closed: closed, wanBindings: make(map[int]*wanBinding)}
	// The kernel-side capacity is read back from the map itself so it can
	// never drift from MAX_DOMAIN_ROUTING_NUM in control/kern/tproxy.c.
	capacity := 0
	if bpf.DomainRoutingMap != nil {
		capacity = int(bpf.DomainRoutingMap.MaxEntries())
	}
	core.domainRegistry = newDomainRegistry(
		capacity,
		consts.DefaultDNSRetentionWindow,
		core.writeDomainBitmaps, core.deleteDomainBitmaps,
	)
	if bpf.Runtime != nil {
		core.domainRegistry.activityLag = tcpMonitorInterval
	}
	core.domainRegistry.Start()
	core.addCleanup(core.closeBpf)
	core.addCleanup(core.domainRegistry.Close)
	return core, nil
}

func (c *controlPlaneCore) addCleanup(cleanup func() error) {
	c.cleanupMu.Lock()
	c.cleanups.add(cleanup)
	c.cleanupMu.Unlock()
}

func (c *controlPlaneCore) takeCleanups() []func() error {
	c.cleanupMu.Lock()
	defer c.cleanupMu.Unlock()

	return c.cleanups.take()
}

// closeBpf releases only this generation's descriptors.
func (c *controlPlaneCore) closeBpf() error {
	return c.bpf.Close()
}

func (c *controlPlaneCore) quiesce() error {
	c.quiesceOnce.Do(func() {
		c.close()
		c.outboundCallbackMu.Lock()
		c.outboundCallbackMu.Unlock()
		if c.netmon != nil {
			c.quiesceErr = c.netmon.Close()
		}
		if c.ifmgr != nil {
			c.quiesceErr = errors.Join(c.quiesceErr, c.ifmgr.Close())
		}
		if c.ownedInterfaces != nil {
			c.quiesceErr = errors.Join(c.quiesceErr, c.ownedInterfaces.Close())
		}
		if c.hostBinder != nil {
			c.hostBinder.quiesce()
		}
	})
	return c.quiesceErr
}

func (c *controlPlaneCore) Close() (err error) {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	return c.closeLocked()
}

func (c *controlPlaneCore) closeLocked() (err error) {
	c.closeOnce.Do(func() {
		// Cancel before joining InterfaceManager callbacks. A callback waiting
		// for the binder mutex can then return without touching shared maps.
		c.closeErr = c.quiesce()
		// Interface callbacks can register TCX link ownership. Waiting for the
		// monitor first freezes dynamic registration before cleanup is drained.
		for _, cleanup := range c.takeCleanups() {
			c.closeErr = errors.Join(c.closeErr, cleanup())
		}
	})
	return c.closeErr
}

func (c *controlPlaneCore) setupSkPidMonitor() error {
	c.kernelLinks.mu.Lock()
	defer c.kernelLinks.mu.Unlock()
	if len(c.pidLinks) != 0 {
		return nil
	}
	/// Set-up SrcPidMapper to support pname routing.
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		return err
	}
	type cgProg struct {
		Prog   *ebpf.Program
		Attach ebpf.AttachType
	}
	cgProgs := []cgProg{
		{Prog: c.bpf.TproxyWanCgSockCreate, Attach: ebpf.AttachCGroupInetSockCreate},
		{Prog: c.bpf.TproxyWanCgSockRelease, Attach: ebpf.AttachCgroupInetSockRelease},
		{Prog: c.bpf.TproxyWanCgConnect4, Attach: ebpf.AttachCGroupInet4Connect},
		{Prog: c.bpf.TproxyWanCgConnect6, Attach: ebpf.AttachCGroupInet6Connect},
		{Prog: c.bpf.TproxyWanCgSendmsg4, Attach: ebpf.AttachCGroupUDP4Sendmsg},
		{Prog: c.bpf.TproxyWanCgSendmsg6, Attach: ebpf.AttachCGroupUDP6Sendmsg},
	}
	for _, prog := range cgProgs {
		attached, err := ciliumLink.AttachCgroup(ciliumLink.CgroupOptions{
			Path:    cgroupPath,
			Attach:  prog.Attach,
			Program: prog.Prog,
		})
		if err != nil {
			return fmt.Errorf("AttachCgroup: %v: %w", prog.Prog.String(), err)
		}
		c.pidLinks = append(c.pidLinks, attached)
	}
	return nil
}

func (c *controlPlaneCore) setupExitHandler() (err error) {
	c.kernelLinks.mu.Lock()
	defer c.kernelLinks.mu.Unlock()
	if c.exitLink != nil {
		return nil
	}
	link, err := ciliumLink.Tracepoint("sched", "sched_process_exit", c.bpf.HandleExit, nil)
	if err != nil {
		return fmt.Errorf("Tracepoint: %w", err)
	}
	c.exitLink = link
	return nil
}

func (c *controlPlaneCore) bindDaens() (err error) {
	c.kernelLinks.mu.Lock()
	defer c.kernelLinks.mu.Unlock()
	if len(c.netnsLinks) != 0 {
		return nil
	}
	c.netnsLinks, err = GetDaeNetns().attachPrograms(c.bpf.bpfPrograms)
	return err
}

func closeBpfLinks(links []ciliumLink.Link) error {
	var err error
	for i := len(links) - 1; i >= 0; i-- {
		err = errors.Join(err, links[i].Close())
	}
	return err
}

// writeDomainBitmaps pushes the derived bitmaps of one IP to the kernel
// domain map. It is bound to domainRegistry.update; the registry computes
// the bitmaps from the registrations of the IP:
//
//	bump bit i    = any cached domain of this IP matches rule i
//	routing bit i = all cached domains of this IP match rule i
//
// Allocation failures on the non-preallocated map are retried by the registry.
func (c *controlPlaneCore) writeDomainBitmaps(ip netip.Addr, bump, routing []uint32) error {
	var value bpfDomainRouting
	if consts.MaxMatchSetLen/32 != len(value.Bump) || len(bump) != len(value.Bump) || len(routing) != len(value.Routing) {
		panic("domain bitmap length not sync with kern program")
	}
	copy(value.Bump[:], bump)
	copy(value.Routing[:], routing)

	ip6 := ip.As16()
	key := common.Ipv6ByteSliceToUint32Array(ip6[:])
	if err := c.bpf.DomainRoutingMap.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update domain bitmap %s: %w", ip, err)
	}
	return nil
}

// deleteDomainBitmaps removes ip from the kernel domain map. It is bound
// to domainRegistry.remove. A missing key is tolerated (the desired end
// state is already reached); other failures retain the installed record.
func (c *controlPlaneCore) deleteDomainBitmaps(ip netip.Addr) error {
	ip6 := ip.As16()
	key := common.Ipv6ByteSliceToUint32Array(ip6[:])
	if err := c.bpf.DomainRoutingMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete domain bitmap %s: %w", ip, err)
	}
	return nil
}
