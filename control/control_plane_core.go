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
	"slices"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/selector"
	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/component/outbound"
)

type controlPlaneCore struct {
	*kernelLinks
	lifecycleMu sync.Mutex
	closeOnce   sync.Once
	closeErr    error
	quiesceOnce sync.Once
	quiesceErr  error

	cleanupMu   sync.Mutex
	cleanups    cleanupStack
	tableReader kernelTableReader
	bpf         *BPFState
	hostBinder  *hostBinder

	isReload bool

	// domainRegistry tracks every domain -> IP registration learned
	// from DNS. It is the single source of truth for domain_routing_map in
	// eBPF; every mutation atomically replaces the affected IP's combined
	// bump/routing value, so user space and BPF stay in sync.
	domainRegistry *DomainRegistry

	closed            context.Context
	close             context.CancelFunc
	ifmgr             *network.InterfaceScope
	ownedInterfaces   *network.InterfaceManager
	netmon            *network.HostNetworkMonitor
	outboundResources *outbound.Resources
	apiAddressChanges chan struct{}

	outboundCallbackMu sync.Mutex
	outboundRecovery   func()
	// Candidate checks update userspace immediately; PrepareKernel enables the
	// private BPF projection before its programs can be published. Values hold
	// the latest projection, pending until then and mirrored afterwards.
	outboundConnectivityPublished bool
	outboundConnectivityValues    map[bpfOutboundConnectivityQuery]outboundConnectivity
}

// UserspaceResources are borrowed for the lifetime of a prepared plane. Nil
// fields give a standalone preparation its own interfaces and outbound state.
type UserspaceResources struct {
	Interfaces *network.InterfaceManager
	Outbounds  *outbound.Resources
	// ProcessIdentity keeps preparation routing independent of the helper's
	// executable filename and real PID, which only the kernel exemption uses.
	ProcessIdentity *ProcessIdentity
	// Input-only preparation may borrow selector hints, never a disk baseline.
	SelectorHints map[string]*selector.Path
	// SkipConnectivityWait launches initial probes without blocking on startup
	// convergence, avoiding multi-second delays while replacement ingress is blocked
	// or when no remote plugin preparation needs routed outbounds.
	SkipConnectivityWait bool
}

func newControlPlaneCore(resources UserspaceResources) (*controlPlaneCore, error) {
	closed, toClose := context.WithCancel(context.Background())
	source := resources.Interfaces
	var ownedInterfaces *network.InterfaceManager
	var err error
	if source == nil {
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
	if resources.Outbounds == nil {
		resources.Outbounds = &outbound.Resources{}
	}
	core := &controlPlaneCore{
		ifmgr:             ifmgr,
		ownedInterfaces:   ownedInterfaces,
		netmon:            netmon,
		outboundResources: resources.Outbounds,
		apiAddressChanges: make(chan struct{}, 1),
		closed:            closed,
		close:             toClose,
	}
	core.domainRegistry = newDomainRegistry(0, consts.DefaultDNSRetentionWindow, nil, nil)
	// Recheck after publication as addresses may change while the candidate is built.
	core.apiAddressChanges <- struct{}{}
	netmon.Register(func(previous, next network.HostNetworkSnapshot) {
		if !slices.Equal(previous.LocalAddresses, next.LocalAddresses) {
			select {
			case core.apiAddressChanges <- struct{}{}:
			default:
			}
		}
	})
	core.addCleanup(core.closeBpf)
	core.addCleanup(core.tableReader.Close)
	core.addCleanup(core.domainRegistry.Close)
	return core, nil
}

// bindBPF takes ownership once; callers serialize installation and Close.
func (c *controlPlaneCore) bindBPF(bpf *BPFState, isReload bool) {
	c.outboundCallbackMu.Lock()
	c.bpf, c.kernelLinks, c.isReload = bpf, &bpf.kernelLinks, isReload
	c.outboundCallbackMu.Unlock()
	c.hostBinder = &hostBinder{kernelLinks: &bpf.kernelLinks, bpf: bpf, ifmgr: c.ifmgr, closed: c.closed, wanBindings: make(map[int]*wanBinding)}
	registry := c.domainRegistry
	registry.mu.Lock()
	// Read actual capacity; preparation never loads a business map for it.
	if bpf.DomainRoutingMap != nil {
		registry.kernel.max = int(bpf.DomainRoutingMap.MaxEntries())
	}
	registry.kernel.update, registry.kernel.remove = c.writeDomainBitmaps, c.deleteDomainBitmaps
	registry.kernel.batchUpdate = c.writeDomainBitmapBatch
	if bpf.DomainActivitySlots != nil {
		feed, err := newDomainDirectFeed(bpf.DomainActivitySlots, bpf.DomainActivityEvents, bpf.DomainActivityLosses)
		if err != nil {
			registry.warnDirect(time.Now(), err)
		} else {
			registry.direct = feed
		}
	}
	if bpf.Runtime != nil {
		registry.activityLag = tcpMonitorInterval
	}
	registry.mu.Unlock()
	registry.Start()
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
	if c.bpf == nil {
		return nil
	}
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
	return c.kernelLinks.attachSocketIdentity([]*ebpf.Program{c.bpf.TproxyWanCgSockCreate, c.bpf.TproxyWanCgConnect4, c.bpf.TproxyWanCgConnect6, c.bpf.TproxyWanCgSendmsg4, c.bpf.TproxyWanCgSendmsg6})
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
	if err := c.pinExitLink(link); err != nil {
		return errors.Join(fmt.Errorf("pin exit handler: %w", err), link.Close())
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
	key := ipv6BytesToWords(ip6[:])
	if err := c.bpf.DomainRoutingMap.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update domain bitmap %s: %w", ip, err)
	}
	return nil
}

func (c *controlPlaneCore) writeDomainBitmapBatch(entries []domainMapEntry) error {
	keys := make([][4]uint32, len(entries))
	values := make([]bpfDomainRouting, len(entries))
	for i, entry := range entries {
		if len(entry.bump) != len(values[i].Bump) || len(entry.routing) != len(values[i].Routing) {
			panic("domain bitmap length not sync with kern program")
		}
		ip := entry.ip.As16()
		keys[i] = ipv6BytesToWords(ip[:])
		copy(values[i].Bump[:], entry.bump)
		copy(values[i].Routing[:], entry.routing)
	}
	n, err := c.bpf.DomainRoutingMap.BatchUpdate(keys, values, &ebpf.BatchOptions{ElemFlags: uint64(ebpf.UpdateAny)})
	if err != nil {
		return err
	}
	if n != len(entries) {
		return fmt.Errorf("domain bitmap batch updated %d of %d entries", n, len(entries))
	}
	return nil
}

// deleteDomainBitmaps removes ip from the kernel domain map. It is bound
// to domainRegistry.remove. A missing key is tolerated (the desired end
// state is already reached); other failures retain the installed record.
func (c *controlPlaneCore) deleteDomainBitmaps(ip netip.Addr) error {
	ip6 := ip.As16()
	key := ipv6BytesToWords(ip6[:])
	if err := c.bpf.DomainRoutingMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete domain bitmap %s: %w", ip, err)
	}
	return nil
}
