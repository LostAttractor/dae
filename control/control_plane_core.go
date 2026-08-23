/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var exitHandlerClose func() error

type controlPlaneCore struct {
	mu          sync.Mutex
	lifecycleMu sync.Mutex
	closeOnce   sync.Once
	closeErr    error

	cleanupMu    sync.Mutex
	deferFuncs   []func() error
	hostTCXLinks []hostTCXLink
	bpf          *bpfState
	wanBindings  map[int]*wanBinding

	isReload bool
	// bpfOwned reports whether this core currently owns the bpf objects and
	// closes them on Close. At most one core owns them; during reload neither
	// core owns them between the old core's EjectBpf and the new core's InjectBpf.
	bpfOwned bool

	// domainRegistry tracks every (domain, qtype) -> IP registration learned
	// from DNS. It is the single source of truth for domain_routing_map in
	// eBPF; every mutation atomically replaces the affected IP's combined
	// bump/routing value, so user space and BPF stay in sync.
	domainRegistry *DomainRegistry

	closed context.Context
	close  context.CancelFunc
	ifmgr  *component.InterfaceManager
	netmon *component.HostNetworkMonitor

	// outboundConnectivityMap stores actual outbound usability per network. It
	// mirrors the eBPF map for userspace skip_while_noalive evaluation. A zero
	// value also represents state that has not been reported yet.
	outboundConnectivityMap [consts.OutboundUserDefinedMax + 1][4]atomic.Bool
	outboundCallbackMu      sync.Mutex
	outboundRecovery        func()
}

type hostTCXRole uint8

const (
	hostTCXLanIngress hostTCXRole = iota
	hostTCXLanEgress
	hostTCXWanIngress
	hostTCXWanEgress
)

type hostTCXLink struct {
	linkIndex int
	role      hostTCXRole
	link      ciliumLink.Link
	close     func() error
}

type hostTCXProgram struct {
	role    hostTCXRole
	program *ebpf.Program
}

type wanBinding struct {
	ifname         string
	manualPatterns map[string]struct{}
	automatic      bool
}

func newControlPlaneCore(
	bpf *bpfState,
	isReload bool,
) (*controlPlaneCore, error) {
	closed, toClose := context.WithCancel(context.Background())
	ifmgr, err := component.NewInterfaceManager()
	if err != nil {
		toClose()
		return nil, oops.Wrapf(err, "initialize interface manager")
	}
	netmon := component.NewHostNetworkMonitor()
	core := &controlPlaneCore{
		bpf:      bpf,
		isReload: isReload,
		// A reload candidate starts without BPF cleanup ownership. The caller
		// released it from the old core before construction and assigns it to
		// this core via InjectBpf only after the old core is retired.
		bpfOwned:    !isReload,
		ifmgr:       ifmgr,
		netmon:      netmon,
		closed:      closed,
		close:       toClose,
		wanBindings: make(map[int]*wanBinding),
	}
	// The kernel-side capacity is read back from the map itself so it can
	// never drift from MAX_DOMAIN_ROUTING_NUM in control/kern/tproxy.c.
	core.domainRegistry = newDomainRegistry(
		int(bpf.DomainRoutingMap.MaxEntries()),
		consts.DomainRegistryMaxSize,
		time.Duration(consts.MinDomainTTL)*time.Second,
	)
	core.domainRegistry.update = core.writeDomainBitmaps
	core.domainRegistry.remove = core.deleteDomainBitmaps
	core.domainRegistry.StartSweeper()
	core.addCleanup(core.closeBpf)
	core.addCleanup(core.domainRegistry.Close)
	return core, nil
}

func (c *controlPlaneCore) addCleanup(cleanup func() error) {
	c.cleanupMu.Lock()
	c.deferFuncs = append(c.deferFuncs, cleanup)
	c.cleanupMu.Unlock()
}

func (c *controlPlaneCore) ownHostTCXLink(owned hostTCXLink) bool {
	c.cleanupMu.Lock()
	defer c.cleanupMu.Unlock()
	for _, existing := range c.hostTCXLinks {
		if existing.linkIndex == owned.linkIndex && existing.role == owned.role {
			return false
		}
	}
	c.hostTCXLinks = append(c.hostTCXLinks, owned)
	return true
}

func (c *controlPlaneCore) hostTCXLink(linkIndex int, role hostTCXRole) (ciliumLink.Link, bool) {
	c.cleanupMu.Lock()
	defer c.cleanupMu.Unlock()
	for _, owned := range c.hostTCXLinks {
		if owned.linkIndex == linkIndex && owned.role == role {
			return owned.link, true
		}
	}
	return nil, false
}

func (c *controlPlaneCore) closeHostTCXLinks(linkIndex int, roles ...hostTCXRole) error {
	c.cleanupMu.Lock()
	links := make([]hostTCXLink, 0, len(c.hostTCXLinks))
	kept := make([]hostTCXLink, 0, len(c.hostTCXLinks))
	for _, owned := range c.hostTCXLinks {
		if owned.linkIndex != linkIndex || (len(roles) > 0 && !slices.Contains(roles, owned.role)) {
			kept = append(kept, owned)
			continue
		}
		links = append(links, owned)
	}
	c.hostTCXLinks = kept
	c.cleanupMu.Unlock()

	var err error
	for i := len(links) - 1; i >= 0; i-- {
		err = errors.Join(err, links[i].close())
	}
	return err
}

func (c *controlPlaneCore) resetHostTCXLinks() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupMu.Lock()
	links := c.hostTCXLinks
	c.hostTCXLinks = nil
	c.cleanupMu.Unlock()
	for i := len(links) - 1; i >= 0; i-- {
		if err := links[i].close(); err != nil {
			log.Errorf("close stale %s TCX link on interface %d: %v", links[i].role, links[i].linkIndex, err)
		}
	}
}

func (c *controlPlaneCore) takeCleanups() []func() error {
	c.cleanupMu.Lock()
	defer c.cleanupMu.Unlock()

	cleanups := make([]func() error, 0, len(c.hostTCXLinks)+len(c.deferFuncs))
	for i := len(c.hostTCXLinks) - 1; i >= 0; i-- {
		cleanups = append(cleanups, c.hostTCXLinks[i].close)
	}
	for i := len(c.deferFuncs) - 1; i >= 0; i-- {
		cleanups = append(cleanups, c.deferFuncs[i])
	}
	c.hostTCXLinks = nil
	c.deferFuncs = nil
	return cleanups
}

// closeBpf closes the bpf objects if this core still owns them (see bpfOwned).
func (c *controlPlaneCore) closeBpf() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.bpfOwned {
		return nil
	}
	return c.bpf.Close()
}

func (c *controlPlaneCore) Close() (err error) {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	return c.closeLocked()
}

func (c *controlPlaneCore) closeLocked() (err error) {
	c.closeOnce.Do(func() {
		// Cancel before joining InterfaceManager callbacks. A callback waiting
		// for c.mu can then acquire it and return without touching shared maps.
		c.close()
		// Wait for callbacks that passed the closed check before cancellation.
		// Later callbacks acquire the mutex, observe closed, and return.
		c.outboundCallbackMu.Lock()
		c.outboundCallbackMu.Unlock()
		if c.netmon != nil {
			c.closeErr = c.netmon.Close()
		}
		if err := c.ifmgr.Close(); err != nil {
			if c.closeErr != nil {
				c.closeErr = oops.Errorf("%w; %v", c.closeErr, err)
			} else {
				c.closeErr = err
			}
		}
		// Interface callbacks can register TCX link ownership. Waiting for the
		// monitor first freezes dynamic registration before cleanup is drained.
		for _, cleanup := range c.takeCleanups() {
			if e := cleanup(); e != nil {
				if c.closeErr != nil {
					c.closeErr = oops.Errorf("%w; %v", c.closeErr, e)
				} else {
					c.closeErr = e
				}
			}
		}
	})
	return c.closeErr
}

func linkHdrLen(link netlink.Link) uint32 {
	switch link.Attrs().EncapType {
	case "none", "ipip", "ppp", "tun":
		return consts.LinkHdrLen_None
	case "ether":
		return consts.LinkHdrLen_Ethernet
	default:
		log.Warnf("Maybe unsupported link type %v, using default link header length", link.Attrs().EncapType)
		return consts.LinkHdrLen_Ethernet
	}
}

func legacyTCFilter(filter netlink.Filter, parent uint32) bool {
	bpfFilter, ok := filter.(*netlink.BpfFilter)
	if !ok || !bpfFilter.DirectAction {
		return false
	}
	attrs := bpfFilter.Attrs()
	major, minor := netlink.MajorMinor(attrs.Handle)
	if attrs.Protocol != unix.ETH_P_ALL {
		return false
	}
	if major == 0 && minor == 1 && attrs.Priority == 0 {
		return parent == netlink.HANDLE_MIN_INGRESS && bpfFilter.Name == consts.AppName+"_ingress" ||
			parent == netlink.HANDLE_MIN_EGRESS && bpfFilter.Name == consts.AppName+"_egress"
	}
	if major != 0x2023 || minor < 1 || minor > 5 {
		return false
	}
	nameMatches := func(base string) bool {
		return bpfFilter.Name == base || bpfFilter.Name == base+"_l2" || bpfFilter.Name == base+"_l3"
	}
	switch {
	case nameMatches(consts.AppName + "_lan_ingress"):
		return parent == netlink.HANDLE_MIN_INGRESS && attrs.Priority == 2
	case nameMatches(consts.AppName + "_lan_egress"):
		return parent == netlink.HANDLE_MIN_EGRESS && attrs.Priority == 1
	case nameMatches(consts.AppName + "_wan_ingress"):
		return parent == netlink.HANDLE_MIN_INGRESS && attrs.Priority == 1
	case nameMatches(consts.AppName + "_wan_egress"):
		return parent == netlink.HANDLE_MIN_EGRESS && (attrs.Priority == 1 || attrs.Priority == 2)
	default:
		return false
	}
}

func cleanupLegacyTCFilters() error {
	links, err := netlink.LinkList()
	if err != nil {
		return oops.Errorf("list interfaces for legacy TC cleanup: %w", err)
	}
	for _, link := range links {
		if err := cleanupLegacyTCFiltersOnLink(link); err != nil {
			return err
		}
	}
	return nil
}

func cleanupLegacyTCFiltersOnLink(link netlink.Link) error {
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		filters, err := netlink.FilterList(link, parent)
		if err != nil {
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.EINVAL) {
				continue
			}
			return oops.Errorf("list legacy TC filters on %s: %w", link.Attrs().Name, err)
		}
		for _, filter := range filters {
			if !legacyTCFilter(filter, parent) {
				continue
			}
			if err := netlink.FilterDel(filter); err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENODEV) {
				return oops.Errorf("delete legacy TC filter on %s: %w", link.Attrs().Name, err)
			}
		}
	}
	return nil
}

func (role hostTCXRole) attachType() ebpf.AttachType {
	switch role {
	case hostTCXLanIngress, hostTCXWanIngress:
		return ebpf.AttachTCXIngress
	case hostTCXLanEgress, hostTCXWanEgress:
		return ebpf.AttachTCXEgress
	default:
		panic("invalid host TCX role")
	}
}

func (role hostTCXRole) String() string {
	switch role {
	case hostTCXLanIngress:
		return "LAN ingress"
	case hostTCXLanEgress:
		return "LAN egress"
	case hostTCXWanIngress:
		return "WAN ingress"
	case hostTCXWanEgress:
		return "WAN egress"
	default:
		return "unknown"
	}
}

func (c *controlPlaneCore) attachHostTCXProgram(linkIndex int, spec hostTCXProgram) (bool, error) {
	if _, exists := c.hostTCXLink(linkIndex, spec.role); exists {
		return false, nil
	}

	var companionRole hostTCXRole
	var before bool
	switch spec.role {
	case hostTCXLanIngress:
		companionRole, before = hostTCXWanIngress, false
	case hostTCXLanEgress:
		companionRole, before = hostTCXWanEgress, true
	case hostTCXWanIngress:
		companionRole, before = hostTCXLanIngress, true
	case hostTCXWanEgress:
		companionRole, before = hostTCXLanEgress, false
	default:
		return false, oops.Errorf("invalid host TCX role %d", spec.role)
	}

	// Keep programs that were attached before dae ahead of its pair.
	anchor := ciliumLink.Anchor(ciliumLink.Tail())
	if companion, exists := c.hostTCXLink(linkIndex, companionRole); exists {
		if before {
			anchor = ciliumLink.BeforeLink(companion)
		} else {
			anchor = ciliumLink.AfterLink(companion)
		}
	}
	attached, err := ciliumLink.AttachTCX(ciliumLink.TCXOptions{
		Interface: linkIndex,
		Program:   spec.program,
		Attach:    spec.role.attachType(),
		Anchor:    anchor,
	})
	if err != nil {
		return false, oops.Errorf("attach %s TCX program: %w", spec.role, err)
	}
	if !c.ownHostTCXLink(hostTCXLink{
		linkIndex: linkIndex,
		role:      spec.role,
		link:      attached,
		close:     attached.Close,
	}) {
		return false, attached.Close()
	}
	return true, nil
}

func (c *controlPlaneCore) migrateHostTCXPrograms(link netlink.Link, programs ...hostTCXProgram) error {
	linkIndex := link.Attrs().Index
	attachedRoles := make([]hostTCXRole, 0, len(programs))
	rollback := func(err error) error {
		if len(attachedRoles) == 0 {
			return err
		}
		return errors.Join(err, c.closeHostTCXLinks(linkIndex, attachedRoles...))
	}
	for _, program := range programs {
		attached, err := c.attachHostTCXProgram(linkIndex, program)
		if err != nil {
			return rollback(err)
		}
		if attached {
			attachedRoles = append(attachedRoles, program.role)
		}
	}
	return nil
}

// bindLan supports lazy binding and rebinding for matching LAN interfaces.
func (c *controlPlaneCore) bindLan(pattern string, autoConfigKernelParameter bool) error {
	bind := func(link netlink.Link) error {
		return c.prepareAndBindLanLink(link, autoConfigKernelParameter)
	}
	initlinkCallback := func(link netlink.Link) error {
		if link.Attrs().Name == hostLinkName {
			return nil
		}
		if err := bind(link); err != nil {
			var notFound netlink.LinkNotFoundError
			if errors.As(err, &notFound) {
				log.Debugf("Skip disappeared LAN interface %s", link.Attrs().Name)
				return nil
			}
			return oops.Errorf("bind LAN interface %s: %w", link.Attrs().Name, err)
		}
		return nil
	}
	newlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == hostLinkName {
			return
		}
		log.Warnf("New link creation of '%v' is detected. Bind LAN program to it.", link.Attrs().Name)
		if err := initlinkCallback(link); err != nil {
			log.Errorf("bind LAN interface %s: %v", link.Attrs().Name, err)
		}
	}
	dellinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == hostLinkName {
			return
		}
		c.mu.Lock()
		if err := c.closeHostTCXLinks(link.Attrs().Index, hostTCXLanIngress, hostTCXLanEgress); err != nil {
			log.Errorf("close TCX links on deleted LAN interface %s: %v", link.Attrs().Name, err)
		}
		c.mu.Unlock()
		log.Warnf("Link deletion of '%v' is detected. Bind LAN program to it once it is re-created.", link.Attrs().Name)
	}
	return c.ifmgr.RegisterWithPatternSync(pattern, initlinkCallback, newlinkCallback, dellinkCallback)
}

func (c *controlPlaneCore) prepareAndBindLanLink(link netlink.Link, autoConfigKernelParameter bool) error {
	if autoConfigKernelParameter {
		SetSendRedirects(link.Attrs().Name, "0")
		SetForwarding(link.Attrs().Name, "1")
	}
	return c.bindLanLink(link)
}

func (c *controlPlaneCore) bindLanLink(linkSnapshot netlink.Link) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	ifname := linkSnapshot.Attrs().Name
	log.Infof("Bind to LAN: %v", ifname)

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	if err := CheckIpforward(ifname); err != nil {
		return err
	}
	if err := CheckSendRedirects(ifname); err != nil {
		return err
	}
	var ingressProgram, egressProgram *ebpf.Program
	if linkHdrLen(link) > 0 {
		ingressProgram = c.bpf.bpfPrograms.LanIngressL2
		egressProgram = c.bpf.bpfPrograms.LanEgressL2
	} else {
		ingressProgram = c.bpf.bpfPrograms.LanIngressL3
		egressProgram = c.bpf.bpfPrograms.LanEgressL3
	}
	return c.migrateHostTCXPrograms(link,
		hostTCXProgram{role: hostTCXLanIngress, program: ingressProgram},
		hostTCXProgram{role: hostTCXLanEgress, program: egressProgram},
	)
}

func (c *controlPlaneCore) setupSkPidMonitor() error {
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
			return oops.Wrapf(err, "AttachCgroup: %v", prog.Prog.String())
		}
		c.addCleanup(func() error {
			return oops.Wrapf(attached.Close(), "inet6Bind.Close()")
		})
	}
	return nil
}

func (c *controlPlaneCore) setupExitHandler() (err error) {
	if exitHandlerClose != nil {
		exitHandlerClose()
	}
	link, err := ciliumLink.Tracepoint("sched", "sched_process_exit", c.bpf.HandleExit, nil)
	if err != nil {
		return oops.Errorf("Tracepoint: %w", err)
	}
	exitHandlerClose = link.Close
	return nil
}

// bindWan registers manual ownership. TC changes are serialized by the WAN
// reconciler instead of running in interface callbacks.
func (c *controlPlaneCore) bindWan(pattern string, prepare func(string)) error {
	set := func(link netlink.Link) {
		if link.Attrs().Name == hostLinkName {
			return
		}
		if link.Attrs().Index == consts.LoopbackIfIndex {
			log.Errorf("cannot bind WAN to loopback interface")
			return
		}
		if prepare != nil {
			prepare(link.Attrs().Name)
		}
		c.setManualWan(link, pattern, true)
	}
	return c.ifmgr.RegisterWithPatternSync(pattern, func(link netlink.Link) error {
		set(link)
		return nil
	}, func(link netlink.Link) {
		log.Warnf("New link creation of '%v' is detected. Bind WAN program to it.", link.Attrs().Name)
		set(link)
	}, func(link netlink.Link) {
		c.removeWanLink(link, pattern)
		log.Warnf("Link deletion of '%v' is detected. Bind WAN program to it once it is re-created.", link.Attrs().Name)
	})
}

func (c *controlPlaneCore) removeWanLink(link netlink.Link, pattern string) {
	// This callback also represents a rename that stopped matching one
	// pattern. Update only that owner; the global DELLINK callback handles
	// physical deletion, and reconciliation detaches after all owners update.
	c.setManualWan(link, pattern, false)
}

func (c *controlPlaneCore) invalidateWanLink(link netlink.Link) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.closeHostTCXLinks(link.Attrs().Index, hostTCXWanIngress, hostTCXWanEgress); err != nil {
		log.Errorf("close TCX links on deleted WAN interface %s: %v", link.Attrs().Name, err)
	}
}

func (c *controlPlaneCore) setManualWan(link netlink.Link, pattern string, present bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Err() != nil {
		return
	}
	index := link.Attrs().Index
	if present && index == consts.LoopbackIfIndex {
		return
	}
	binding := c.wanBindings[index]
	if !present {
		if binding != nil && binding.ifname == link.Attrs().Name {
			delete(binding.manualPatterns, pattern)
		}
		return
	}
	if binding == nil {
		binding = &wanBinding{manualPatterns: make(map[string]struct{})}
		c.wanBindings[index] = binding
	}
	if binding.ifname != "" && binding.ifname != link.Attrs().Name {
		clear(binding.manualPatterns)
	}
	binding.ifname = link.Attrs().Name
	binding.manualPatterns[pattern] = struct{}{}
}

func autoWanTargets(snapshot component.HostNetworkSnapshot) map[int]string {
	desired := make(map[int]string, len(snapshot.Interfaces))
	for _, intf := range snapshot.Interfaces {
		if intf.Index != consts.LoopbackIfIndex && (intf.IPv4Default || intf.IPv6Default) {
			desired[intf.Index] = intf.Name
		}
	}
	return desired
}

// reconcileWan attaches every required interface before dropping obsolete
// automatic ownership, avoiding an interception gap during route replacement.
// A nil snapshot retries existing state without changing automatic ownership.
func (c *controlPlaneCore) reconcileWan(snapshot *component.HostNetworkSnapshot) (retry bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Err() != nil {
		return false
	}
	var desired map[int]string
	if snapshot != nil {
		desired = autoWanTargets(*snapshot)
		for index, ifname := range desired {
			binding := c.wanBindings[index]
			if binding == nil {
				binding = &wanBinding{ifname: ifname, manualPatterns: make(map[string]struct{})}
				c.wanBindings[index] = binding
			}
		}
	}

	autoReady := true
	for index, binding := range c.wanBindings {
		_, wantedAutomatically := desired[index]
		required := len(binding.manualPatterns) > 0 || binding.automatic
		if snapshot != nil {
			required = len(binding.manualPatterns) > 0 || wantedAutomatically
		}
		if !required {
			continue
		}
		link, err := netlink.LinkByIndex(index)
		if err != nil {
			log.Debugf("WAN link %d is no longer present: %v", index, err)
			retry = true
			if wantedAutomatically {
				autoReady = false
			}
			continue
		}
		if wantedName := desired[index]; wantedName != "" && wantedName != link.Attrs().Name {
			log.Debugf("WAN link %d changed from %q to %q", index, wantedName, link.Attrs().Name)
			retry = true
			autoReady = false
			continue
		}
		// TC filters are attached by ifindex and remain valid across a rename.
		binding.ifname = link.Attrs().Name
		if !c.wanAttached(index) {
			if err := c.attachWanLocked(link, binding); err != nil {
				log.Errorf("bind WAN %v: %v", binding.ifname, err)
				retry = true
				if wantedAutomatically {
					autoReady = false
				}
			}
		}
	}

	if snapshot != nil && autoReady {
		for index, binding := range c.wanBindings {
			_, binding.automatic = desired[index]
		}
	}
	for index, binding := range c.wanBindings {
		_, provisionalAuto := desired[index]
		if binding.automatic || len(binding.manualPatterns) > 0 || !autoReady && provisionalAuto {
			continue
		}
		if err := c.detachWanLocked(index, binding); err != nil {
			log.Errorf("unbind obsolete WAN %d: %v", index, err)
			retry = true
			continue
		}
		delete(c.wanBindings, index)
	}
	return retry
}

func (c *controlPlaneCore) wanAttached(linkIndex int) bool {
	_, ingress := c.hostTCXLink(linkIndex, hostTCXWanIngress)
	_, egress := c.hostTCXLink(linkIndex, hostTCXWanEgress)
	return ingress && egress
}

func (c *controlPlaneCore) detachWanLocked(linkIndex int, binding *wanBinding) error {
	log.Infof("Unbind from WAN: %v", binding.ifname)
	return c.closeHostTCXLinks(linkIndex, hostTCXWanIngress, hostTCXWanEgress)
}

func (c *controlPlaneCore) attachWanLocked(link netlink.Link, binding *wanBinding) error {
	ifname := link.Attrs().Name
	log.Infof("Bind to WAN: %v", ifname)
	if link.Attrs().Index == consts.LoopbackIfIndex {
		return oops.Errorf("cannot bind to loopback interface")
	}

	var ingressProgram, egressProgram *ebpf.Program
	if linkHdrLen(link) > 0 {
		ingressProgram = c.bpf.bpfPrograms.TproxyWanIngressL2
		egressProgram = c.bpf.bpfPrograms.TproxyWanEgressL2
	} else {
		ingressProgram = c.bpf.bpfPrograms.TproxyWanIngressL3
		egressProgram = c.bpf.bpfPrograms.TproxyWanEgressL3
	}
	return c.migrateHostTCXPrograms(link,
		hostTCXProgram{role: hostTCXWanEgress, program: egressProgram},
		hostTCXProgram{role: hostTCXWanIngress, program: ingressProgram},
	)
}

func (c *controlPlaneCore) bindDaens() (err error) {
	daens := GetDaeNetns()
	links := make([]ciliumLink.Link, 0, 3)
	defer func() {
		if err != nil {
			err = errors.Join(err, closeBpfLinks(links))
			return
		}
		c.addCleanup(func() error { return closeBpfLinks(links) })
	}()

	skLookupLink, err := ciliumLink.AttachNetNs(int(daens.daeNs), c.bpf.bpfPrograms.TproxySkLookup)
	if err != nil {
		return oops.Errorf("attach SK_LOOKUP program to dae netns: %w", err)
	}
	links = append(links, skLookupLink)

	primaryLink, err := ciliumLink.AttachNetkit(ciliumLink.NetkitOptions{
		Interface: daens.Dae0().Attrs().Index,
		Program:   c.bpf.bpfPrograms.TproxyDae0peerIngress,
		Attach:    ebpf.AttachNetkitPrimary,
	})
	if err != nil {
		return oops.Errorf("attach primary Netkit program: %w", err)
	}
	links = append(links, primaryLink)

	peerLink, err := ciliumLink.AttachNetkit(ciliumLink.NetkitOptions{
		Interface: daens.Dae0().Attrs().Index,
		Program:   c.bpf.bpfPrograms.TproxyDae0Ingress,
		Attach:    ebpf.AttachNetkitPeer,
	})
	if err != nil {
		return oops.Errorf("attach peer Netkit program: %w", err)
	}
	links = append(links, peerLink)
	return nil
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
// Failures panic (see panicDomainMapWrite).
func (c *controlPlaneCore) writeDomainBitmaps(ip netip.Addr, bump, routing []uint32) {
	var value bpfDomainRouting
	if consts.MaxMatchSetLen/32 != len(value.Bump) || len(bump) != len(value.Bump) || len(routing) != len(value.Routing) {
		panic("domain bitmap length not sync with kern program")
	}
	copy(value.Bump[:], bump)
	copy(value.Routing[:], routing)

	ip6 := ip.As16()
	key := common.Ipv6ByteSliceToUint32Array(ip6[:])
	if err := c.bpf.DomainRoutingMap.Update(key, value, ebpf.UpdateAny); err != nil {
		panicDomainMapWrite("DomainRoutingMap.Update", ip, err)
	}
}

// panicDomainMapWrite panics on a kernel domain-map write failure. Such a
// failure indicates a logic bug (e.g. bitmap length drift) or bpf state
// tampered with externally (e.g. another process pinning its maps over
// ours); neither is recoverable at runtime, and silently degrading domain
// routing would be far harder to diagnose.
func panicDomainMapWrite(op string, ip netip.Addr, err error) {
	panic(oops.Wrapf(err, op+"(%v): kernel domain map write failed (logic bug, or the bpf maps were tampered with externally)", ip))
}

// deleteDomainBitmaps removes ip from the kernel domain map. It is bound
// to domainRegistry.remove. A missing key is tolerated (the desired end
// state is already reached); any other failure panics.
func (c *controlPlaneCore) deleteDomainBitmaps(ip netip.Addr) {
	ip6 := ip.As16()
	key := common.Ipv6ByteSliceToUint32Array(ip6[:])
	if err := c.bpf.DomainRoutingMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		panicDomainMapWrite("DomainRoutingMap.Delete", ip, err)
	}
}

// EjectBpf releases this core's cleanup ownership so Close will not destroy the
// BPF objects. They remain unowned until a core later calls InjectBpf.
func (c *controlPlaneCore) EjectBpf() *bpfState {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bpfOwned = false
	return c.bpf
}

// InjectBpf makes this core responsible for closing the BPF objects.
func (c *controlPlaneCore) InjectBpf() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bpfOwned = true
}
