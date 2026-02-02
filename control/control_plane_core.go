/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"github.com/mohae/deepcopy"
	"github.com/safchain/ethtool"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// coreFlip should be 0 or 1
var coreFlip = 0
var exitHandlerClose func() error

type controlPlaneCore struct {
	mu          sync.Mutex
	lifecycleMu sync.Mutex
	closeOnce   sync.Once
	closeErr    error

	cleanupMu      sync.Mutex
	deferFuncs     []func() error
	filterCleanups map[filterCleanupKey]func() error
	filterOrder    []filterCleanupKey
	bpf            *bpfObjects

	kernelVersion *internal.Version

	flip     int
	isReload bool
	// bpfOwned reports whether this core currently owns the bpf objects and
	// closes them on Close. At most one core owns them at any time; the
	// ownership moves to the next plane via EjectBpf/InjectBpf on reload.
	bpfOwned bool

	// domainRegistry tracks every (domain, qtype) -> IP registration learned
	// from DNS. It is the single source of truth for domain_routing_map in
	// eBPF; every mutation atomically replaces the affected IP's combined
	// bump/routing value, so user space and BPF stay in sync.
	domainRegistry *DomainRegistry

	closed context.Context
	close  context.CancelFunc
	ifmgr  *component.InterfaceManager

	// outboundConnectivityMap stores actual outbound liveness, indexed by
	// [outbound][NetworkTypeToIndex]. It is written by the same callback that
	// maintains the eBPF outbound_connectivity_map and read by the userspace
	// routing matcher to evaluate skip_while_noalive rules without BPF map
	// lookups in the hot path. A zero-valued bool also represents a state that
	// has not been reported yet, which is conservatively treated as unusable.
	outboundConnectivityMap [consts.OutboundUserDefinedMax + 1][4]atomic.Bool
}

type filterCleanupKey struct {
	namespace string
	linkIndex int
	parent    uint32
	handle    uint32
}

func newControlPlaneCore(
	bpf *bpfObjects,
	kernelVersion *internal.Version,
	isReload bool,
) *controlPlaneCore {
	if isReload {
		coreFlip = coreFlip&1 ^ 1
	}
	closed, toClose := context.WithCancel(context.Background())
	ifmgr := component.NewInterfaceManager()
	core := &controlPlaneCore{
		bpf:           bpf,
		kernelVersion: kernelVersion,
		flip:          coreFlip,
		isReload:      isReload,
		// A core built for a reload does not own the bpf objects yet — they
		// are still owned by the previously running core; it takes over the
		// ownership via InjectBpf when the reload commits.
		bpfOwned:       !isReload,
		ifmgr:          ifmgr,
		closed:         closed,
		close:          toClose,
		filterCleanups: make(map[filterCleanupKey]func() error),
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
	return core
}

func (c *controlPlaneCore) addCleanup(cleanup func() error) {
	c.cleanupMu.Lock()
	c.deferFuncs = append(c.deferFuncs, cleanup)
	c.cleanupMu.Unlock()
}

func (c *controlPlaneCore) ownFilter(key filterCleanupKey, cleanup func() error) {
	c.cleanupMu.Lock()
	if _, exists := c.filterCleanups[key]; !exists {
		c.filterOrder = append(c.filterOrder, key)
	}
	c.filterCleanups[key] = cleanup
	c.cleanupMu.Unlock()
}

func (c *controlPlaneCore) releaseLinkFilters(namespace string, linkIndex int) {
	c.cleanupMu.Lock()
	for key := range c.filterCleanups {
		if key.namespace == namespace && key.linkIndex == linkIndex {
			delete(c.filterCleanups, key)
		}
	}
	kept := c.filterOrder[:0]
	for _, key := range c.filterOrder {
		if key.namespace != namespace || key.linkIndex != linkIndex {
			kept = append(kept, key)
		}
	}
	c.filterOrder = kept
	c.cleanupMu.Unlock()
}

func (c *controlPlaneCore) takeCleanups() []func() error {
	c.cleanupMu.Lock()
	defer c.cleanupMu.Unlock()

	cleanups := make([]func() error, 0, len(c.filterCleanups)+len(c.deferFuncs))
	for i := len(c.filterOrder) - 1; i >= 0; i-- {
		if cleanup := c.filterCleanups[c.filterOrder[i]]; cleanup != nil {
			cleanups = append(cleanups, cleanup)
		}
	}
	for i := len(c.deferFuncs) - 1; i >= 0; i-- {
		cleanups = append(cleanups, c.deferFuncs[i])
	}
	c.filterCleanups = nil
	c.filterOrder = nil
	c.deferFuncs = nil
	return cleanups
}

func hostFilterCleanupKey(filter *netlink.BpfFilter) filterCleanupKey {
	attrs := filter.Attrs()
	return filterCleanupKey{
		namespace: "host",
		linkIndex: attrs.LinkIndex,
		parent:    attrs.Parent,
		handle:    attrs.Handle,
	}
}

func filterAlreadyGone(err error) bool {
	return errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV)
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

func (c *controlPlaneCore) Flip() {
	coreFlip = coreFlip&1 ^ 1
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
		c.closeErr = c.ifmgr.Close()
		// Interface callbacks can register filter ownership. Waiting for the
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

func getIfParamsFromLink(link netlink.Link) (ifParams bpfIfParams, err error) {
	et, err := ethtool.NewEthtool()
	if err != nil {
		return bpfIfParams{}, err
	}
	defer et.Close()
	features, err := et.Features(link.Attrs().Name)
	if err != nil {
		return bpfIfParams{}, err
	}
	if features["tx-checksum-ip-generic"] {
		ifParams.TxL4CksmIp4Offload = true
		ifParams.TxL4CksmIp6Offload = true
	}
	if features["tx-checksum-ipv4"] {
		ifParams.TxL4CksmIp4Offload = true
	}
	if features["tx-checksum-ipv6"] {
		ifParams.TxL4CksmIp6Offload = true
	}
	if features["rx-checksum"] {
		ifParams.RxCksmOffload = true
	}
	switch {
	case regexp.MustCompile(`^docker\d+$`).MatchString(link.Attrs().Name):
		ifParams.UseNonstandardOffloadAlgorithm = true
	default:
	}
	return ifParams, nil
}

func (c *controlPlaneCore) linkHdrLen(ifname string) (uint32, error) {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return 0, err
	}
	var linkHdrLen uint32
	switch link.Attrs().EncapType {
	case "none", "ipip", "ppp", "tun":
		linkHdrLen = consts.LinkHdrLen_None
	case "ether":
		linkHdrLen = consts.LinkHdrLen_Ethernet
	default:
		log.Warnf("Maybe unsupported link type %v, using default link header length", link.Attrs().EncapType)
		linkHdrLen = consts.LinkHdrLen_Ethernet
	}
	return linkHdrLen, nil
}

func (c *controlPlaneCore) addQdisc(ifname string) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return oops.Errorf("cannot add clsact qdisc: %w", err)
	}
	return nil
}

func (c *controlPlaneCore) delQdisc(ifname string) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscDel(qdisc); err != nil {
		if !os.IsExist(err) {
			return oops.Errorf("cannot add clsact qdisc: %w", err)
		}
	}
	return nil
}

// bindLan automatically configures kernel parameters and bind to lan interface `ifname`.
// bindLan supports lazy-bind if interface `ifname` is not found.
// bindLan supports rebinding when the interface `ifname` is detected in the future.
func (c *controlPlaneCore) bindLan(ifname string, autoConfigKernelParameter bool) {
	initlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		if autoConfigKernelParameter {
			SetSendRedirects(link.Attrs().Name, "0")
			SetForwarding(link.Attrs().Name, "1")
		}
		if err := c._bindLan(link.Attrs().Name); err != nil {
			log.Errorf("bindLan: %v", err)
		}
	}
	newlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		log.Warnf("New link creation of '%v' is detected. Bind LAN program to it.", link.Attrs().Name)
		if err := c.addQdisc(link.Attrs().Name); err != nil {
			log.Errorf("addQdisc: %v", err)
			return
		}
		initlinkCallback(link)
	}
	dellinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.releaseLinkFilters("host", link.Attrs().Index)
		log.Warnf("Link deletion of '%v' is detected. Bind LAN program to it once it is re-created.", link.Attrs().Name)
	}
	c.ifmgr.RegisterWithPattern(ifname, initlinkCallback, newlinkCallback, dellinkCallback)
}

func (c *controlPlaneCore) _bindLan(ifname string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	log.Infof("Bind to LAN: %v", ifname)

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	if err = CheckIpforward(ifname); err != nil {
		return err
	}
	if err = CheckSendRedirects(ifname); err != nil {
		return err
	}
	_ = c.addQdisc(ifname)
	linkHdrLen, err := c.linkHdrLen(ifname)
	if err != nil {
		return err
	}
	ifParams, err := getIfParamsFromLink(link)
	if err != nil {
		return err
	}
	if err = ifParams.CheckVersionRequirement(c.kernelVersion); err != nil {
		return err
	}

	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b100+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			// Priority should be behind of WAN's
			Priority: 2,
		},
		Name:         consts.AppName + "_lan_ingress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterIngress.Fd = c.bpf.bpfPrograms.LanIngressL2.FD()
		filterIngress.Name = filterIngress.Name + "_l2"
	} else {
		filterIngress.Fd = c.bpf.bpfPrograms.LanIngressL3.FD()
		filterIngress.Name = filterIngress.Name + "_l3"
	}
	_ = netlink.FilterDel(filterIngress)
	if !c.isReload {
		// Clean up thoroughly.
		filterIngressFlipped := deepcopy.Copy(filterIngress).(*netlink.BpfFilter)
		filterIngressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterIngressFlipped)
	}
	if err := netlink.FilterAdd(filterIngress); err != nil {
		return oops.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	c.ownFilter(hostFilterCleanupKey(filterIngress), func() error {
		if err := netlink.FilterDel(filterIngress); err != nil && !filterAlreadyGone(err) {
			return oops.Errorf("FilterDel(%v:%v): %w", ifname, filterIngress.Name, err)
		}
		return nil
	})

	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			// Priority should be front of WAN's
			Priority: 1,
		},
		Name:         consts.AppName + "_lan_egress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterEgress.Fd = c.bpf.bpfPrograms.LanEgressL2.FD()
		filterEgress.Name = filterEgress.Name + "_l2"
	} else {
		filterEgress.Fd = c.bpf.bpfPrograms.LanEgressL3.FD()
		filterEgress.Name = filterEgress.Name + "_l3"
	}
	_ = netlink.FilterDel(filterEgress)
	if !c.isReload {
		// Clean up thoroughly.
		filterEgressFlipped := deepcopy.Copy(filterEgress).(*netlink.BpfFilter)
		filterEgressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterEgressFlipped)
	}
	if err := netlink.FilterAdd(filterEgress); err != nil {
		return oops.Errorf("cannot attach ebpf object to filter egress: %w", err)
	}
	c.ownFilter(hostFilterCleanupKey(filterEgress), func() error {
		if err := netlink.FilterDel(filterEgress); err != nil && !filterAlreadyGone(err) {
			return oops.Errorf("FilterDel(%v:%v): %w", ifname, filterEgress.Name, err)
		}
		return nil
	})

	return nil
}

func (c *controlPlaneCore) setupSkPidMonitor() error {
	/// Set-up SrcPidMapper to support pname routing.
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		return err
	}
	type cgProg struct {
		Name   string
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

// bindWan supports lazy-bind if interface `ifname` is not found.
// bindWan supports rebinding when the interface `ifname` is detected in the future.
func (c *controlPlaneCore) bindWan(ifname string, autoConfigKernelParameter bool) {
	initlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		if err := c._bindWan(link.Attrs().Name); err != nil {
			log.Errorf("bindWan: %v", err)
		}
	}
	newlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		log.Warnf("New link creation of '%v' is detected. Bind WAN program to it.", link.Attrs().Name)
		if err := c.addQdisc(link.Attrs().Name); err != nil {
			log.Errorf("addQdisc: %v", err)
			return
		}
		initlinkCallback(link)
	}
	dellinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.releaseLinkFilters("host", link.Attrs().Index)
		log.Warnf("Link deletion of '%v' is detected. Bind WAN program to it once it is re-created.", link.Attrs().Name)
	}
	c.ifmgr.RegisterWithPattern(ifname, initlinkCallback, newlinkCallback, dellinkCallback)
}

func (c *controlPlaneCore) _bindWan(ifname string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	log.Infof("Bind to WAN: %v", ifname)
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	if link.Attrs().Index == consts.LoopbackIfIndex {
		return oops.Errorf("cannot bind to loopback interface")
	}
	_ = c.addQdisc(ifname)
	linkHdrLen, err := c.linkHdrLen(ifname)
	if err != nil {
		return err
	}

	ifParams, err := getIfParamsFromLink(link)
	if err != nil {
		return err
	}
	if err = ifParams.CheckVersionRequirement(c.kernelVersion); err != nil {
		return err
	}

	/// Set-up WAN ingress/egress TC programs.
	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b100+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  2,
		},
		Name:         consts.AppName + "_wan_egress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterEgress.Fd = c.bpf.bpfPrograms.TproxyWanEgressL2.FD()
		filterEgress.Name = filterEgress.Name + "_l2"
	} else {
		filterEgress.Fd = c.bpf.bpfPrograms.TproxyWanEgressL3.FD()
		filterEgress.Name = filterEgress.Name + "_l3"
	}
	_ = netlink.FilterDel(filterEgress)
	if !c.isReload {
		// Clean up thoroughly.
		filterEgressFlipped := deepcopy.Copy(filterEgress).(*netlink.BpfFilter)
		filterEgressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterEgressFlipped)
	}
	if err := netlink.FilterAdd(filterEgress); err != nil {
		return oops.Errorf("cannot attach ebpf object to filter egress: %w", err)
	}
	c.ownFilter(hostFilterCleanupKey(filterEgress), func() error {
		if err := netlink.FilterDel(filterEgress); err != nil && !filterAlreadyGone(err) {
			return oops.Errorf("FilterDel(%v:%v): %w", ifname, filterEgress.Name, err)
		}
		return nil
	})

	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Name:         consts.AppName + "_wan_ingress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterIngress.Fd = c.bpf.bpfPrograms.TproxyWanIngressL2.FD()
		filterIngress.Name = filterIngress.Name + "_l2"
	} else {
		filterIngress.Fd = c.bpf.bpfPrograms.TproxyWanIngressL3.FD()
		filterIngress.Name = filterIngress.Name + "_l3"
	}
	_ = netlink.FilterDel(filterIngress)
	if !c.isReload {
		// Clean up thoroughly.
		filterIngressFlipped := deepcopy.Copy(filterIngress).(*netlink.BpfFilter)
		filterIngressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterIngressFlipped)
	}
	if err := netlink.FilterAdd(filterIngress); err != nil {
		return oops.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	c.ownFilter(hostFilterCleanupKey(filterIngress), func() error {
		if err := netlink.FilterDel(filterIngress); err != nil && !filterAlreadyGone(err) {
			return oops.Errorf("FilterDel(%v:%v): %w", ifname, filterIngress.Name, err)
		}
		return nil
	})

	return nil
}

func (c *controlPlaneCore) bindDaens() (err error) {
	daens := GetDaeNetns()

	// tproxy_dae0peer_ingress@eth0 at dae netns
	daens.With(func() error {
		return c.addQdisc(daens.Dae0Peer().Attrs().Name)
	})
	filterDae0peerIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: daens.Dae0Peer().Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2022, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  0,
		},
		Fd:           c.bpf.bpfPrograms.TproxyDae0peerIngress.FD(),
		Name:         consts.AppName + "_dae0peer_ingress",
		DirectAction: true,
	}
	daens.With(func() error {
		return netlink.FilterDel(filterDae0peerIngress)
	})
	if !c.isReload {
		// Clean up thoroughly.
		filterIngressFlipped := deepcopy.Copy(filterDae0peerIngress).(*netlink.BpfFilter)
		filterIngressFlipped.FilterAttrs.Handle ^= 1
		daens.With(func() error {
			return netlink.FilterDel(filterIngressFlipped)
		})
	}
	if err = daens.With(func() error {
		return netlink.FilterAdd(filterDae0peerIngress)
	}); err != nil {
		return oops.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	daePeerKey := hostFilterCleanupKey(filterDae0peerIngress)
	daePeerKey.namespace = "dae"
	c.ownFilter(daePeerKey, func() error {
		if err := daens.With(func() error {
			return netlink.FilterDel(filterDae0peerIngress)
		}); err != nil && !filterAlreadyGone(err) {
			return oops.Errorf("FilterDel(%v:%v): %w", daens.Dae0Peer().Attrs().Name, filterDae0peerIngress.Name, err)
		}
		return nil
	})

	// tproxy_dae0_ingress@dae0 at host netns
	c.addQdisc(daens.Dae0().Attrs().Name)
	filterDae0Ingress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: daens.Dae0().Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2022, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  0,
		},
		Fd:           c.bpf.bpfPrograms.TproxyDae0Ingress.FD(),
		Name:         consts.AppName + "_dae0_ingress",
		DirectAction: true,
	}
	_ = netlink.FilterDel(filterDae0Ingress)
	if !c.isReload {
		// Clean up thoroughly.
		filterEgressFlipped := deepcopy.Copy(filterDae0Ingress).(*netlink.BpfFilter)
		filterEgressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterEgressFlipped)
	}
	if err := netlink.FilterAdd(filterDae0Ingress); err != nil {
		return oops.Errorf("cannot attach ebpf object to filter egress: %w", err)
	}
	c.ownFilter(hostFilterCleanupKey(filterDae0Ingress), func() error {
		if err := netlink.FilterDel(filterDae0Ingress); err != nil && !filterAlreadyGone(err) {
			return oops.Errorf("FilterDel(%v:%v): %w", daens.Dae0().Attrs().Name, filterDae0Ingress.Name, err)
		}
		return nil
	})
	return
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

// EjectBpf removes the bpf objects from this core's ownership so its Close
// will not destroy them; the successor core takes them over via InjectBpf.
func (c *controlPlaneCore) EjectBpf() *bpfObjects {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bpfOwned = false
	return c.bpf
}

// InjectBpf will inject bpf back.
func (c *controlPlaneCore) InjectBpf() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bpfOwned = true
}
