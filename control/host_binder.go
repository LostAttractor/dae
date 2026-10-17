// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path"
	"sync"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/network"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// hostBinder serializes host attachment changes and owns this plane's WAN
// intent. Runtime owns the links themselves across configuration generations.
// Shutdown cancels closed and joins interface callbacks before BPF is released.
type hostBinder struct {
	*kernelLinks
	mu          sync.Mutex
	bpf         *BPFState
	ifmgr       *network.InterfaceScope
	closed      context.Context
	wanBindings map[int]*wanBinding
}

// quiesce joins attachment work after the owner cancels closed and stops
// interface callbacks. Later reconciliation observes cancellation under mu.
func (c *hostBinder) quiesce() {
	c.mu.Lock()
	c.mu.Unlock()
}

type hostTCXRole uint8

const (
	hostTCXLanIngress hostTCXRole = iota
	hostTCXLanEgress
	hostTCXWanIngress
	hostTCXWanEgress
)

type hostTCXLink struct {
	linkIndex  int
	role       hostTCXRole
	link       ciliumLink.Link
	program    *ebpf.Program
	close      func() error
	generation uint64
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

func (c *hostBinder) resetHostTCXLinks() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.kernelLinks.mu.Lock()
	links := c.hostTCXLinks
	c.hostTCXLinks = nil
	c.kernelLinks.mu.Unlock()
	for i := len(links) - 1; i >= 0; i-- {
		if err := links[i].close(); err != nil {
			log.WithError(err).WithFields(log.Fields{"interface_index": links[i].linkIndex, "role": links[i].role}).Error("Could not close stale TCX link")
		}
	}
}

func linkHdrLen(link netlink.Link) uint32 {
	switch link.Attrs().EncapType {
	case "none", "ipip", "ppp", "tun":
		return consts.LinkHdrLen_None
	case "ether":
		return consts.LinkHdrLen_Ethernet
	default:
		log.WithFields(log.Fields{"interface": link.Attrs().Name, "link_type": link.Attrs().EncapType}).Warn("Unknown link type; assuming Ethernet headers")
		return consts.LinkHdrLen_Ethernet
	}
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

func (role hostTCXRole) program(programs *bpfPrograms, ethernet bool) *ebpf.Program {
	switch role {
	case hostTCXLanIngress:
		if ethernet {
			return programs.LanIngressL2
		}
		return programs.LanIngressL3
	case hostTCXLanEgress:
		if ethernet {
			return programs.LanEgressL2
		}
		return programs.LanEgressL3
	case hostTCXWanIngress:
		if ethernet {
			return programs.TproxyWanIngressL2
		}
		return programs.TproxyWanIngressL3
	case hostTCXWanEgress:
		if ethernet {
			return programs.TproxyWanEgressL2
		}
		return programs.TproxyWanEgressL3
	default:
		panic("invalid host TCX role")
	}
}

func (c *hostBinder) program(role hostTCXRole, link netlink.Link) hostTCXProgram {
	return hostTCXProgram{role: role, program: role.program(&c.bpf.bpfPrograms, linkHdrLen(link) > 0)}
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

func (c *hostBinder) attachHostTCXProgram(linkIndex int, spec hostTCXProgram) (bool, error) {
	if found, err := c.updateHostTCXLink(linkIndex, spec); found || err != nil {
		return false, err
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
		return false, fmt.Errorf("invalid host TCX role %d", spec.role)
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
		return false, fmt.Errorf("attach %s TCX program: %w", spec.role, err)
	}
	if !c.ownHostTCXLink(hostTCXLink{
		linkIndex: linkIndex,
		role:      spec.role,
		link:      attached,
		program:   spec.program,
		close:     attached.Close,
	}) {
		return false, attached.Close()
	}
	return true, nil
}

func (c *hostBinder) migrateHostTCXPrograms(link netlink.Link, programs ...hostTCXProgram) error {
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
func (c *hostBinder) bindLan(pattern string, autoConfigKernelParameter bool) error {
	bind := func(link netlink.Link) error {
		return c.prepareAndBindLanLink(link, autoConfigKernelParameter)
	}
	initlinkCallback := func(link netlink.Link) error {
		if link.Attrs().Name == hostLinkName {
			return nil
		}
		if err := bind(link); err != nil {
			if linkSnapshotDisappeared(link, err, netlink.LinkByName) {
				log.Debugf("Skip disappeared LAN interface %s", link.Attrs().Name)
				return nil
			}
			return fmt.Errorf("bind LAN interface %s: %w", link.Attrs().Name, err)
		}
		return nil
	}
	newlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == hostLinkName {
			return
		}
		log.WithField("interface", link.Attrs().Name).Debug("LAN interface appeared")
		if err := initlinkCallback(link); err != nil {
			log.WithError(err).WithField("interface", link.Attrs().Name).Error("Could not attach LAN programs")
		}
	}
	dellinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == hostLinkName {
			return
		}
		c.mu.Lock()
		if err := c.closeHostTCXLinks(link.Attrs().Index, hostTCXLanIngress, hostTCXLanEgress); err != nil {
			log.WithError(err).WithField("interface", link.Attrs().Name).Error("Could not close TCX links on removed LAN interface")
		}
		c.mu.Unlock()
		log.WithField("interface", link.Attrs().Name).Info("LAN interface removed; waiting for it to reappear")
	}
	return c.ifmgr.RegisterWithPatternSync(pattern, initlinkCallback, newlinkCallback, dellinkCallback)
}

func linkSnapshotDisappeared(link netlink.Link, cause error, linkByName func(string) (netlink.Link, error)) bool {
	if _, ok := errors.AsType[interface {
		error
		Unwrap() []error
	}](cause); ok && !onlyLinkDisappearanceErrors(cause) {
		return false
	}
	if _, ok := errors.AsType[netlink.LinkNotFoundError](cause); ok {
		return true
	}
	if !errors.Is(cause, unix.ENOENT) {
		return false
	}
	current, err := linkByName(link.Attrs().Name)
	if _, ok := errors.AsType[netlink.LinkNotFoundError](err); ok || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) {
		return true
	}
	return err == nil && current != nil && current.Attrs() != nil &&
		current.Attrs().Index != link.Attrs().Index
}

func onlyLinkDisappearanceErrors(err error) bool {
	if joined, ok := errors.AsType[interface {
		error
		Unwrap() []error
	}](err); ok {
		for _, child := range joined.Unwrap() {
			if !onlyLinkDisappearanceErrors(child) {
				return false
			}
		}
		return true
	}
	_, notFound := errors.AsType[netlink.LinkNotFoundError](err)
	return notFound || errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.ENODEV)
}

func (c *hostBinder) prepareAndBindLanLink(link netlink.Link, autoConfigKernelParameter bool) error {
	if autoConfigKernelParameter {
		if err := SetSendRedirects(link.Attrs().Name, "0"); err != nil {
			return err
		}
		if err := SetForwarding(link.Attrs().Name, "1"); err != nil {
			return err
		}
	}
	return c.bindLanLink(link)
}

func (c *hostBinder) bindLanLink(linkSnapshot netlink.Link) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	ifname := linkSnapshot.Attrs().Name

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
	if err := c.migrateHostTCXPrograms(link,
		c.program(hostTCXLanIngress, link),
		c.program(hostTCXLanEgress, link),
	); err != nil {
		return err
	}
	log.WithField("interface", ifname).Info("Attached LAN programs")
	return nil
}

// bindWan registers manual ownership. TC changes are serialized by the WAN
// reconciler instead of running in interface callbacks.
func (c *hostBinder) bindWan(pattern string, prepare func(string) error) error {
	validLink := func(link netlink.Link) bool {
		if link.Attrs().Name == hostLinkName {
			return false
		}
		if link.Attrs().Index == consts.LoopbackIfIndex {
			log.Errorf("cannot bind WAN to loopback interface")
			return false
		}
		return true
	}
	return c.ifmgr.RegisterWithPatternSync(pattern, func(link netlink.Link) error {
		if !validLink(link) {
			return nil
		}
		if prepare != nil {
			if err := prepare(link.Attrs().Name); err != nil {
				if linkSnapshotDisappeared(link, err, netlink.LinkByName) {
					log.Debugf("Skip disappeared WAN interface %s", link.Attrs().Name)
					return nil
				}
				return fmt.Errorf("prepare WAN interface %s: %w", link.Attrs().Name, err)
			}
		}
		c.setManualWan(link, pattern, true)
		return nil
	}, func(link netlink.Link) {
		log.WithField("interface", link.Attrs().Name).Debug("WAN interface appeared")
		if !validLink(link) {
			return
		}
		c.setManualWan(link, pattern, true)
		if prepare != nil {
			if err := prepare(link.Attrs().Name); err != nil {
				log.WithError(err).WithField("interface", link.Attrs().Name).Error("Could not prepare WAN interface")
			}
		}
	}, func(link netlink.Link) {
		c.removeWanLink(link, pattern)
		log.WithField("interface", link.Attrs().Name).Info("WAN interface removed; waiting for it to reappear")
	})
}

func (c *hostBinder) removeWanLink(link netlink.Link, pattern string) {
	// This callback also represents a rename that stopped matching one
	// pattern. Update only that owner; the global DELLINK callback handles
	// physical deletion, and reconciliation detaches after all owners update.
	c.setManualWan(link, pattern, false)
}

func (c *hostBinder) invalidateWanLink(link netlink.Link) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.closeHostTCXLinks(link.Attrs().Index, hostTCXWanIngress, hostTCXWanEgress); err != nil {
		log.WithError(err).WithField("interface", link.Attrs().Name).Error("Could not close TCX links on removed WAN interface")
	}
}

func (c *hostBinder) setManualWan(link netlink.Link, pattern string, present bool) {
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
	binding.setName(link.Attrs().Name)
	binding.manualPatterns[pattern] = struct{}{}
}

func (b *wanBinding) setName(name string) {
	b.ifname = name
	maps.DeleteFunc(b.manualPatterns, func(pattern string, _ struct{}) bool {
		matched, _ := path.Match(pattern, name)
		return !matched
	})
}

func autoWanTargets(snapshot network.HostNetworkSnapshot) map[int]string {
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
func (c *hostBinder) reconcileWan(snapshot *network.HostNetworkSnapshot, prepare func(string) error) bool {
	return c.reconcileWanWith(snapshot, prepare, netlink.LinkByIndex)
}

func (c *hostBinder) reconcileWanWith(
	snapshot *network.HostNetworkSnapshot,
	prepare func(string) error,
	linkByIndex func(int) (netlink.Link, error),
) (retry bool) {
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
		link, err := linkByIndex(index)
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
		// Reconciliation can observe a rename before interface callbacks do.
		// Keep TCX only for owners that still match the authoritative name.
		binding.setName(link.Attrs().Name)
		required = len(binding.manualPatterns) > 0 || binding.automatic
		if snapshot != nil {
			required = len(binding.manualPatterns) > 0 || wantedAutomatically
		}
		if !required {
			continue
		}
		if prepare != nil {
			if err := prepare(binding.ifname); err != nil {
				log.WithError(err).WithField("interface", binding.ifname).Error("Could not prepare WAN interface")
				retry = true
				if wantedAutomatically {
					autoReady = false
				}
				continue
			}
		}
		if !c.wanAttached(index) {
			if err := c.attachWanLocked(link, binding); err != nil {
				log.WithError(err).WithField("interface", binding.ifname).Error("Could not attach WAN programs")
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
			// Preserve these owners across reload too, including the old
			// automatic path while its replacement is not ready yet.
			c.useHostTCXLink(index, hostTCXWanIngress)
			c.useHostTCXLink(index, hostTCXWanEgress)
			continue
		}
		if err := c.detachWanLocked(index, binding); err != nil {
			log.WithError(err).WithField("interface_index", index).Error("Could not detach obsolete WAN programs")
			retry = true
			continue
		}
		delete(c.wanBindings, index)
	}
	return retry
}

func (c *hostBinder) wanAttached(linkIndex int) bool {
	_, ingress := c.hostTCXLink(linkIndex, hostTCXWanIngress)
	_, egress := c.hostTCXLink(linkIndex, hostTCXWanEgress)
	return ingress && egress
}

func (c *hostBinder) detachWanLocked(linkIndex int, binding *wanBinding) error {
	if err := c.closeHostTCXLinks(linkIndex, hostTCXWanIngress, hostTCXWanEgress); err != nil {
		return err
	}
	log.WithField("interface", binding.ifname).Info("Detached WAN programs")
	return nil
}

func (c *hostBinder) attachWanLocked(link netlink.Link, binding *wanBinding) error {
	ifname := link.Attrs().Name
	if link.Attrs().Index == consts.LoopbackIfIndex {
		return fmt.Errorf("cannot bind to loopback interface")
	}

	if err := c.migrateHostTCXPrograms(link,
		c.program(hostTCXWanEgress, link),
		c.program(hostTCXWanIngress, link),
	); err != nil {
		return err
	}
	log.WithField("interface", ifname).Info("Attached WAN programs")
	return nil
}

// Seed discovery from the still-attached WAN links on reload. An authoritative
// snapshot replaces these provisional owners; an unavailable snapshot retains
// them until discovery recovers instead of creating an interception gap.
func (c *hostBinder) seedAutoWanBindings() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.kernelLinks.mu.Lock()
	defer c.kernelLinks.mu.Unlock()
	for _, owned := range c.hostTCXLinks {
		if owned.role != hostTCXWanEgress {
			continue
		}
		binding := c.wanBindings[owned.linkIndex]
		if binding == nil {
			binding = &wanBinding{manualPatterns: make(map[string]struct{})}
			c.wanBindings[owned.linkIndex] = binding
		}
		binding.automatic = true
	}
}
