// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/internal/handoff"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type ReplacementLink struct {
	Kind     string
	Ifindex  int
	Role     uint8
	Ethernet bool
	ID       uint32
}

// ReplacementSnapshot owns exported FDs independent of Runtime.Close and borrows
// Runtime links while frozen. Once blocked, only the successor may retire pinned
// entry links after installing its own guards.
type ReplacementSnapshot struct {
	Links   []ReplacementLink
	Files   []*os.File
	runtime *Runtime
	links   []link.Link
	frozen  bool
	once    sync.Once
}

func (r *Runtime) ExportReplacement(ctx context.Context) (_ *ReplacementSnapshot, err error) {
	if err := r.waitForRetirement(ctx); err != nil {
		return nil, err
	}
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	if c := r.current; c != nil && c.core.hostBinder != nil {
		// Do not freeze halfway through attaching or detaching a pair of host links.
		c.core.hostBinder.mu.Lock()
		defer c.core.hostBinder.mu.Unlock()
	}
	k := &r.kernelLinks
	k.mu.Lock()
	select {
	case <-r.done:
		k.mu.Unlock()
		return nil, net.ErrClosed
	default:
	}
	if k.transferred || k.frozen {
		k.mu.Unlock()
		return nil, errors.New("replacement links are unavailable")
	}
	hosts := slices.Clone(k.hostTCXLinks)
	nets := slices.Clone(k.netnsLinks)
	pids := slices.Clone(k.pidLinks)
	k.frozen = true
	k.mu.Unlock()

	s := &ReplacementSnapshot{runtime: r, frozen: true}
	defer func() {
		if err != nil {
			s.Release()
		}
	}()
	add := func(l link.Link, descriptor ReplacementLink) error {
		info, err := l.Info()
		if err != nil {
			return err
		}
		file, err := handoff.Dup(l.(interface{ FD() int }).FD(), "bpf-link")
		if err != nil {
			return err
		}
		descriptor.ID = uint32(info.ID)
		s.links = append(s.links, l)
		s.Links = append(s.Links, descriptor)
		s.Files = append(s.Files, file)
		return nil
	}
	for _, owned := range hosts {
		device, err := netlink.LinkByIndex(owned.linkIndex)
		if err != nil {
			return nil, err
		}
		if err := add(owned.link, ReplacementLink{Kind: "host", Ifindex: owned.linkIndex, Role: uint8(owned.role), Ethernet: linkHdrLen(device) != 0}); err != nil {
			return nil, err
		}
	}
	if len(nets) != netnsRoleCount {
		return nil, errors.New("incomplete namespace attachments")
	}
	for i, l := range nets {
		if err := add(l, ReplacementLink{Kind: "netns", Role: uint8(i)}); err != nil {
			return nil, err
		}
	}
	if len(pids) != 0 && len(pids) != len(socketIdentityAttachTypes) {
		return nil, errors.New("incomplete socket identity attachments")
	}
	for i, l := range pids {
		if err := add(l, ReplacementLink{Kind: "identity", Role: uint8(i)}); err != nil {
			return nil, err
		}
	}
	if err := validateReplacementDescriptors(s.Links); err != nil {
		return nil, err
	}
	return s, nil
}

// Block is the irreversible boundary. Pins outlive both processes on failure.
func (s *ReplacementSnapshot) Block(ctx context.Context) (err error) {
	r := s.runtime
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	k := &r.kernelLinks
	k.mu.Lock()
	select {
	case <-r.done:
		if s.frozen {
			k.frozen = false
		}
		k.mu.Unlock()
		return net.ErrClosed
	default:
	}
	if !s.frozen || k.transferred {
		k.mu.Unlock()
		return errors.New("replacement snapshot is not active")
	}
	hooks := k.replacementHooks()
	k.mu.Unlock()

	if r.shared["exited_map"] == nil {
		return errors.New("replacement has no ingress state")
	}
	if c := r.current; c != nil {
		if err := c.validateReplacementInterfaces(s.Links); err != nil {
			return err
		}
	}
	var pinned []string
	defer func() {
		if err != nil {
			for _, directory := range pinned {
				err = errors.Join(err, removeReplacementGuard(directory))
			}
		}
	}()
	for i, d := range s.Links {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		if d.Kind != "host" {
			continue
		}
		added, err := pinReplacementGuard(s.links[i], hostTCXRole(d.Role), hooks...)
		if err != nil {
			return err
		}
		if added {
			pinned = append(pinned, replacementGuardDirectory(link.ID(d.ID)))
		}
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if err := r.StopIngress(); err != nil {
		return err
	}
	k.mu.Lock()
	k.frozen = false
	k.transferred = true
	k.mu.Unlock()
	s.links = nil
	s.frozen = false
	return nil
}

// TakeFiles transfers ownership of the exported FDs to the caller.
func (s *ReplacementSnapshot) TakeFiles() []*os.File {
	files := s.Files
	s.Files = nil
	return files
}

func (s *ReplacementSnapshot) Release() {
	s.once.Do(func() {
		s.links = nil
		if s.frozen {
			s.runtime.kernelLinks.mu.Lock()
			s.runtime.kernelLinks.frozen = false
			s.runtime.kernelLinks.recheckHost = true
			s.runtime.kernelLinks.mu.Unlock()
			s.frozen = false
			s.runtime.mu.Lock()
			if c := s.runtime.current; c != nil && c.hostReconcileCh != nil {
				c.requestHostReconcile()
			}
			s.runtime.mu.Unlock()
		}
		for _, f := range s.TakeFiles() {
			_ = f.Close()
		}
	})
}

type replacementAttachment struct {
	link link.Link
	next *ebpf.Program
}

func validateReplacementDescriptors(descriptors []ReplacementLink) error {
	type hook struct {
		kind  string
		index int
		role  uint8
	}
	seen := make(map[hook]bool)
	ids := make(map[uint32]bool)
	var namespaces, identities uint8
	wan := false
	for _, d := range descriptors {
		key := hook{d.Kind, d.Ifindex, d.Role}
		if d.ID == 0 || ids[d.ID] || seen[key] {
			return errors.New("duplicate or invalid attachment identity")
		}
		ids[d.ID], seen[key] = true, true
		switch d.Kind {
		case "host":
			if d.Ifindex <= 0 || d.Role > uint8(hostTCXWanEgress) {
				return errors.New("invalid host attachment")
			}
			wan = wan || d.Role == uint8(hostTCXWanIngress) || d.Role == uint8(hostTCXWanEgress)
		case "netns":
			if d.Ifindex != 0 || d.Ethernet || d.Role >= netnsRoleCount {
				return errors.New("invalid namespace attachment")
			}
			namespaces |= 1 << d.Role
		case "identity":
			if d.Ifindex != 0 || d.Ethernet || int(d.Role) >= len(socketIdentityAttachTypes) {
				return errors.New("invalid socket identity attachment")
			}
			identities |= 1 << d.Role
		default:
			return errors.New("unknown attachment kind")
		}
	}
	if namespaces != 1<<netnsRoleCount-1 || identities != 0 && identities != 1<<len(socketIdentityAttachTypes)-1 || wan && identities == 0 {
		return errors.New("incomplete replacement attachments")
	}
	return nil
}

// ImportReplacement duplicates the files; the caller must close its inherited
// references before CommitReplacement can retire the old guards.
func (r *Runtime) ImportReplacement(descriptors []ReplacementLink, files []*os.File) (err error) {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	select {
	case <-r.done:
		return net.ErrClosed
	default:
	}
	if r.staged || r.current != nil || len(r.shared) != 0 || len(r.kernelLinks.hostTCXLinks) != 0 || len(r.kernelLinks.netnsLinks) != 0 || len(r.kernelLinks.pidLinks) != 0 || r.kernelLinks.exitLink != nil {
		return errors.New("replacement requires a fresh runtime")
	}
	if len(descriptors) != len(files) {
		return errors.New("invalid attachment descriptors")
	}
	if err := validateReplacementDescriptors(descriptors); err != nil {
		return err
	}
	var imported []link.Link
	defer func() {
		if err != nil {
			err = errors.Join(err, closeBpfLinks(imported))
		}
	}()
	var hosts []hostTCXLink
	namespaces := make([]link.Link, netnsRoleCount)
	var identities []link.Link
	var attachments []replacementAttachment
	var retained []ReplacementLink
	for i, d := range descriptors {
		if files[i] == nil {
			return errors.New("missing attachment file")
		}
		fd, err := unix.FcntlInt(files[i].Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return err
		}
		l, err := link.NewFromFD(fd)
		if err != nil {
			return err
		}
		imported = append(imported, l)
		info, err := l.Info()
		if err != nil || uint32(info.ID) != d.ID {
			return errors.Join(errors.New("attachment identity changed"), err)
		}
		switch d.Kind {
		case "host":
			tcx := info.TCX()
			if tcx == nil || int(tcx.Ifindex) != d.Ifindex || uint32(tcx.AttachType) != uint32(hostTCXRole(d.Role).attachType()) {
				return errors.New("host attachment differs")
			}
			hosts = append(hosts, hostTCXLink{linkIndex: d.Ifindex, role: hostTCXRole(d.Role), link: l, close: l.Close})
		case "netns":
			valid := false
			attach := namespaceAttachType(d.Role, info.Netkit() != nil)
			if ns := info.NetNs(); ns != nil {
				valid = uint32(ns.AttachType) == uint32(attach)
			} else if tcx := info.TCX(); tcx != nil {
				valid = uint32(tcx.AttachType) == uint32(attach)
			} else if netkit := info.Netkit(); netkit != nil {
				valid = uint32(netkit.AttachType) == uint32(attach)
			}
			if !valid {
				return errors.New("namespace attachment differs")
			}
			namespaces[d.Role] = l
		case "identity":
			cgroup := info.Cgroup()
			if cgroup == nil || uint32(cgroup.AttachType) != uint32(socketIdentityAttachTypes[d.Role]) {
				return errors.New("socket identity attachment differs")
			}
			identities = append(identities, l)
			continue
		}
		attachments = append(attachments, replacementAttachment{link: l})
		retained = append(retained, d)
	}
	r.kernelLinks.hostTCXLinks, r.kernelLinks.netnsLinks = hosts, namespaces
	r.identityHooks = identities
	r.replacementLinks, r.replacementDescriptors = attachments, retained
	r.staged, r.kernelLinks.preparing, r.kernelLinks.privatePins = true, true, true
	return nil
}

// SetReplacementPID accepts the preflight process's kernel TGID, not its namespace PID.
func (r *Runtime) SetReplacementPID(kernelPID uint32) error {
	m := r.shared["replacement_pid_map"]
	if m == nil {
		return errors.New("replacement has no process identity map")
	}
	return m.Update(uint32(0), kernelPID, ebpf.UpdateAny)
}

// stageReplacementLocked runs under Runtime.lifecycle.Lock().
func (r *Runtime) stageReplacementLocked(c *ControlPlane) error {
	select {
	case <-r.done:
		return net.ErrClosed
	default:
	}
	if r.current != nil {
		return errors.New("replacement plane already published")
	}
	for i, d := range r.replacementDescriptors {
		var next *ebpf.Program
		switch d.Kind {
		case "host":
			if d.Role > uint8(hostTCXWanEgress) {
				return errors.New("unknown host attachment role")
			}
			next = hostTCXRole(d.Role).program(&c.core.bpf.bpfPrograms, d.Ethernet)
		case "netns":
			programs := c.core.bpf.namespacePrograms()
			if int(d.Role) >= len(programs) {
				return errors.New("unknown namespace attachment role")
			}
			next = programs[d.Role]
		default:
			return errors.New("unknown attachment kind")
		}
		r.replacementLinks[i].next = next
		for j := range r.kernelLinks.hostTCXLinks {
			if r.kernelLinks.hostTCXLinks[j].link == r.replacementLinks[i].link {
				r.kernelLinks.hostTCXLinks[j].program = next
			}
		}
	}
	if err := c.activateLinks(); err != nil {
		return err
	}
	r.mu.Lock()
	r.current = c
	r.planes[c.routingGeneration] = c
	r.mu.Unlock()
	SetAnyfromSoMark(c.soMarkFromDae)
	return nil
}

// activateReplacementLocked installs downstream programs and new host guards.
// The caller holds Runtime.lifecycle and core.lifecycleMu; listeners must be ready.
func (r *Runtime) activateReplacementLocked(c *ControlPlane) error {
	if err := r.kernelLinks.finishRebind(); err != nil {
		return err
	}
	if err := c.validateReplacementInterfaces(r.replacementDescriptors); err != nil {
		return err
	}
	r.kernelLinks.mu.Lock()
	defer r.kernelLinks.mu.Unlock()
	previous := make([]*ebpf.Program, len(r.replacementLinks))
	defer func() {
		for _, p := range previous {
			if p != nil {
				_ = p.Close()
			}
		}
	}()
	for i, item := range r.replacementLinks {
		if item.next == nil {
			return errors.New("replacement program unavailable")
		}
		info, err := item.link.Info()
		if err != nil || uint32(info.ID) != r.replacementDescriptors[i].ID {
			return errors.Join(errors.New("attachment identity changed"), err)
		}
		previous[i], err = ebpf.NewProgramFromID(info.Program)
		if err != nil {
			return err
		}
		if previous[i].Type() != item.next.Type() {
			return errors.New("replacement program type differs")
		}
	}
	for i, d := range r.replacementDescriptors {
		if d.Kind == "netns" {
			item := r.replacementLinks[i]
			if err := updateReplacementLink(item.link, item.next, previous[i]); err != nil {
				return err
			}
		}
	}
	for i, d := range r.replacementDescriptors {
		if d.Kind != "host" {
			continue
		}
		item := &r.replacementLinks[i]
		var owned *hostTCXLink
		for j := range r.kernelLinks.hostTCXLinks {
			if r.kernelLinks.hostTCXLinks[j].link == item.link {
				owned = &r.kernelLinks.hostTCXLinks[j]
				break
			}
		}
		if owned == nil {
			return errors.New("replacement host attachment has no owner")
		}
		l, err := link.AttachTCX(link.TCXOptions{Interface: d.Ifindex, Attach: hostTCXRole(d.Role).attachType(), Program: item.next, Anchor: link.AfterLink(item.link)})
		if err != nil {
			return err
		}
		owned.link, owned.close, owned.program = l, l.Close, item.next
		old := item.link
		item.link = l
		// Record ownership before pinning; failed installation must still close it.
		if _, err := pinReplacementGuard(l, hostTCXRole(d.Role), r.kernelLinks.replacementHooks()...); err != nil {
			return errors.Join(err, old.Close())
		}
		// No extra host FD may keep a guard attached after its pin is removed.
		if err := old.Close(); err != nil {
			return err
		}
	}
	r.replacementLinks = nil
	return nil
}

func (c *ControlPlane) validateReplacementInterfaces(descriptors []ReplacementLink) error {
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	var automatic map[int]string
	if c.autoWan {
		snapshot, err := network.CurrentHostNetworkSnapshot()
		if err != nil {
			return err
		}
		automatic = autoWanTargets(snapshot)
	}
	return validateReplacementInterfaces(descriptors, links, c.lanInterface, c.wanInterface, automatic)
}

func validateReplacementInterfaces(descriptors []ReplacementLink, links []netlink.Link, lan, wan []string, automatic map[int]string) error {
	type hook struct {
		index int
		role  hostTCXRole
	}
	desired := make(map[hook]bool)
	for _, device := range links {
		if device.Attrs().Name == hostLinkName {
			continue
		}
		index := device.Attrs().Index
		if matchesInterface(lan, device.Attrs().Name) {
			desired[hook{index, hostTCXLanIngress}] = linkHdrLen(device) != 0
			desired[hook{index, hostTCXLanEgress}] = linkHdrLen(device) != 0
		}
		if index != consts.LoopbackIfIndex && (matchesInterface(wan, device.Attrs().Name) || automatic[index] == device.Attrs().Name) {
			desired[hook{index, hostTCXWanIngress}] = linkHdrLen(device) != 0
			desired[hook{index, hostTCXWanEgress}] = linkHdrLen(device) != 0
		}
	}
	for _, descriptor := range descriptors {
		if descriptor.Kind != "host" {
			continue
		}
		key := hook{descriptor.Ifindex, hostTCXRole(descriptor.Role)}
		ethernet, ok := desired[key]
		if !ok || ethernet != descriptor.Ethernet {
			return errors.New("interception interfaces changed; reload configuration before replacing the executable")
		}
		delete(desired, key)
	}
	if len(desired) != 0 {
		return errors.New("interception interfaces changed; reload configuration before replacing the executable")
	}
	return nil
}

func updateReplacementLink(l link.Link, next, previous *ebpf.Program) error {
	updater, ok := l.(interface {
		UpdateArgs(link.RawLinkUpdateOptions) error
	})
	if !ok {
		return errors.New("attachment does not support checked replacement")
	}
	return updater.UpdateArgs(link.RawLinkUpdateOptions{New: next, Old: previous, Flags: unix.BPF_F_REPLACE})
}

// closeIdentityHooks runs after guard retirement, or during terminal shutdown.
// These old socket-owner writers must never populate the new runtime's pidLinks.
func (r *Runtime) closeIdentityHooks() error {
	err := closeBpfLinks(r.identityHooks)
	r.identityHooks = nil
	return err
}

// CommitReplacement prepares exports, installs the successor, and retires old guards.
func (r *Runtime) CommitReplacement(ctx context.Context) (err error) {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if !r.staged || r.current == nil || len(r.replacementLinks) == 0 {
		return errors.New("replacement is not prepared")
	}
	c := r.current
	c.core.lifecycleMu.Lock()
	defer c.core.lifecycleMu.Unlock()
	if c.core.closed.Err() != nil {
		return net.ErrClosed
	}
	exports, err := c.prepareClientExports()
	if err != nil {
		return fmt.Errorf("prepare replacement client exports: %w", err)
	}
	defer func() {
		// The old runtime is closed: keep applied sets even if commit fails.
		if cleanupErr := exports.Commit(); cleanupErr != nil {
			if err != nil {
				err = errors.Join(err, cleanupErr)
			} else {
				log.WithError(cleanupErr).Warn("Remove client export backups after replacement")
			}
		}
	}()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if err := r.activateReplacementLocked(c); err != nil {
		return err
	}
	if err := exports.Apply(); err != nil {
		return fmt.Errorf("publish replacement client exports: %w", err)
	}
	if host := c.MITMHost(); host != nil {
		if err := host.Start(c.ctx); err != nil {
			return err
		}
	}
	if c.domainRegistryDir != "" {
		c.core.domainRegistry.EnablePersistence(c.domainRegistryDir)
	}
	if err := r.kernelLinks.finishRebind(); err != nil {
		return err
	}
	if err := c.validateReplacementInterfaces(r.replacementDescriptors); err != nil {
		return err
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if err := r.finishReplacementGuards(); err != nil {
		return err
	}
	r.replacementDescriptors = nil
	r.staged = false
	if err := r.pruneUDPTimerPins(true); err != nil {
		log.WithError(err).Warn("Retire unreferenced runtime timer pins")
	}
	return nil
}

// ConfirmReady validates the frozen generation before announcing readiness.
// After notify succeeds, only cleanup remains; failure keeps every guard.
func (r *Runtime) ConfirmReady(notify func() error) error {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	select {
	case <-r.done:
		return net.ErrClosed
	default:
	}
	if r.staged || r.recoveringGuards || r.kernelLinks.transferred || r.offline {
		return errors.New("replacement is not committed")
	}
	if !r.kernelLinks.privatePins {
		return notify()
	}
	if !r.online || r.current == nil {
		return errors.New("replacement datapath is not online")
	}
	r.kernelLinks.mu.Lock()
	defer r.kernelLinks.mu.Unlock()
	if r.kernelLinks.prepareErr != nil {
		return r.kernelLinks.prepareErr
	}
	var guards []link.ID
	var hosts []ReplacementLink
	for _, owned := range r.kernelLinks.hostTCXLinks {
		info, err := owned.link.Info()
		if err != nil {
			return err
		}
		if tcx := info.TCX(); tcx == nil || int(tcx.Ifindex) != owned.linkIndex {
			return errors.New("host attachment disappeared before readiness")
		}
		if owned.role.interceptsTraffic() {
			guards = append(guards, info.ID)
		}
		ethernet := owned.program == owned.role.program(&r.current.core.bpf.bpfPrograms, true)
		hosts = append(hosts, ReplacementLink{Kind: "host", Ifindex: owned.linkIndex, Role: uint8(owned.role), Ethernet: ethernet})
	}
	if err := r.current.validateReplacementInterfaces(hosts); err != nil {
		return err
	}
	if err := notify(); err != nil {
		return err
	}
	for _, id := range guards {
		if err := removeReplacementGuard(replacementGuardDirectory(id)); err != nil {
			log.WithError(err).Warn("Remove committed replacement guard pins")
		}
	}
	if r.kernelLinks.pinPath != "" {
		if err := os.Remove(filepath.Join(filepath.Dir(r.kernelLinks.pinPath), replacementMarker)); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.WithError(err).Warn("Remove committed replacement marker")
		}
	}
	r.kernelLinks.privatePins, r.kernelLinks.preparing = false, false
	return nil
}
