// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common/consts"
	log "github.com/sirupsen/logrus"
)

const replacementMarker = "replacement_pending"

func kernelPinPath() string { return filepath.Join(consts.BpfPinRoot, consts.AppName) }

func hostTCXPinName(index int, role hostTCXRole) string {
	return fmt.Sprintf("tcx_%d_%d", index, role)
}

func parseHostTCXPinName(name string) (int, hostTCXRole, bool) {
	parts := strings.Split(name, "_")
	if len(parts) != 3 || parts[0] != "tcx" {
		return 0, 0, false
	}
	index, err := strconv.Atoi(parts[1])
	role, roleErr := strconv.ParseUint(parts[2], 10, 8)
	if err != nil || roleErr != nil || index <= 0 || role > uint64(hostTCXWanEgress) {
		return 0, 0, false
	}
	parsedRole := hostTCXRole(role)
	return index, parsedRole, name == hostTCXPinName(index, parsedRole)
}

func daeLinkPinName(name string) bool {
	if name == "exit" || name == "exit_next" {
		return true
	}
	if _, _, ok := parseHostTCXPinName(name); ok {
		return true
	}
	for _, attach := range []ebpf.AttachType{
		ebpf.AttachCGroupInetSockCreate, ebpf.AttachCGroupInet4Connect,
		ebpf.AttachCGroupInet6Connect, ebpf.AttachCGroupUDP4Sendmsg, ebpf.AttachCGroupUDP6Sendmsg,
	} {
		if name == fmt.Sprintf("pid_%d", attach) {
			return true
		}
	}
	return false
}

func removePinnedLink(path string) error {
	attached, err := link.LoadPinnedLink(path, nil)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.Join(unpinLinkIfPresent(attached), attached.Close())
}

func (k *kernelLinks) removePinnedLinks(cleanupErr error) error {
	if k.pinPath == "" {
		return cleanupErr
	}
	entries, err := os.ReadDir(k.pinPath)
	if errors.Is(err, os.ErrNotExist) {
		return cleanupErr
	}
	if err != nil {
		return errors.Join(cleanupErr, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "exit" || name == "exit_next" {
			continue
		}
		if !daeLinkPinName(name) {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("unknown kernel link pin %s; retaining it", name))
			continue
		}
		cleanupErr = errors.Join(cleanupErr, removePinnedLink(filepath.Join(k.pinPath, name)))
	}
	// Keep the exit hook until all classifiers and socket hooks are removed.
	if cleanupErr == nil {
		for _, name := range []string{"exit_next", "exit"} {
			if err := removePinnedLink(filepath.Join(k.pinPath, name)); err != nil {
				cleanupErr = err
				break
			}
		}
	}
	if err := os.Remove(k.pinPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		cleanupErr = errors.Join(cleanupErr, err)
	}
	return cleanupErr
}

func unpinLinkIfPresent(attached link.Link) error {
	err := attached.Unpin()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (k *kernelLinks) preparePins(root string) error {
	if k.pinPath != "" {
		return nil
	}
	path := filepath.Join(root, "links")
	if err := os.MkdirAll(path, 0700); err != nil {
		return fmt.Errorf("prepare persistent BPF links: %w", err)
	}
	k.pinPath = path
	if k.privatePins {
		return nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		index, role, ok := parseHostTCXPinName(entry.Name())
		if !ok {
			continue
		}
		attached, err := link.LoadPinnedLink(filepath.Join(path, entry.Name()), nil)
		if err != nil {
			return fmt.Errorf("load persistent TCX link %s: %w", entry.Name(), err)
		}
		info, err := attached.Info()
		if err != nil {
			return errors.Join(fmt.Errorf("inspect persistent TCX link %s: %w", entry.Name(), err), attached.Close())
		}
		tcx := info.TCX()
		if tcx != nil && tcx.Ifindex == 0 {
			if err := errors.Join(unpinLinkIfPresent(attached), attached.Close()); err != nil {
				return err
			}
			continue
		}
		if tcx == nil || tcx.Ifindex != uint32(index) || ebpf.AttachType(tcx.AttachType) != role.attachType() {
			return errors.Join(fmt.Errorf("invalid persistent TCX link %s", entry.Name()), attached.Close())
		}
		if !k.ownHostTCXLink(hostTCXLink{linkIndex: index, role: role, link: attached, close: attached.Close}) {
			return errors.Join(errors.New("duplicate persistent TCX link"), attached.Close())
		}
	}
	// Invalid pins fail startup before adoption, so cleanup can remove them.
	k.inherited = len(k.hostTCXLinks) != 0
	return nil
}

func (k *kernelLinks) pinHostTCXLink(attached link.Link, index int, role hostTCXRole) error {
	if k.pinPath == "" || k.privatePins {
		return nil
	}
	return attached.Pin(filepath.Join(k.pinPath, hostTCXPinName(index, role)))
}

// Perf-event links cannot update programs. Pin the replacement before removing
// its predecessor, so the process exit hook never loses its kernel owner.
func (k *kernelLinks) pinExitLink(attached link.Link) error {
	if k.pinPath == "" || k.privatePins {
		return nil
	}
	path := filepath.Join(k.pinPath, "exit")
	previous, err := link.LoadPinnedLink(path, nil)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if previous != nil {
		if err := previous.Close(); err != nil {
			return err
		}
	}
	temporary := path + "_next"
	if err := removePinnedLink(temporary); err != nil {
		return err
	}
	if err := attached.Pin(temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return errors.Join(err, attached.Unpin())
	}
	return nil
}

// RegisterDaemonIdentity lets only this locked daemon use the old rules for
// bootstrap traffic before a replacement runtime has loaded its programs.
func RegisterDaemonIdentity() error {
	pid, err := KernelProcessID()
	if err != nil {
		return err
	}
	paths := []string{filepath.Join(kernelPinPath(), "daemon_identity_map")}
	entries, err := os.ReadDir(replacementGuardPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, entry := range entries {
		paths = append(paths, filepath.Join(replacementGuardPath(), entry.Name(), "daemon_identity_map"))
	}
	for _, path := range paths {
		m, err := ebpf.LoadPinnedMap(path, nil)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("load daemon socket identity: %w", err)
		}
		spec := &ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1}
		if err := spec.Compatible(m); err != nil {
			return errors.Join(fmt.Errorf("daemon socket identity layout: %w", err), m.Close())
		}
		if err := errors.Join(m.Update(uint32(0), uint64(pid), ebpf.UpdateAny), m.Close()); err != nil {
			return err
		}
	}
	return nil
}

func loadPinnedDeviceRoutes(root string) (*ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(root, "device_routes_map"), nil)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	spec, err := parsedBPFSpec()
	if err == nil {
		err = spec.Maps["device_routes_map"].Compatible(m)
	}
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		// Like other incompatible pins: a cold start, not a retained failure.
		if removeErr := errors.Join(m.Close(), os.Remove(filepath.Join(root, "device_routes_map"))); removeErr != nil {
			return nil, fmt.Errorf("remove incompatible persistent device routes: %w", removeErr)
		}
		log.WithError(err).Info("Removed incompatible pinned eBPF map device_routes_map")
		return nil, nil
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("persistent device routes: %w", err), m.Close())
	}
	return m, nil
}

func restoreDeviceEpochs(routes *deviceRoutes) error {
	var table *ebpf.Map
	if err := routes.outer.Lookup(uint32(0), &table); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return err
	}
	defer table.Close()
	var mac [6]byte
	var state bpfDeviceRouteState
	interrupted := false
	entries := table.Iterate()
	for entries.Next(&mac, &state) {
		device := routes.device(mac)
		device.epoch = state.Epoch
		if state.Updating != 0 {
			// A crashed settings transaction cannot revive its old connections.
			device.epoch++
			interrupted = true
		}
	}
	if err := entries.Err(); err != nil || !interrupted {
		return err
	}
	recovered, err := routes.table(nil, false)
	if err != nil {
		return err
	}
	defer recovered.Close()
	return routes.outer.Update(uint32(0), recovered, ebpf.UpdateAny)
}

var udpTimerMapNames = [...]string{"udp_conn_state_map", "udp_routing_cache_map"}

// Timers require a userspace map reference, not just a pinned program's reference.
// These pins stay private to one Runtime: cached outbound IDs cannot cross restarts.
func (r *Runtime) pinUDPTimers() (err error) {
	path, err := os.MkdirTemp(filepath.Dir(r.kernelLinks.pinPath), "runtime_")
	if err != nil {
		return err
	}
	var pinned []string
	defer func() {
		if err != nil {
			for _, file := range pinned {
				err = errors.Join(err, os.Remove(file))
			}
			err = errors.Join(err, os.Remove(path))
		}
	}()
	for _, name := range udpTimerMapNames {
		file := filepath.Join(path, name)
		if err := r.shared[name].Pin(file); err != nil {
			return fmt.Errorf("pin runtime timer map %s: %w", name, err)
		}
		pinned = append(pinned, file)
	}
	return nil
}

func (k *kernelLinks) hostMapIDs() (map[ebpf.MapID]bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	ids := make(map[ebpf.MapID]bool)
	seen := make(map[ebpf.ProgramID]bool)
	for _, owned := range k.hostTCXLinks {
		info, err := owned.link.Info()
		if err != nil {
			return nil, err
		}
		if info.TCX() == nil {
			return nil, errors.New("host attachment is not a TCX link")
		}
		if info.TCX().Ifindex == 0 {
			continue
		}
		if seen[info.Program] {
			continue
		}
		seen[info.Program] = true
		program, err := ebpf.NewProgramFromID(info.Program)
		if err != nil {
			return nil, err
		}
		programInfo, err := program.Info()
		if err = errors.Join(err, program.Close()); err != nil {
			return nil, err
		}
		mapIDs, ok := programInfo.MapIDs()
		if !ok {
			return nil, errors.New("host program map IDs are unavailable")
		}
		for _, id := range mapIDs {
			ids[id] = true
		}
	}
	return ids, nil
}

// Call only before cold startup, after publication, or after interface callbacks
// have stopped. Current maps stay pinned during publication for late attachments.
func (r *Runtime) pruneUDPTimerPins(keepCurrent bool) error {
	if r.kernelLinks.pinPath == "" {
		return nil
	}
	needed, err := r.kernelLinks.hostMapIDs()
	if err != nil {
		return err
	}
	if keepCurrent {
		for _, name := range udpTimerMapNames {
			info, err := r.shared[name].Info()
			if err != nil {
				return err
			}
			id, ok := info.ID()
			if !ok {
				return errors.New("runtime timer map ID is unavailable")
			}
			needed[id] = true
		}
	}
	root := filepath.Dir(r.kernelLinks.pinPath)
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var pruneErr error
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "runtime_") {
			continue
		}
		// One unreadable directory keeps only itself.
		if err := pruneTimerDirectory(filepath.Join(root, entry.Name()), needed); err != nil {
			pruneErr = errors.Join(pruneErr, err)
		}
	}
	return pruneErr
}

func pruneTimerDirectory(directory string, needed map[ebpf.MapID]bool) error {
	retained := false
	for _, name := range udpTimerMapNames {
		path := filepath.Join(directory, name)
		m, err := ebpf.LoadPinnedMap(path, nil)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		info, err := m.Info()
		if err = errors.Join(err, m.Close()); err != nil {
			return err
		}
		id, ok := info.ID()
		if !ok {
			return errors.New("pinned timer map ID is unavailable")
		}
		if needed[id] {
			retained = true
		} else if err := os.Remove(path); err != nil {
			return err
		}
	}
	if !retained {
		return os.Remove(directory)
	}
	return nil
}

// removePins removes dae's pinned state once its links are gone: every map,
// this version's or an earlier one's, and the runtime timer pins. The
// fallback sequence goes last, so a failed removal never pairs surviving
// grants with reused tokens. Close calls this only when it owns the pins.
func (r *Runtime) removePins() error {
	if r.kernelLinks.pinPath == "" {
		return nil
	}
	if _, err := os.Stat(r.kernelLinks.pinPath); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("kernel links were not fully removed: %v", err)
	}
	root := filepath.Dir(r.kernelLinks.pinPath)
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == "fallback_sequence_map" {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			return fmt.Errorf("remove kernel pin %s; retaining fallback sequence: %w", entry.Name(), err)
		}
	}
	if err := os.Remove(filepath.Join(root, "fallback_sequence_map")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Remove(root)
}

// Publish only while old and new guards are pinned. A partial publication is
// recovered as a private generation, never by loading the mixed canonical maps.
func (r *Runtime) publishReplacementPins() error {
	k := &r.kernelLinks
	if !k.privatePins || k.pinPath == "" {
		return nil
	}
	spec, err := parsedBPFSpec()
	if err != nil {
		return err
	}
	// A generation without capture interfaces has no guard bundle to mark a partial publish.
	if err := os.MkdirAll(filepath.Join(filepath.Dir(k.pinPath), replacementMarker), 0700); err != nil {
		return err
	}
	for name, mapSpec := range spec.Maps {
		if mapSpec.Pinning != ebpf.PinByName && name != "device_routes_map" {
			continue
		}
		m := r.shared[name]
		if m == nil {
			return fmt.Errorf("persistent replacement map %s is unavailable", name)
		}
		owned, err := m.Clone()
		if err != nil {
			return err
		}
		path := filepath.Join(filepath.Dir(k.pinPath), name)
		err = publishKernelPin(path, owned.Pin)
		if err = errors.Join(err, owned.Close()); err != nil {
			return fmt.Errorf("publish replacement map %s: %w", name, err)
		}
	}
	publishLink := func(owned *link.Link, name string) error {
		info, err := (*owned).Info()
		if err != nil {
			return err
		}
		pinned, err := link.NewFromID(info.ID)
		if err != nil {
			return err
		}
		path := filepath.Join(k.pinPath, name)
		err = publishKernelPin(path, pinned.Pin)
		if err = errors.Join(err, pinned.Close()); err != nil {
			return err
		}
		// Reload the pin so Unpin owns the final path, not the temporary path.
		pinned, err = link.LoadPinnedLink(path, nil)
		if err != nil {
			return err
		}
		previous := *owned
		*owned = pinned
		return previous.Close()
	}
	for i := range k.hostTCXLinks {
		owned := &k.hostTCXLinks[i]
		err := publishLink(&owned.link, hostTCXPinName(owned.linkIndex, owned.role))
		owned.close = owned.link.Close
		if err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(k.pinPath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if name, temporary := strings.CutSuffix(entry.Name(), "_next"); temporary && daeLinkPinName(name) {
			if err := removePinnedLink(filepath.Join(k.pinPath, entry.Name())); err != nil {
				return err
			}
			continue
		}
		index, role, ok := parseHostTCXPinName(entry.Name())
		if !ok {
			continue
		}
		current := false
		for _, owned := range k.hostTCXLinks {
			current = current || owned.linkIndex == index && owned.role == role
		}
		if !current {
			if err := removePinnedLink(filepath.Join(k.pinPath, entry.Name())); err != nil {
				return err
			}
		}
	}
	for i := range k.pidLinks {
		if err := publishLink(&k.pidLinks[i], fmt.Sprintf("pid_%d", socketIdentityAttachTypes[i])); err != nil {
			return err
		}
	}
	for _, attach := range socketIdentityAttachTypes[len(k.pidLinks):] {
		if err := removePinnedLink(filepath.Join(k.pinPath, fmt.Sprintf("pid_%d", attach))); err != nil {
			return err
		}
	}
	if k.exitLink != nil {
		return publishLink(&k.exitLink, "exit")
	}
	return nil
}

func publishKernelPin(path string, pin func(string) error) error {
	temporary := path + "_next"
	if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := pin(temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return errors.Join(err, os.Remove(temporary))
	}
	return nil
}
