// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/internal/routingabi"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func replacementGuardPath() string {
	return filepath.Join(consts.BpfPinRoot, consts.AppName, "guards")
}

func replacementGuardDirectory(id link.ID) string {
	return filepath.Join(replacementGuardPath(), strconv.FormatUint(uint64(id), 10))
}

func (role hostTCXRole) interceptsTraffic() bool {
	return role == hostTCXLanIngress || role == hostTCXWanEgress
}

func (k *kernelLinks) replacementHooks() []link.Link {
	hooks := slices.Clone(k.pidLinks)
	if k.exitLink != nil {
		hooks = append(hooks, k.exitLink)
	}
	return hooks
}

func pinReplacementGuard(l link.Link, role hostTCXRole, hooks ...link.Link) (_ bool, err error) {
	if !role.interceptsTraffic() {
		return false, nil
	}
	info, err := l.Info()
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(replacementGuardPath(), 0700); err != nil {
		return false, err
	}
	directory := replacementGuardDirectory(info.ID)
	created := true
	if err := os.Mkdir(directory, 0700); errors.Is(err, os.ErrExist) {
		created = false
		existing, err := link.LoadPinnedLink(filepath.Join(directory, "link"), nil)
		if err != nil {
			return false, err
		}
		defer existing.Close()
		pinned, err := existing.Info()
		if err != nil {
			return false, err
		}
		if pinned.ID != info.ID {
			return false, errors.New("replacement guard identity changed")
		}
	} else if err != nil {
		return false, err
	}
	defer func() {
		if err != nil && created {
			err = errors.Join(err, removeReplacementGuard(directory))
		}
	}()
	if created {
		// Keep a link until all map pins are gone, including interrupted preparation.
		pinned, err := link.NewFromID(info.ID)
		if err != nil {
			return false, err
		}
		defer pinned.Close()
		if err := pinned.Pin(filepath.Join(directory, "link")); err != nil {
			return false, err
		}
	}
	program, err := ebpf.NewProgramFromID(info.Program)
	if err != nil {
		return false, err
	}
	defer program.Close()
	programInfo, err := program.Info()
	if err != nil {
		return false, err
	}
	mapIDs, ok := programInfo.MapIDs()
	if !ok {
		return false, errors.New("replacement guard map IDs unavailable")
	}
	spec, err := parsedBPFSpec()
	if err != nil {
		return false, err
	}
	for _, id := range mapIDs {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return false, err
		}
		mapInfo, err := m.Info()
		if err == nil {
			// UDP timers need a userspace reference; bootstrap needs the old identity.
			for _, name := range []string{udpTimerMapNames[0], udpTimerMapNames[1], "daemon_identity_map"} {
				if mapInfo.Name == name[:min(len(name), unix.BPF_OBJ_NAME_LEN-1)] {
					if err = spec.Maps[name].Compatible(m); err != nil {
						break
					}
					path := filepath.Join(directory, name)
					if created {
						err = m.Pin(path)
					} else {
						var pinned *ebpf.Map
						pinned, err = ebpf.LoadPinnedMap(path, nil)
						if err == nil {
							var info *ebpf.MapInfo
							info, err = pinned.Info()
							if err == nil {
								if pinnedID, _ := info.ID(); pinnedID != id {
									err = errors.New("replacement guard map identity changed")
								}
							}
							err = errors.Join(err, pinned.Close())
						}
					}
					break
				}
			}
		}
		err = errors.Join(err, m.Close())
		if err != nil {
			return false, err
		}
	}
	for _, hook := range hooks {
		info, err := hook.Info()
		if err != nil {
			return false, err
		}
		name := "exit"
		if cg := info.Cgroup(); cg != nil {
			name = fmt.Sprintf("pid_%d", cg.AttachType)
		}
		path := filepath.Join(directory, name)
		if created {
			pinned, err := link.NewFromID(info.ID)
			if err != nil {
				return false, err
			}
			if err := errors.Join(pinned.Pin(path), pinned.Close()); err != nil {
				return false, err
			}
		} else {
			pinned, err := link.LoadPinnedLink(path, nil)
			if err != nil {
				return false, err
			}
			actual, err := pinned.Info()
			err = errors.Join(err, pinned.Close())
			if err != nil {
				return false, err
			}
			if actual.ID != info.ID {
				return false, errors.New("replacement guard identity hook changed")
			}
		}
	}
	return created, nil
}

// Keep identity writers and their exit hook until the guarding link is unpinned.
func removeReplacementGuard(directory string) error {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, name := range udpTimerMapNames {
		if err := os.Remove(filepath.Join(directory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Remove(filepath.Join(directory, "link")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == "exit" {
			continue
		}
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Remove(filepath.Join(directory, "exit")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(directory); err != nil {
		return err
	}
	_ = os.Remove(replacementGuardPath())
	return nil
}

// STOPPING is sticky across process exit; only an explicitly ready successor
// changes its own map back to ONLINE. The old classifier keeps its private maps.
func (r *Runtime) StopIngress() error {
	if m := r.shared["exited_map"]; m != nil {
		return m.Update(uint32(0), uint8(routingabi.DAEMON_STOPPING), ebpf.UpdateAny)
	}
	return nil
}

// Recovery uses the same barrier as replacement. Validate coverage before
// deleting any old pin; a changed interface set must never expose an old hook.
func (r *Runtime) finishReplacementGuards() (err error) {
	r.kernelLinks.mu.Lock()
	defer r.kernelLinks.mu.Unlock()
	if r.kernelLinks.privatePins {
		r.kernelLinks.preparing = true
	}
	if err := r.StopIngress(); err != nil {
		return err
	}
	type hook struct {
		index  uint32
		attach uint32
	}
	covered := make(map[hook]bool)
	current := make(map[link.ID]hostTCXLink)
	for _, owned := range r.kernelLinks.hostTCXLinks {
		// A reply-only program on the same hook cannot replace a guard.
		if !owned.role.interceptsTraffic() {
			continue
		}
		info, err := owned.link.Info()
		if err != nil {
			return err
		}
		current[info.ID] = owned
		covered[hook{uint32(owned.linkIndex), uint32(owned.role.attachType())}] = true
	}
	entries, err := os.ReadDir(replacementGuardPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	stale := make(map[string]link.Link)
	defer func() {
		for _, l := range stale {
			_ = l.Close()
		}
	}()
	for _, entry := range entries {
		directory := filepath.Join(replacementGuardPath(), entry.Name())
		l, err := link.LoadPinnedLink(filepath.Join(directory, "link"), nil)
		if errors.Is(err, os.ErrNotExist) {
			// Preparation or retirement can leave a bundle without its host link.
			if err := removeReplacementGuard(directory); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		info, err := l.Info()
		if err != nil {
			_ = l.Close()
			return err
		}
		if current[info.ID].link != nil {
			_ = l.Close()
			continue
		}
		stale[directory] = l
		tcx := info.TCX()
		if tcx == nil || tcx.Ifindex != 0 && !covered[hook{tcx.Ifindex, uint32(tcx.AttachType)}] {
			return fmt.Errorf("replacement guard %d has no ready successor; restore the previous interception interfaces", info.ID)
		}
	}
	var created []string
	retiring := false
	defer func() {
		if err != nil && !retiring {
			for _, directory := range created {
				err = errors.Join(err, removeReplacementGuard(directory))
			}
		}
	}()
	for id, owned := range current {
		added, err := pinReplacementGuard(owned.link, owned.role, r.kernelLinks.replacementHooks()...)
		if err != nil {
			return err
		}
		if added {
			created = append(created, replacementGuardDirectory(id))
		}
	}
	// Publication can replace canonical references before returning an error.
	retiring = true
	if err := r.publishReplacementPins(); err != nil {
		return err
	}
	for directory, l := range stale {
		if err := removeReplacementGuard(directory); err != nil {
			return err
		}
		if err := l.Close(); err != nil {
			return err
		}
		delete(stale, directory)
	}
	// Old guards are detached; retire their socket writers before unblocking.
	if err := r.closeIdentityHooks(); err != nil {
		return err
	}
	if err := r.setExited(routingabi.DAEMON_ONLINE); err != nil {
		return err
	}
	// Private generations keep their recovery marker until READY acknowledges
	// ownership; failure before then must not look like an ordinary restart.
	if !r.kernelLinks.privatePins {
		for id := range current {
			if err := removeReplacementGuard(replacementGuardDirectory(id)); err != nil {
				log.WithError(err).Warn("Remove committed replacement guard pins")
			}
		}
		_ = os.Remove(replacementGuardPath())
	}
	r.recoveringGuards = false
	return nil
}
