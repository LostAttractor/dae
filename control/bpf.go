/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	log "github.com/sirupsen/logrus"
)

// BPFState is one configuration generation. Its programs reference private
// routing maps and Runtime-owned connection maps. Closing it never closes traffic.
type BPFState struct {
	*bpfObjects
	*Runtime
	routingGeneration          uint32
	closeOnce                  sync.Once
	closeErr                   error
	routingRegistrationCancels []func()
}

func (b *BPFState) Close() error {
	b.closeOnce.Do(func() {
		b.clearRoutingRegistrations()
		b.closeErr = b.bpfObjects.Close()
	})
	return b.closeErr
}

// detectCgroupPath returns the first-found cgroup2 mount point.
func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("cgroup2 not mounted")
}

func loadBpfObjectsWithConstants(obj any, opts *ebpf.CollectionOptions, constants map[string]any) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}
	for name, value := range constants {
		variable, ok := spec.Variables[name]
		if !ok {
			return fmt.Errorf("missing constant %s", name)
		}
		if !variable.Constant() {
			return fmt.Errorf("variable %s is not a constant", name)
		}
		if err := variable.Set(value); err != nil {
			return fmt.Errorf("set constant %s: %w", name, err)
		}
	}
	if opts != nil && opts.Maps.PinPath != "" {
		if err := removeIncompatiblePinnedMaps(spec, opts.Maps.PinPath); err != nil {
			return err
		}
	}
	return spec.LoadAndAssign(obj, opts)
}

func fullLoadBpfObjects(
	bpf *bpfObjects,
	soMarkFromDae uint32,
	opts *ebpf.CollectionOptions,
) (err error) {
	hasBpfGetCurrentTask, err := probeBPFCurrentTask()
	if err != nil {
		return err
	}
	constants := map[string]any{
		"PARAM": struct {
			controlPlanePid      uint32
			dae0Ifindex          uint32
			dae0peerIfindex      uint32
			dae0peerMac          [6]byte
			hasBpfGetCurrentTask uint8
			padding              uint8
			soMarkFromDae        uint32
		}{
			controlPlanePid:      uint32(os.Getpid()),
			dae0Ifindex:          uint32(GetDaeNetns().Dae0().Attrs().Index),
			dae0peerIfindex:      uint32(GetDaeNetns().Dae0Peer().Attrs().Index),
			dae0peerMac:          [6]byte(GetDaeNetns().Dae0Peer().Attrs().HardwareAddr),
			hasBpfGetCurrentTask: hasBpfGetCurrentTask,
			soMarkFromDae:        soMarkFromDae,
		},
	}
	if err = loadBpfObjectsWithConstants(bpf, opts, constants); err != nil {
		return explainBPFLoadError(err)
	}
	return nil
}

func probeBPFCurrentTask() (uint8, error) {
	err := features.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetCurrentTask)
	if err == nil {
		return 1, nil
	}
	if !errors.Is(err, ebpf.ErrNotSupported) {
		return 0, fmt.Errorf("probe bpf_get_current_task (requires BPF privileges): %w", err)
	}
	log.Warn("Kernel lacks bpf_get_current_task; process name routing uses truncated task names")
	return 0, nil
}

func explainBPFLoadError(err error) error {
	if log.IsLevelEnabled(log.TraceLevel) {
		if verifierErr, ok := errors.AsType[*ebpf.VerifierError](err); ok {
			log.WithField("verifier", fmt.Sprintf("%+v", verifierErr)).Trace("eBPF verifier rejected program")
		}
	}
	if strings.Contains(err.Error(), "no BTF found for kernel version") {
		return fmt.Errorf("%w: compile the kernel with CONFIG_DEBUG_INFO_BTF=y", err)
	} else if strings.Contains(err.Error(), "unknown func bpf_trace_printk") {
		return fmt.Errorf("%w: compile dae without bpf_printk", err)
	} else if strings.Contains(err.Error(), "unknown func bpf_probe_read") {
		return fmt.Errorf("%w: compile the kernel with CONFIG_BPF_EVENTS=y and CONFIG_KPROBE_EVENTS=y", err)
	}
	return err
}

func (b *BPFState) clearRoutingRegistrations() {
	for _, cancel := range b.routingRegistrationCancels {
		cancel()
	}
	b.routingRegistrationCancels = nil
}

func removeIncompatiblePinnedMaps(spec *ebpf.CollectionSpec, pinPath string) error {
	for _, mapSpec := range spec.Maps {
		if mapSpec.Pinning != ebpf.PinByName {
			continue
		}
		path := filepath.Join(pinPath, mapSpec.Name)
		pinned, err := ebpf.LoadPinnedMap(path, nil)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("load pinned map %q for compatibility check: %w", mapSpec.Name, err)
		}
		compatibleErr := mapSpec.Compatible(pinned)
		if err := pinned.Close(); err != nil {
			return fmt.Errorf("close pinned map %q: %w", mapSpec.Name, err)
		}
		if compatibleErr == nil {
			continue
		}
		if !errors.Is(compatibleErr, ebpf.ErrMapIncompatible) {
			return fmt.Errorf("check pinned map %q compatibility: %w", mapSpec.Name, compatibleErr)
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove incompatible pinned map %q: %w", mapSpec.Name, err)
		}
		log.WithField("map", mapSpec.Name).Info("Removed incompatible pinned eBPF map")
	}
	return nil
}
