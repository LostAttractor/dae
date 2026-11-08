/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/internal/kernel"
	"github.com/daeuniverse/dae/internal/routingabi"
	log "github.com/sirupsen/logrus"
)

// ControlPlanePreparation owns prepared kernel resources until NewControlPlane
// consumes them. Its cloned Runtime map descriptors can be discarded independently.
type ControlPlanePreparation struct {
	bpf      *BPFState
	isReload bool
}

// PrepareControlPlane prepares private kernel resources independently of rule
// and subscription loading. NewControlPlane receives both prepared inputs.
func PrepareControlPlane(
	ctx context.Context,
	runtime *Runtime,
	soMarkFromDae uint32,
) (*ControlPlanePreparation, error) {
	started := time.Now()
	bpf, err := prepareBPF(ctx, runtime, soMarkFromDae)
	if err != nil {
		return nil, err
	}
	log.WithField("duration", time.Since(started)).Debug("Prepared eBPF resources")
	return &ControlPlanePreparation{bpf: bpf, isReload: runtime.IsReload()}, nil
}

func prepareBPF(ctx context.Context, runtime *Runtime, soMarkFromDae uint32) (_ *BPFState, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := runtime.waitForRetirement(ctx); err != nil {
		return nil, err
	}
	runtime.lifecycle.Lock()
	defer runtime.lifecycle.Unlock()
	select {
	case <-runtime.done:
		return nil, net.ErrClosed
	default:
	}
	if runtime.offline {
		return nil, net.ErrClosed
	}
	if err := runtime.checkSocketMark(soMarkFromDae); err != nil {
		return nil, err
	}
	if err := kernel.CheckVersion(); err != nil {
		return nil, err
	}
	if err = rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit.RemoveMemlock:%v", err)
	}

	runtime.kernelOwned = true
	InitDaeNetns()
	if err = InitSysctlManager(); err != nil {
		return nil, err
	}
	if err = GetDaeNetns().Setup(); err != nil {
		return nil, fmt.Errorf("failed to setup dae netns: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	pinPath := kernelPinPath()
	if err = os.MkdirAll(pinPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to prepare BPF pin directory %s: %w; verify bpffs is mounted read-write at %s and is writable by this process", pinPath, err, consts.BpfPinRoot)
	}

	if err := runtime.kernelLinks.preparePins(pinPath); err != nil {
		return nil, err
	}
	mapReplacements := runtime.shared
	var previousRoutes *ebpf.Map
	if len(runtime.shared) == 0 {
		if err := runtime.pruneUDPTimerPins(false); err != nil {
			log.WithError(err).Warn("Prune unreferenced runtime timer pins")
		}
		previousRoutes, err = loadPinnedDeviceRoutes(pinPath)
		if err != nil {
			return nil, err
		}
		if previousRoutes != nil {
			defer previousRoutes.Close()
			mapReplacements = map[string]*ebpf.Map{"device_routes_map": previousRoutes}
		}
	}

	log.Debug("Loading eBPF programs and maps")
	var programOptions ebpf.ProgramOptions
	if log.IsLevelEnabled(log.TraceLevel) {
		programOptions.LogLevel = ebpf.LogLevelBranch | ebpf.LogLevelStats
	}
	collectionOpts := &ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
		Cache:           kernelBTFCache,
		Maps:            ebpf.MapOptions{PinPath: pinPath},
		Programs:        programOptions,
	}
	if runtime.nextGeneration == ^uint32(0) {
		return nil, errors.New("routing generation exhausted")
	}
	runtime.nextGeneration++
	bpf := &BPFState{bpfObjects: new(bpfObjects), Runtime: runtime, routingGeneration: runtime.nextGeneration}
	if err = fullLoadBpfObjects(bpf.bpfObjects, collectionOpts); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}
	if err := bpf.RoutingGeneration.Set(bpf.routingGeneration); err != nil {
		return nil, errors.Join(err, bpf.Close())
	}
	if len(runtime.shared) != 0 {
		return bpf, nil
	}
	if err := bpf.ExitedMap.Update(uint32(0), uint8(routingabi.DAEMON_STARTING), ebpf.UpdateAny); err != nil {
		return nil, errors.Join(fmt.Errorf("initialize starting datapath: %w", err), bpf.Close())
	}
	if err := bpf.DaemonIdentityMap.Update(uint32(0), uint64(os.Getpid()), ebpf.UpdateAny); err != nil {
		return nil, errors.Join(fmt.Errorf("register daemon socket identity: %w", err), bpf.Close())
	}
	if previousRoutes == nil {
		if err := bpf.DeviceRoutesMap.Pin(filepath.Join(pinPath, "device_routes_map")); err != nil {
			return nil, errors.Join(fmt.Errorf("pin device route epochs: %w", err), bpf.Close())
		}
	}
	if err := runtime.retainMaps(bpf.bpfObjects); err != nil {
		return nil, errors.Join(err, bpf.Close())
	}
	if err := runtime.pinUDPTimers(); err != nil {
		return nil, errors.Join(err, bpf.Close())
	}
	runtime.soMarkFromDae = soMarkFromDae
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, errors.Join(contextErr, bpf.Close())
	}
	log.Debug("Loaded eBPF programs and maps")
	return bpf, nil
}

func (p *ControlPlanePreparation) take() (*BPFState, bool, error) {
	if p == nil {
		return nil, false, errors.New("control plane preparation is nil")
	}
	if p.bpf == nil {
		return nil, false, errors.New("control plane preparation has no BPF state")
	}
	bpf := p.bpf
	p.bpf = nil
	return bpf, p.isReload, nil
}

func (p *ControlPlanePreparation) Close() error {
	if p == nil {
		return nil
	}
	if p.bpf == nil {
		return nil
	}
	bpf := p.bpf
	p.bpf = nil
	return bpf.Close()
}
