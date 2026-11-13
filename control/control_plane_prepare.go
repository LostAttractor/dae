/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
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
	if err := runtime.prepareHost(ctx, soMarkFromDae); err != nil {
		return nil, err
	}

	if err := runtime.prepareKernelPins(); err != nil {
		return nil, err
	}
	pinPath := kernelPinPath()
	mapReplacements := maps.Clone(runtime.shared)
	if mapReplacements == nil {
		mapReplacements = make(map[string]*ebpf.Map)
	}
	if runtime.socketIdentity != nil {
		mapReplacements["socket_owner_map"] = runtime.socketIdentity.SocketOwner
	}
	var previousRoutes *ebpf.Map
	if len(runtime.shared) == 0 && !runtime.kernelLinks.privatePins {
		if err := runtime.pruneUDPTimerPins(false); err != nil {
			log.WithError(err).Warn("Prune unreferenced runtime timer pins")
		}
		previousRoutes, err = loadPinnedDeviceRoutes(pinPath)
		if err != nil {
			return nil, err
		}
		if previousRoutes != nil {
			defer previousRoutes.Close()
			mapReplacements["device_routes_map"] = previousRoutes
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
		Programs:        programOptions,
	}
	if !runtime.kernelLinks.privatePins {
		collectionOpts.Maps.PinPath = pinPath
	}
	if runtime.nextGeneration == ^uint32(0) {
		return nil, errors.New("routing generation exhausted")
	}
	runtime.nextGeneration++
	bpf := &BPFState{bpfObjects: new(bpfObjects), Runtime: runtime, routingGeneration: runtime.nextGeneration}
	kernelPID, err := fullLoadBpfObjects(bpf.bpfObjects, collectionOpts)
	if err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}
	// The full generation now owns the socket map descriptor; pinned links keep
	// the early writers alive without retaining their preparation descriptors.
	if err := runtime.socketIdentity.Close(); err != nil {
		return nil, errors.Join(err, bpf.Close())
	}
	runtime.socketIdentity = nil
	if err := bpf.RoutingGeneration.Set(bpf.routingGeneration); err != nil {
		return nil, errors.Join(err, bpf.Close())
	}
	if len(runtime.shared) != 0 {
		return bpf, nil
	}
	initialState := uint8(routingabi.DAEMON_STARTING)
	if runtime.recoveringGuards || runtime.staged {
		initialState = uint8(routingabi.DAEMON_STOPPING)
	}
	if err := bpf.ExitedMap.Update(uint32(0), initialState, ebpf.UpdateAny); err != nil {
		return nil, errors.Join(fmt.Errorf("initialize datapath state: %w", err), bpf.Close())
	}
	if err := bpf.DaemonIdentityMap.Update(uint32(0), uint64(kernelPID), ebpf.UpdateAny); err != nil {
		return nil, errors.Join(fmt.Errorf("register daemon socket identity: %w", err), bpf.Close())
	}
	if previousRoutes == nil && !runtime.kernelLinks.privatePins {
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
