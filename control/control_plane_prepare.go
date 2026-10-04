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
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control/internal/splice"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// ControlPlanePreparation owns a candidate generation until NewControlPlane
// consumes it. Its cloned Runtime map descriptors can be discarded independently.
type ControlPlanePreparation struct {
	bpf      *BPFState
	rules    preparedRules
	isReload bool
}

// PrepareControlPlane loads kernel resources and expands external rule data in
// parallel. It does not update shared routing maps or bind programs to traffic
// interfaces, so it is safe while the previous control plane serves a reload.
func PrepareControlPlane(
	ctx context.Context,
	runtime *Runtime,
	routingConfig *config.Routing,
	global *config.Global,
	externGeoDataDirs []string,
	flowRules config.Rules,
) (_ *ControlPlanePreparation, err error) {
	soMarkFromDae := common.EffectiveSoMarkFromDae(global.SoMarkFromDae)
	if err := common.ValidateSoMarkFromDae(soMarkFromDae); err != nil {
		return nil, err
	}
	preparation := &ControlPlanePreparation{isReload: runtime.IsReload()}
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		phaseStarted := time.Now()
		bpf, err := prepareBPF(groupCtx, runtime, soMarkFromDae)
		if err == nil {
			preparation.bpf = bpf
			log.WithField("duration", time.Since(phaseStarted)).Debug("Prepared eBPF resources")
		}
		return err
	})
	group.Go(func() error {
		phaseStarted := time.Now()
		rules, err := prepareRoutingRules(groupCtx, routingConfig, externGeoDataDirs)
		if err == nil {
			err = rules.enableFlowRules(groupCtx, flowRules, externGeoDataDirs)
		}
		if err == nil {
			preparation.rules = rules
			log.WithField("duration", time.Since(phaseStarted)).Debug("Prepared routing rules")
		}
		return err
	})
	err = group.Wait()
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		if closeErr := preparation.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close control plane preparation: %w", closeErr))
		}
		return nil, err
	}
	return preparation, nil
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
	if len(runtime.shared) != 0 && runtime.soMarkFromDae != soMarkFromDae {
		return nil, fmt.Errorf("so_mark_from_dae (%#x -> %#x) cannot change on reload; restart dae to apply it", runtime.soMarkFromDae, soMarkFromDae)
	}
	kernelVersion, err := internal.KernelVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get kernel version: %w", err)
	}
	if kernelVersion.Less(consts.MinimumKernelVersion) {
		return nil, fmt.Errorf("your kernel version %v does not satisfy the minimum requirement; expect >=%v",
			kernelVersion.String(), consts.MinimumKernelVersion.String())
	}
	if err = rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit.RemoveMemlock:%v", err)
	}

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

	pinPath := filepath.Join(consts.BpfPinRoot, consts.AppName)
	if err = os.MkdirAll(pinPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to prepare BPF pin directory %s: %w; verify bpffs is mounted read-write at %s and is writable by this process", pinPath, err, consts.BpfPinRoot)
	}

	log.Debug("Loading eBPF programs and maps")
	var programOptions ebpf.ProgramOptions
	if log.IsLevelEnabled(log.TraceLevel) {
		programOptions.LogLevel = ebpf.LogLevelBranch | ebpf.LogLevelStats
	}
	collectionOpts := &ebpf.CollectionOptions{
		MapReplacements: runtime.shared,
		Cache:           btf.NewCache(),
		Maps:            ebpf.MapOptions{PinPath: pinPath},
		Programs:        programOptions,
	}
	if runtime.nextGeneration == ^uint32(0) {
		return nil, errors.New("routing generation exhausted")
	}
	runtime.nextGeneration++
	bpf := &BPFState{bpfObjects: new(bpfObjects), Runtime: runtime, routingGeneration: runtime.nextGeneration}
	if err = fullLoadBpfObjects(bpf.bpfObjects, soMarkFromDae, collectionOpts); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}
	if err := bpf.RoutingGeneration.Set(bpf.routingGeneration); err != nil {
		return nil, errors.Join(err, bpf.Close())
	}
	if len(runtime.shared) != 0 {
		return bpf, nil
	}
	if err := bpf.DeviceRoutesMap.Update(uint32(0), bpf.UnusedDeviceRoutes, ebpf.UpdateAny); err != nil {
		return nil, errors.Join(err, bpf.Close())
	}
	if err := runtime.retainMaps(bpf.bpfObjects); err != nil {
		return nil, errors.Join(err, bpf.Close())
	}
	runtime.soMarkFromDae = soMarkFromDae
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, errors.Join(contextErr, bpf.Close())
	}
	spliceOptions := *collectionOpts
	spliceOptions.MapReplacements = nil
	spliceRuntime, spliceErr := splice.New(&spliceOptions, DefaultNatTimeoutTCPEstablished)
	if spliceErr != nil {
		log.WithError(spliceErr).Warn("TCP splice unavailable; using userspace relay")
	} else if spliceRuntime != nil {
		bpf.splice = spliceRuntime
		log.Debug("Loaded optional TCP splice programs")
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, errors.Join(contextErr, bpf.Close())
	}
	log.Debug("Loaded eBPF programs and maps")
	return bpf, nil
}

func (p *ControlPlanePreparation) take() (*BPFState, preparedRules, bool, error) {
	if p == nil {
		return nil, preparedRules{}, false, errors.New("control plane preparation is nil")
	}
	if p.bpf == nil {
		return nil, preparedRules{}, false, errors.New("control plane preparation has no BPF state")
	}
	bpf := p.bpf
	rules := p.rules
	p.bpf = nil
	p.rules = preparedRules{}
	return bpf, rules, p.isReload, nil
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
