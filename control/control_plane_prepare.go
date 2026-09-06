/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control/internal/splice"
	"github.com/daeuniverse/dae/pkg/config_parser"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"github.com/mohae/deepcopy"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type preparedRules struct {
	destinations routing.DestinationRewrites
	geoDirs      []string
	routing      []*config_parser.RoutingRule
	capture      *routingCapture
	dnsRequest   []*config_parser.RoutingRule
	dnsResponse  []*config_parser.RoutingRule
}

// ControlPlanePreparation owns startup resources until NewControlPlane
// consumes them. A reload preparation borrows its BPF state and never closes
// it, allowing the caller to restore ownership to the running plane on error.
type ControlPlanePreparation struct {
	bpf      *bpfState
	rules    preparedRules
	isReload bool
}

// PrepareControlPlane loads kernel resources and expands external rule data in
// parallel. It does not update shared routing maps or bind programs to traffic
// interfaces, so it is safe while the previous control plane serves a reload.
func PrepareControlPlane(
	ctx context.Context,
	reusableBpf any,
	routingConfig *config.Routing,
	global *config.Global,
	dnsConfig *config.Dns,
	externGeoDataDirs []string,
	destinations config.Rules,
) (_ *ControlPlanePreparation, err error) {
	soMarkFromDae := common.EffectiveSoMarkFromDae(global.SoMarkFromDae)
	if err := common.ValidateSoMarkFromDae(soMarkFromDae); err != nil {
		return nil, err
	}
	preparation := &ControlPlanePreparation{isReload: reusableBpf != nil}
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		phaseStarted := time.Now()
		bpf, err := prepareBPF(groupCtx, reusableBpf, soMarkFromDae)
		if err == nil {
			preparation.bpf = bpf
			log.WithField("duration", time.Since(phaseStarted)).Info("Prepared eBPF resources")
		}
		return err
	})
	group.Go(func() error {
		phaseStarted := time.Now()
		rules, err := prepareRoutingRules(groupCtx, routingConfig, dnsConfig, externGeoDataDirs)
		if err == nil {
			rules.destinations, err = destinations.Destinations()
			if err == nil {
				rules.destinations, err = prepareDestinationRules(groupCtx, rules.destinations, externGeoDataDirs)
			}
		}
		if err == nil {
			preparation.rules = rules
			log.WithField("duration", time.Since(phaseStarted)).Info("Prepared routing rules")
		}
		return err
	})
	err = group.Wait()
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		if closeErr := preparation.Close(); closeErr != nil {
			err = errors.Join(err, oops.Wrapf(closeErr, "close control plane preparation"))
		}
		return nil, err
	}
	return preparation, nil
}

func prepareDestinationRules(ctx context.Context, rules routing.DestinationRewrites, dirs []string) (routing.DestinationRewrites, error) {
	reader := routing.NewDatReaderOptimizer(ctx, assets.NewLocationFinder(dirs))
	result := make(routing.DestinationRewrites, 0, len(rules))
	for i, rule := range rules {
		if len(rule.To) == 0 {
			return nil, fmt.Errorf("destination rule %d: missing target", i+1)
		}
		for _, ip := range rule.To {
			if !ip.IsValid() || ip.Zone() != "" {
				return nil, fmt.Errorf("destination rule %d: invalid target IP", i+1)
			}
		}
		filter := deepcopy.Copy(rule.Filter).([]*config_parser.Function)
		if len(filter) == 0 {
			return nil, fmt.Errorf("destination rule %d: missing predicate", i+1)
		}
		// Only predicate normalization applies here; rules with equal actions
		// must retain their original order, without merging equal actions.
		normalized, err := routing.ApplyRulesOptimizers([]*config_parser.RoutingRule{{AndFunctions: filter, Outbound: config_parser.Function{Name: "direct"}}}, &routing.AliasOptimizer{}, reader, &routing.DeduplicateParamsOptimizer{})
		if err != nil {
			return nil, fmt.Errorf("destination rule %d: %w", i+1, err)
		}
		rule.Filter = normalized[0].AndFunctions
		result = append(result, rule)
	}
	return result, nil
}

func prepareBPF(ctx context.Context, reusable any, soMarkFromDae uint32) (_ *bpfState, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reusedBpf, err := validateReusableBpfState(reusable, soMarkFromDae)
	if err != nil {
		return nil, err
	}
	kernelVersion, err := internal.KernelVersion()
	if err != nil {
		return nil, oops.Errorf("failed to get kernel version: %w", err)
	}
	if kernelVersion.Less(consts.MinimumKernelVersion) {
		return nil, oops.Errorf("your kernel version %v does not satisfy the minimum requirement; expect >=%v",
			kernelVersion.String(), consts.MinimumKernelVersion.String())
	}
	if err = rlimit.RemoveMemlock(); err != nil {
		return nil, oops.Errorf("rlimit.RemoveMemlock:%v", err)
	}

	InitDaeNetns()
	if err = InitSysctlManager(); err != nil {
		return nil, err
	}
	if err = GetDaeNetns().Setup(); err != nil {
		return nil, oops.Errorf("failed to setup dae netns: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	pinPath := filepath.Join(consts.BpfPinRoot, consts.AppName)
	if err = os.MkdirAll(pinPath, 0755); err != nil {
		return nil, oops.Errorf("failed to prepare BPF pin directory %s: %w; verify bpffs is mounted read-write at %s and is writable by this process", pinPath, err, consts.BpfPinRoot)
	}
	if reusedBpf != nil {
		log.Infof("Loaded eBPF programs and maps")
		return reusedBpf, nil
	}

	log.Infof("Loading eBPF programs and maps into the kernel...")
	log.Infof("The loading process takes about 120MB free memory, which will be released after loading. Insufficient memory will cause loading failure.")
	var programOptions ebpf.ProgramOptions
	if log.IsLevelEnabled(log.PanicLevel) {
		programOptions.LogLevel = ebpf.LogLevelBranch | ebpf.LogLevelStats
	}
	collectionOpts := &ebpf.CollectionOptions{
		Cache:    btf.NewCache(),
		Maps:     ebpf.MapOptions{PinPath: pinPath},
		Programs: programOptions,
	}
	bpf := &bpfState{bpfObjects: new(bpfObjects), soMarkFromDae: soMarkFromDae}
	if err = fullLoadBpfObjects(bpf.bpfObjects, pinPath, soMarkFromDae, collectionOpts); err != nil {
		err = oops.Wrapf(err, "load eBPF objects")
		if log.IsLevelEnabled(log.PanicLevel) {
			log.Panicf("%+v", err)
		}
		return nil, err
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, errors.Join(contextErr, bpf.Close())
	}
	spliceRuntime, spliceErr := splice.New(collectionOpts, DefaultNatTimeoutTCPEstablished)
	if spliceErr != nil {
		log.Warnf("TCP splice is unavailable; falling back to userspace relay: %v", spliceErr)
	} else if spliceRuntime != nil {
		bpf.splice = spliceRuntime
		log.Infof("Loaded optional TCP splice programs")
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, errors.Join(contextErr, bpf.Close())
	}
	log.Infof("Loaded eBPF programs and maps")
	return bpf, nil
}

func prepareRoutingRules(ctx context.Context, routingConfig *config.Routing, dnsConfig *config.Dns, externGeoDataDirs []string) (preparedRules, error) {
	var prepared preparedRules
	prepared.geoDirs = append([]string(nil), externGeoDataDirs...)
	locationFinder := assets.NewLocationFinder(externGeoDataDirs)
	datReader := routing.NewDatReaderOptimizer(ctx, locationFinder)
	if err := ctx.Err(); err != nil {
		return prepared, err
	}
	var err error
	prepared.routing, err = routing.ApplyRulesOptimizers(routingConfig.Rules,
		&routing.AliasOptimizer{}, datReader,
		&routing.MergeAndSortRulesOptimizer{}, &routing.DeduplicateParamsOptimizer{})
	if err != nil {
		return prepared, fmt.Errorf("prepare routing rules: %w", err)
	}
	prepared.dnsRequest, err = routing.ApplyRulesOptimizers(dnsConfig.Routing.Request.Rules,
		&routing.AliasOptimizer{}, datReader,
		&routing.MergeAndSortRulesOptimizer{}, &routing.DeduplicateParamsOptimizer{})
	if err != nil {
		return prepared, fmt.Errorf("prepare DNS request rules: %w", err)
	}
	prepared.dnsResponse, err = routing.ApplyRulesOptimizers(dnsConfig.Routing.Response.Rules,
		datReader, &routing.MergeAndSortRulesOptimizer{}, &routing.DeduplicateParamsOptimizer{})
	if err != nil {
		return prepared, fmt.Errorf("prepare DNS response rules: %w", err)
	}
	return prepared, nil
}

func (p *ControlPlanePreparation) take() (*bpfState, preparedRules, bool, error) {
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
	if p.bpf == nil || p.isReload {
		return nil
	}
	bpf := p.bpf
	p.bpf = nil
	return bpf.Close()
}
