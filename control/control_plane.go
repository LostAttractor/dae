/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/selector"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	log "github.com/sirupsen/logrus"
)

// ControlPlane composes generation-owned capabilities. Kernel resources keep
// their separate publication and retirement boundary in controlPlaneCore.
type ControlPlane struct {
	core            *controlPlaneCore
	processIdentity *ProcessIdentity
	selectorHints   map[string]*selector.Path
	planeOutbounds
	planeTraffic
	planeHTTP
	planeAPI

	dnsRelay          *dnsRelay
	domainRegistryDir string

	kernelReady            bool
	routingGeneration      uint32
	deviceRoutes           *deviceRoutes
	closeOnRouteChange     bool
	unexpectedExitOutbound consts.OutboundIndex
	routingMatcher         *RoutingMatcher
	routingState           *routingState
	muRealDomainSet        sync.Mutex
	realDomainSet          *bloom.BloomFilter
	dialTargetOverride     bool
	rerouteMode            consts.RerouteMode
	sniffingTimeout        time.Duration
	sniffVerifyMode        consts.SniffVerifyMode
	soMarkFromDae          uint32
	mptcp                  bool
	markedDirectDialers    sync.Map

	wanInterface              []string
	autoWan                   bool
	lanInterface              []string
	hostReconcileCh           chan struct{}
	hostReconcileDone         chan struct{}
	autoConfigKernelParameter bool
	skipConnectivityWait      bool

	// Close is serialized by core.lifecycleMu, including asynchronous retirement.
	cleanups   cleanupStack
	ctx        context.Context
	cancel     context.CancelFunc
	closedDone atomic.Bool
	closeErr   error
}

// TODO: unify the DNS resolvers used by outbounds.
// TODO: support mark for Hy2.
// TODO: split Route and Dial between HandlePkt and HandleConn.
//
// NewControlPlane consumes prepared kernel resources and copies prepared rules
// to build the userspace control plane. When WAN is configured, it attaches the
// runtime-wide cgroup hooks that record socket owners before outbounds open
// sockets; they stay attached if the candidate fails. It does not bind
// programs to traffic interfaces. Call PrepareKernel and Runtime.Publish to activate it.
// loadMITM runs after initial connectivity checks, using the configured DNS
// and routing policies. Module rules are compiled after downloads finish.
func NewControlPlane(
	startupCtx context.Context,
	preparation *ControlPlanePreparation,
	loadedRules *PreparedRules,
	nodes []outbound.NodeDescriptor,
	conf *config.Config,
	runtimeSettings *settings.Store,
	loadMITM func(*http.Client) (PreparedMITM, error),
) (*ControlPlane, error) {
	if runtimeSettings == nil {
		return nil, errors.New("runtime settings are required")
	}
	if preparation == nil || preparation.bpf == nil {
		return nil, errors.New("control plane preparation has no BPF state")
	}
	resources := UserspaceResources{}
	if runtime := preparation.bpf.Runtime; runtime != nil {
		var err error
		resources.Interfaces, err = runtime.Interfaces()
		if err != nil {
			return nil, err
		}
		resources.Outbounds = &runtime.outboundResources
	}
	plane, err := newControlPlane(startupCtx, resources, preparation, loadedRules, nodes, conf, runtimeSettings, loadMITM)
	if err != nil {
		return nil, err
	}
	if err := plane.BuildServices(startupCtx); err != nil {
		return nil, errors.Join(err, plane.Close())
	}
	return plane, nil
}

// NewUserspaceControlPlane prepares the same routing and outbounds without
// loading or attaching business BPF. The caller supplies socket identity
// protection before construction and closes the plane after input preparation.
func NewUserspaceControlPlane(
	startupCtx context.Context,
	resources UserspaceResources,
	loadedRules *PreparedRules,
	nodes []outbound.NodeDescriptor,
	conf *config.Config,
	runtimeSettings *settings.Store,
	loadMITM func(*http.Client) (PreparedMITM, error),
) (*ControlPlane, error) {
	return newControlPlane(startupCtx, resources, nil, loadedRules, nodes, conf, runtimeSettings, loadMITM)
}

func newControlPlane(
	startupCtx context.Context,
	resources UserspaceResources,
	preparation *ControlPlanePreparation,
	loadedRules *PreparedRules,
	nodes []outbound.NodeDescriptor,
	conf *config.Config,
	runtimeSettings *settings.Store,
	loadMITM func(*http.Client) (PreparedMITM, error),
) (_ *ControlPlane, err error) {
	global := new(conf.Global)
	plane, err := configuredControlPlane(conf, global, runtimeSettings)
	if err != nil {
		return nil, err
	}
	if loadedRules == nil || loadedRules.rules.routing == nil {
		return nil, errors.New("prepared routing rules are required")
	}
	preparedRules := loadedRules.copy()
	core, err := newControlPlaneCore(resources)
	if err != nil {
		return nil, err
	}
	plane.initialize(core)
	plane.skipConnectivityWait = resources.SkipConnectivityWait
	if resources.ProcessIdentity != nil {
		plane.processIdentity = new(*resources.ProcessIdentity)
	}
	if runtimeSettings == nil {
		plane.selectorHints = make(map[string]*selector.Path, len(resources.SelectorHints))
		for group, path := range resources.SelectorHints {
			plane.selectorHints[group] = path.Clone()
		}
	}
	defer func() {
		if err != nil {
			// A failed candidate has no admitted traffic. Cancel preparation work
			// before using the same ownership and shutdown order as a live plane.
			plane.cancel()
			err = errors.Join(err, plane.Close())
		}
	}()
	if preparation != nil {
		if err := plane.BindKernel(preparation); err != nil {
			return nil, err
		}
		// Until the host owns these hooks independently, formal construction
		// installs them before any potentially persistent outbound socket.
		if len(plane.wanInterface) > 0 || plane.autoWan {
			if err := core.setupSkPidMonitor(); err != nil {
				return nil, fmt.Errorf("setup WAN socket identity monitor: %w", err)
			}
		}
	}
	outboundBuilder, err := core.buildOutbounds(startupCtx, nodes, conf.Group, preparedRules.routing, global, plane.noConnectivityOutbound)
	if err != nil {
		return nil, err
	}
	err = outboundBuilder.buildRuleTargets(preparedRules.earlyRoutes, preparedRules.lateRoutes)
	// Include partially constructed targets in the plane's cleanup ownership.
	plane.adoptOutbounds(outboundBuilder)
	if err != nil {
		return nil, err
	}
	preparedRules.validationOutbounds = outboundBuilder.validationOutbounds
	if err := preparedRules.bypassLocalAPI(conf.API.Listen); err != nil {
		return nil, err
	}
	if err := plane.initializeRouting(preparedRules, outboundBuilder, conf); err != nil {
		return nil, err
	}
	if err := plane.startConnectivity(startupCtx); err != nil {
		return nil, err
	}
	if loadMITM != nil {
		if err := plane.prepareMITM(startupCtx, conf, &preparedRules, outboundBuilder, loadMITM); err != nil {
			return nil, err
		}
	}
	if err := startupCtx.Err(); err != nil {
		return nil, err
	}
	for _, group := range conf.Group {
		if _, used := outboundBuilder.nameToID[group.Name]; !used {
			log.WithField("group", group.Name).Debug("Group has no active routing references; skipping standalone outbound")
		}
	}
	plane.apiBypass = preparedRules.apiBypass
	return plane, nil
}
