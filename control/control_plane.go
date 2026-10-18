/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	log "github.com/sirupsen/logrus"
)

// ControlPlane composes generation-owned capabilities. Kernel resources keep
// their separate publication and retirement boundary in controlPlaneCore.
type ControlPlane struct {
	core *controlPlaneCore
	planeOutbounds
	planeTraffic
	planeHTTP
	planeAPI

	dnsRelay           *dnsRelay
	domainRegistryPath string

	kernelReady         bool
	routingGeneration   uint32
	deviceRoutes        *deviceRoutes
	closeOnRouteChange  bool
	routingMatcher      *RoutingMatcher
	routingState        *routingState
	muRealDomainSet     sync.Mutex
	realDomainSet       *bloom.BloomFilter
	dialTargetOverride  bool
	rerouteMode         consts.RerouteMode
	sniffingTimeout     time.Duration
	sniffVerifyMode     consts.SniffVerifyMode
	soMarkFromDae       uint32
	mptcp               bool
	markedDirectDialers sync.Map

	wanInterface              []string
	autoWan                   bool
	lanInterface              []string
	hostReconcileCh           chan struct{}
	hostReconcileDone         chan struct{}
	autoConfigKernelParameter bool

	// Close is serialized by core.lifecycleMu, including asynchronous retirement.
	cleanups   cleanupStack
	ctx        context.Context
	cancel     context.CancelFunc
	closedDone atomic.Bool
	closeErr   error
}

// TODO: 统一 Outbound 中的DNS解析器
// TODO: Hy2 的 mark 支持
// TODO: HandlePkt HandleConn 分割 Route 和 Dial
//
// NewControlPlane consumes prepared kernel resources and copies prepared rules
// to build the userspace control plane. It does not modify shared BPF maps or
// bind programs to traffic interfaces. Call PrepareKernel and Runtime.Publish to activate it.
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
	bpf, isReload, err := preparation.take()
	if err != nil {
		return nil, err
	}
	core, err := newControlPlaneCore(bpf, isReload)
	if err != nil {
		return nil, errors.Join(err, bpf.Close())
	}
	plane.initialize(core)
	defer func() {
		if err != nil {
			// A failed candidate has no admitted traffic. Cancel preparation work
			// before using the same ownership and shutdown order as a live plane.
			plane.cancel()
			err = errors.Join(err, plane.Close())
		}
	}()
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
	if err := preparedRules.bypassLocalAPI(global.APIPort); err != nil {
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
