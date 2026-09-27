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
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/clientmatch"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	log "github.com/sirupsen/logrus"
)

type ControlPlane struct {
	core       *controlPlaneCore
	deferFuncs []func() error

	// Outbounds are immutable after preparation. Connectivity callbacks use a
	// snapshot while plugin preparation can still append targets.
	outbounds              []*outbound.DialerGroup
	connectivityOutbounds  atomic.Pointer[[]*outbound.DialerGroup]
	criticalOutbounds      []bool
	noConnectivityOutbound consts.OutboundIndex
	tcpConnections         *tcpConnectionTracker
	udpTaskPool            *udpTaskPool[netip.AddrPort]
	udpSetups              atomic.Int32
	udpSetupDrops          udpPacketDrops
	udpEndpoints           *UdpEndpointPool

	dnsRelay           *dnsRelay
	domainRegistryPath string
	mitmHost           *mitm.Host
	mitmClients        clientmatch.Matcher
	settings           *settings.Store
	settingsMu         sync.Mutex
	apiKey             string
	apiPort            uint16
	kernelActive       bool
	clients            map[string]config.Client
	deviceRoutes       *deviceRoutes
	closeOnRouteChange bool
	apiBypass          []bpfIpPort

	routingMatcher        *RoutingMatcher
	routingMatcherBuilder *RoutingMatcherBuilder

	ctx             context.Context
	cancel          context.CancelFunc
	tcpSetupCtx     context.Context
	cancelTCPSetups context.CancelFunc

	ingressMu      sync.Mutex
	ingress        *controlPlaneIngress
	ingressRetired bool
	udpDraining    atomic.Bool

	abortConnections atomic.Bool

	muRealDomainSet sync.Mutex
	realDomainSet   *bloom.BloomFilter

	wanInterface []string
	autoWan      bool
	lanInterface []string

	hostReconcileCh   chan struct{}
	hostReconcileDone chan struct{}

	// Fields below are saved at NewControlPlane and consumed by Activate.
	autoConfigKernelParameter bool

	dialTargetOverride  bool
	rerouteMode         consts.RerouteMode
	sniffingTimeout     time.Duration
	sniffVerifyMode     consts.SniffVerifyMode
	soMarkFromDae       uint32
	mptcp               bool
	markedDirectDialers sync.Map

	// closedDone is set after Close completes successfully. InheritDomainRegistry
	// checks it before rewriting the shared kernel domain map.
	closedDone atomic.Bool
}

// TODO: 统一 Outbound 中的DNS解析器
// TODO: Hy2 的 mark 支持
// TODO: HandlePkt HandleConn 分割 Route 和 Dial
//
// NewControlPlane consumes prepared kernel and rule resources and builds the
// userspace control plane. It does not modify shared BPF maps or bind programs
// to traffic interfaces. Call Activate to commit it to the kernel.
// loadMITM runs after initial connectivity checks, using the configured DNS
// and routing policies. Module rules are compiled after downloads finish.
func NewControlPlane(
	startupCtx context.Context,
	preparation *ControlPlanePreparation,
	nodes []outbound.NodeDescriptor,
	conf *config.Config,
	runtimeSettings *settings.Store,
	loadMITM func(*http.Client, *http.Client) (*mitm.Host, error),
) (c *ControlPlane, err error) {
	groups, global := conf.Group, &conf.Global
	var mitmClients clientmatch.Matcher
	if conf.MITM.Enabled {
		clients := conf.MITM.ClientSourceAddress
		mitmClients, err = clientmatch.Parse(clients)
		if err != nil {
			return nil, fmt.Errorf("mitm client_source_address: %w", err)
		}
	}
	if runtimeSettings == nil {
		return nil, fmt.Errorf("runtime settings are required")
	}
	global.SoMarkFromDae = common.EffectiveSoMarkFromDae(global.SoMarkFromDae)
	if err = common.ValidateSoMarkFromDae(global.SoMarkFromDae); err != nil {
		return nil, err
	}
	bpf, preparedRules, isReload, err := preparation.take()
	if err != nil {
		return nil, err
	}
	core, err := newControlPlaneCore(
		bpf,
		isReload,
	)
	if err != nil {
		if !isReload {
			if closeErr := bpf.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close eBPF objects: %w", closeErr))
			}
		}
		return nil, err
	}
	defer func() {
		if err != nil {
			if closeErr := core.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close control plane core: %w", closeErr))
			}
		}
	}()

	if err := consts.VerifyRerouteMode(string(global.RerouteMode)); err != nil {
		return nil, err
	}
	if err := consts.VerifySniffVerifyMode(string(global.SniffVerifyMode)); err != nil {
		return nil, err
	}

	sniffingTimeout := global.SniffingTimeout
	if !global.DialTargetOverride && global.RerouteMode == consts.RerouteMode_None {
		// Sniff is not needed.
		sniffingTimeout = 0
	}

	/// Init DialerGroups.
	if err := config.ValidateConnectionBehavior("route_change_behavior", global.RouteChangeBehavior); err != nil {
		return nil, err
	}
	var noConnectivityOutbound consts.OutboundIndex
	if global.NoConnectivityBehavior == "direct" {
		noConnectivityOutbound = consts.OutboundDirect
	} else if global.NoConnectivityBehavior == "block" {
		noConnectivityOutbound = consts.OutboundBlock
	} else {
		return nil, fmt.Errorf("invalid no_connectivity_behavior: %v", global.NoConnectivityBehavior)
	}

	outboundBuilder, err := core.buildOutbounds(startupCtx, nodes, groups, preparedRules.routing, global, noConnectivityOutbound)
	if err != nil {
		return nil, err
	}
	var plane *ControlPlane
	var cancel context.CancelFunc
	defer func() {
		if err != nil {
			if plane == nil {
				_ = closeDialerGroups(outboundBuilder.outbounds)
			} else {
				cancel()
				if plane.mitmHost != nil {
					_ = plane.mitmHost.Close()
				}
				for i := len(plane.deferFuncs) - 1; i >= 0; i-- {
					_ = plane.deferFuncs[i]()
				}
			}
		}
	}()
	if err := outboundBuilder.buildRuleTargets(preparedRules.earlyRoutes, preparedRules.lateRoutes); err != nil {
		return nil, err
	}
	outbounds, outboundName2Id := outboundBuilder.outbounds, outboundBuilder.nameToID
	preparedRules.validationOutbounds = outboundBuilder.validationOutbounds

	if loadMITM == nil {
		if err := preparedRules.bypassLocalAPI(global.APIPort); err != nil {
			return nil, err
		}
	}

	/// Routing.
	// Parse rules and build. BuildUserspace is in-memory only and is safe to
	// run during the validation phase; BuildKernspace is deferred to Activate.
	builder, err := preparedRules.compileRouting(outboundName2Id, bpf, core.ifmgr)
	if err != nil {
		return nil, fmt.Errorf("compile routing: %w", err)
	}
	criticalOutbounds := builder.criticalOutbounds(len(outbounds))
	configureOutboundChecks(outbounds, groups, criticalOutbounds)
	routingMatcher, err := builder.BuildUserspace()
	if err != nil {
		return nil, fmt.Errorf("RoutingMatcherBuilder.BuildUserspace: %w", err)
	}
	// Back skip_while_noalive rule evaluation with the core's in-memory
	// mirror of outbound connectivity.
	routingMatcher.outboundUsable = core.outboundUsable
	if global.DNSRetentionWindow > 0 {
		core.domainRegistry.mu.Lock()
		core.domainRegistry.window = global.DNSRetentionWindow
		core.domainRegistry.mu.Unlock()
	}

	wanInterface, autoWan := splitWanInterfaces(global.WanInterface)

	clients := make(map[string]config.Client, len(conf.Client))
	for _, client := range conf.Client {
		clients[client.Name] = client
	}
	ctx, cancel := context.WithCancel(context.Background())
	tcpSetupCtx, cancelTCPSetups := context.WithCancel(ctx)
	plane = &ControlPlane{
		core:                      core,
		dnsRelay:                  newDNSRelay(),
		settings:                  runtimeSettings,
		mitmClients:               mitmClients,
		deviceRoutes:              core.bpf.deviceRoutes,
		closeOnRouteChange:        global.RouteChangeBehavior == "close",
		apiKey:                    global.APIKey,
		apiPort:                   global.APIPort,
		clients:                   clients,
		outbounds:                 outbounds,
		criticalOutbounds:         criticalOutbounds,
		noConnectivityOutbound:    noConnectivityOutbound,
		tcpConnections:            new(tcpConnectionTracker),
		udpTaskPool:               newUdpTaskPool[netip.AddrPort](),
		udpEndpoints:              &DefaultUdpEndpointPool,
		hostReconcileCh:           make(chan struct{}, 1),
		routingMatcher:            routingMatcher,
		routingMatcherBuilder:     builder,
		ctx:                       ctx,
		cancel:                    cancel,
		tcpSetupCtx:               tcpSetupCtx,
		cancelTCPSetups:           cancelTCPSetups,
		realDomainSet:             bloom.NewWithEstimates(2048, 0.001),
		lanInterface:              common.Deduplicate(global.LanInterface),
		wanInterface:              wanInterface,
		autoWan:                   autoWan,
		autoConfigKernelParameter: global.AutoConfigKernelParameter,
		dialTargetOverride:        global.DialTargetOverride,
		rerouteMode:               global.RerouteMode,
		sniffVerifyMode:           global.SniffVerifyMode,
		sniffingTimeout:           sniffingTimeout,
		soMarkFromDae:             global.SoMarkFromDae,
		mptcp:                     global.Mptcp,
	}
	for _, predicate := range builder.destination.predicates {
		if predicate.domain && plane.sniffingTimeout <= 0 {
			plane.sniffingTimeout = time.Second
			break
		}
	}
	// Retire DNS work before closing its outbound resources and checks.
	plane.deferFuncs = append(plane.deferFuncs, plane.closeOutbounds)
	// Plugin shutdown drains requests before this relay cancellation and join.
	plane.deferFuncs = append(plane.deferFuncs, plane.dnsRelay.Close)

	for _, group := range outbounds {
		group.DeferStats()
	}
	if err := plane.restoreRuntimeSettings(false); err != nil {
		return nil, err
	}
	plane.watchConnectivity()
	connectivityStarted := time.Now()
	waiters, err := startConnectivityChecks(outbounds)
	if err != nil {
		return nil, err
	}
	remaining := max(initialConnectivityTimeout-time.Since(connectivityStarted), 0)
	if err := waitForStartupConnectivity(waiters, remaining, startupCtx.Done()); err != nil {
		return nil, err
	}
	log.WithField("duration", time.Since(connectivityStarted)).Debug("Initial connectivity checks finished")

	if loadMITM != nil {
		if err := plane.prepareMITM(startupCtx, conf, &preparedRules, outboundBuilder, loadMITM); err != nil {
			return nil, err
		}
	}
	if err := startupCtx.Err(); err != nil {
		return nil, err
	}
	for _, group := range groups {
		if _, used := outboundName2Id[group.Name]; !used {
			log.WithField("group", group.Name).Debug("Group has no active routing references; skipping standalone outbound")
		}
	}
	plane.apiBypass = preparedRules.apiBypass
	return plane, nil
}
