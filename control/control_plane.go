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
	"strings"
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
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
)

type ControlPlane struct {
	core       *controlPlaneCore
	deferFuncs []func() error

	// TODO: add mutex?
	outbounds              []*outbound.DialerGroup
	criticalOutbounds      []bool
	noConnectivityOutbound consts.OutboundIndex
	tcpConnections         *tcpConnectionTracker
	udpTaskPool            *udpTaskPool[netip.AddrPort]
	udpSetups              atomic.Int32
	udpSetupDrops          udpPacketDrops
	udpEndpoints           *UdpEndpointPool

	dnsController      *DnsController
	mitmHost           *mitm.Host
	mitmClients        clientmatch.Matcher
	settings           *settings.Store
	settingsMu         sync.Mutex
	apiToken           string
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
	fallbackResolver    string
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
	groups, routingA, global, dnsConfig := conf.Group, &conf.Routing, &conf.Global, &conf.Dns
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
				err = errors.Join(err, oops.Wrapf(closeErr, "close eBPF objects"))
			}
		}
		return nil, err
	}
	defer func() {
		if err != nil {
			if closeErr := core.Close(); closeErr != nil {
				err = errors.Join(err, oops.Wrapf(closeErr, "close control plane core"))
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
		return nil, oops.Errorf("invalid no_connectivity_behavior: %v", global.NoConnectivityBehavior)
	}

	outbounds, outboundName2Id, err := core.buildOutbounds(nodes, groups, routingA, global, noConnectivityOutbound)
	if err != nil {
		return nil, err
	}
	var plane *ControlPlane
	var cancel context.CancelFunc
	defer func() {
		if err != nil {
			if plane == nil {
				_ = closeDialerGroups(outbounds)
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

	if loadMITM == nil {
		if err := preparedRules.bypassLocalAPI(global.APIPort); err != nil {
			return nil, err
		}
	}

	/// Routing.
	// Parse rules and build. BuildUserspace is in-memory only and is safe to
	// run during the validation phase; BuildKernspace is deferred to Activate.
	builder, err := NewRoutingMatcherBuilder(preparedRules.routing, outboundName2Id, bpf, routingA.Fallback, core.ifmgr, preparedRules.capture, preparedRules.destinations)
	if err != nil {
		return nil, oops.Errorf("NewRoutingMatcherBuilder: %w", err)
	}
	criticalOutbounds := builder.criticalOutbounds(len(outbounds))
	for i, group := range outbounds {
		group.CheckAsync = group.ChecksConnectivity() && !criticalOutbounds[i]
	}
	for _, group := range groups {
		if id, ok := outboundName2Id[group.Name]; ok && (group.CheckAsync || group.Present["check_async"]) {
			outbounds[id].CheckAsync = group.CheckAsync
		}
	}
	routingMatcher, err := builder.BuildUserspace()
	if err != nil {
		return nil, oops.Errorf("RoutingMatcherBuilder.BuildUserspace: %w", err)
	}
	// Back skip_while_noalive rule evaluation with the core's in-memory
	// mirror of outbound connectivity.
	routingMatcher.outboundUsable = core.outboundUsable

	wanInterface, autoWan := splitWanInterfaces(global.WanInterface)

	clients := make(map[string]config.Client, len(conf.Client))
	for _, client := range conf.Client {
		clients[client.Name] = client
	}
	ctx, cancel := context.WithCancel(context.Background())
	tcpSetupCtx, cancelTCPSetups := context.WithCancel(ctx)
	plane = &ControlPlane{
		core:                      core,
		settings:                  runtimeSettings,
		mitmClients:               mitmClients,
		deviceRoutes:              core.bpf.deviceRoutes,
		closeOnRouteChange:        global.RouteChangeBehavior == "close",
		apiToken:                  global.APIToken,
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
		fallbackResolver:          global.FallbackResolver,
		mptcp:                     global.Mptcp,
	}
	for _, predicate := range builder.destination.predicates {
		if predicate.domain && plane.sniffingTimeout <= 0 {
			plane.sniffingTimeout = time.Second
			break
		}
	}
	// Stop connectivity checks after DNS forwarders have been retired. A
	// forwarder close is bounded, so a broken tunneled Conn.Close cannot block
	// the remainder of control-plane shutdown indefinitely.
	plane.deferFuncs = append(plane.deferFuncs, plane.closeOutbounds)
	// Close plugin transports (registered below) before their resolver. The
	// closure follows the final controller after preparation replaces it.
	plane.deferFuncs = append(plane.deferFuncs, func() error {
		if plane.dnsController != nil {
			return plane.dnsController.Close()
		}
		return nil
	})

	for _, group := range outbounds {
		group.DeferStats()
	}
	if err := plane.restoreRuntimeSettings(false); err != nil {
		return nil, err
	}
	connectivityStarted := time.Now()
	waiters, err := plane.startConnectivityChecks()
	if err != nil {
		return nil, err
	}
	remaining := max(initialConnectivityTimeout-time.Since(connectivityStarted), 0)
	if err := waitForStartupConnectivity(waiters, remaining, startupCtx.Done()); err != nil {
		return nil, err
	}
	log.WithField("duration", time.Since(connectivityStarted)).Info("Initial connectivity startup phase finished")

	if loadMITM != nil {
		if err := plane.prepareMITM(startupCtx, conf, &preparedRules, outboundName2Id, loadMITM); err != nil {
			return nil, err
		}
	}
	if log.IsLevelEnabled(log.DebugLevel) {
		var debugBuilder strings.Builder
		for _, rule := range preparedRules.routing {
			debugBuilder.WriteString(rule.String(true, false, false) + "\n")
		}
		log.Debugf("RoutingA:\n%vfallback: %v\n", debugBuilder.String(), routingA.Fallback)
	}
	if err := startupCtx.Err(); err != nil {
		return nil, err
	}
	if plane.dnsController, err = plane.newDNSController(dnsConfig, preparedRules, core.domainRegistry); err != nil {
		return nil, err
	}
	dnsConfig.Routing.Request.Rules = nil
	dnsConfig.Routing.Response.Rules = nil

	plane.apiBypass = preparedRules.apiBypass
	return plane, nil
}
