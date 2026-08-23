/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/rlimit"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control/internal/splice"
	"github.com/daeuniverse/dae/pkg/config_parser"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/pool"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"

	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
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
	udpEndpoints           *UdpEndpointPool

	dnsController *DnsController

	routingMatcher        *RoutingMatcher
	routingMatcherBuilder *RoutingMatcherBuilder

	ctx             context.Context
	cancel          context.CancelFunc
	tcpSetupCtx     context.Context
	cancelTCPSetups context.CancelFunc

	ingressMu      sync.Mutex
	ingress        *controlPlaneIngress
	ingressRetired bool

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

	PrometheusRegistry *prometheus.Registry
}

func splitWanInterfaces(ifnames []string) (manual []string, auto bool) {
	for _, ifname := range common.Deduplicate(ifnames) {
		if ifname == "auto" {
			auto = true
			continue
		}
		manual = append(manual, ifname)
	}
	return manual, auto
}

// TODO: 统一 Outbound 中的DNS解析器
// TODO: Hy2 的 mark 支持
// TODO: Connectivity Check Failed 仅将状态变更作为 Warning、
// HandlePkt HandleConn 分割 Route 和 Dial
//
// NewControlPlane validates the configuration and builds a control plane in
// memory. It loads external resources (e.g. geoip) and verifies they are
// usable, but it does NOT modify shared BPF maps and does NOT bind to any
// network interfaces. Call Activate to commit the configuration to the kernel.
// This split lets reload abort cleanly when the new config or its referenced
// resources are invalid, leaving the previously running control plane intact.
func NewControlPlane(
	_bpf interface{},
	tagToNodeList map[string][]string,
	groups []config.Group,
	routingA *config.Routing,
	global *config.Global,
	dnsConfig *config.Dns,
	externGeoDataDirs []string,
) (c *ControlPlane, err error) {
	global.SoMarkFromDae = common.EffectiveSoMarkFromDae(global.SoMarkFromDae)
	if err = common.ValidateSoMarkFromDae(global.SoMarkFromDae); err != nil {
		return nil, err
	}
	reusedBpf, err := validateReusableBpfState(_bpf, global.SoMarkFromDae)
	if err != nil {
		return nil, err
	}
	// TODO: Some users reported that enabling GSO on the client wgrpcould affect the performance of watching YouTube, so we disabled it by default.
	if _, ok := os.LookupEnv("QUIC_GO_DISABLE_GSO"); !ok {
		os.Setenv("QUIC_GO_DISABLE_GSO", "1")
	}

	kernelVersion, e := internal.KernelVersion()
	if e != nil {
		return nil, oops.Errorf("failed to get kernel version: %w", e)
	}
	if kernelVersion.Less(consts.MinimumKernelVersion) {
		return nil, oops.Errorf("your kernel version %v does not satisfy the minimum requirement; expect >=%v",
			kernelVersion.String(), consts.MinimumKernelVersion.String())
	}
	if err := features.HaveProgramHelper(ebpf.SchedCLS, asm.FnLoop); err != nil {
		return nil, oops.Errorf("%w: bpf_loop is unavailable but required by routing", err)
	}

	/// Allow the current process to lock memory for eBPF resources.
	if err = rlimit.RemoveMemlock(); err != nil {
		return nil, oops.Errorf("rlimit.RemoveMemlock:%v", err)
	}

	/// Init DaeNetns.
	InitDaeNetns()
	if err = InitSysctlManager(); err != nil {
		return nil, err
	}

	if err = GetDaeNetns().Setup(); err != nil {
		return nil, oops.Errorf("failed to setup dae netns: %w", err)
	}
	pinPath := filepath.Join(consts.BpfPinRoot, consts.AppName)
	if err = os.MkdirAll(pinPath, 0755); err != nil && !os.IsExist(err) {
		if os.IsNotExist(err) {
			log.Warnln("Perhaps you are in a container environment (such as lxc). If so, please use higher virtualization (kvm/qemu).")
		}
		return nil, err
	}

	/// Load pre-compiled programs and maps into the kernel.
	if reusedBpf == nil {
		log.Infof("Loading eBPF programs and maps into the kernel...")
		log.Infof("The loading process takes about 120MB free memory, which will be released after loading. Insufficient memory will cause loading failure.")
	}
	//var bpf bpfObjects
	var ProgramOptions = ebpf.ProgramOptions{
		KernelTypes: nil,
	}
	if log.IsLevelEnabled(log.PanicLevel) {
		ProgramOptions.LogLevel = ebpf.LogLevelBranch | ebpf.LogLevelStats
		// ProgramOptions.LogLevel = ebpf.LogLevelInstruction | ebpf.LogLevelStats
	}
	collectionOpts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
		Programs: ProgramOptions,
	}
	var bpf *bpfState
	if reusedBpf != nil {
		bpf = reusedBpf
	} else {
		bpf = &bpfState{bpfObjects: new(bpfObjects), soMarkFromDae: global.SoMarkFromDae}
		if err = fullLoadBpfObjects(bpf.bpfObjects, pinPath, global.SoMarkFromDae, collectionOpts); err != nil {
			err = oops.Wrapf(err, "load eBPF objects")
			if log.IsLevelEnabled(log.PanicLevel) {
				log.Panicf("%+v", err)
			}
			return nil, err
		}
		spliceRuntime, spliceErr := splice.New(
			collectionOpts,
			DefaultNatTimeoutTCPEstablished,
		)
		if spliceErr != nil {
			log.Warnf("TCP splice is unavailable; falling back to userspace relay: %v", spliceErr)
		} else if spliceRuntime != nil {
			bpf.splice = spliceRuntime
			log.Infof("Loaded optional TCP splice programs")
		}
	}
	log.Infof("Loaded eBPF programs and maps")
	core, err := newControlPlaneCore(
		bpf,
		reusedBpf != nil,
	)
	if err != nil {
		if reusedBpf == nil {
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

	prometheusRegistry := prometheus.NewRegistry()
	common.InitPrometheus(prometheusRegistry)

	/// DialerGroups (outbounds).
	if global.AllowInsecure {
		log.Warnln("AllowInsecure is enabled, but it is not recommended. Please make sure you have to turn it on.")
	}
	option := dialer.NewGlobalOption(global)

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
	var noConnectivityOutbound consts.OutboundIndex
	if global.NoConnectivityBehavior == "direct" {
		noConnectivityOutbound = consts.OutboundDirect
	} else if global.NoConnectivityBehavior == "block" {
		noConnectivityOutbound = consts.OutboundBlock
	} else {
		return nil, oops.Errorf("invalid no_connectivity_behavior: %v", global.NoConnectivityBehavior)
	}

	_direct, directProperty := D.NewDirectDialer(&option.ExtraOption)
	direct := dialer.NewDialer(_direct, option, &dialer.Property{Property: *directProperty}, false)
	_block, blockProperty := D.NewBlockDialer(&option.ExtraOption, func() { /*Dialer Outbound*/ })
	block := dialer.NewDialer(_block, option, &dialer.Property{Property: *blockProperty}, false)
	outbounds := []*outbound.DialerGroup{
		outbound.NewDialerGroup(option, consts.OutboundDirect.String(), outbound.GroupKindAlwaysAlive,
			[]*dialer.Dialer{direct}, []*dialer.Annotation{{}},
			dialer.DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy_Fixed,
				FixedIndex: 0,
			}, nil),
		outbound.NewDialerGroup(option, consts.OutboundBlock.String(), outbound.GroupKindInvisible,
			[]*dialer.Dialer{block}, []*dialer.Annotation{{}},
			dialer.DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy_Fixed,
				FixedIndex: 0,
			}, nil),
	}
	// Filter out groups.
	dialerSet := outbound.NewDialerSetFromLinks(option, prometheusRegistry, tagToNodeList)
	var plane *ControlPlane
	var cancel context.CancelFunc
	defer func() {
		if err != nil {
			if plane == nil {
				_ = closeDialerGroups(outbounds)
			} else {
				cancel()
				for i := len(plane.deferFuncs) - 1; i >= 0; i-- {
					_ = plane.deferFuncs[i]()
				}
			}
			_ = dialerSet.Close()
		}
	}()
	for _, group := range groups {
		policy, err := dialer.NewDialerSelectionPolicyFromGroupParam(&group)
		if err != nil {
			return nil, oops.Errorf("failed to create group %v: %w", group.Name, err)
		}
		dialers, annos, err := dialerSet.FilterAndAnnotate(group.Filter, group.FilterAnnotation, group.NextHop)
		if err != nil {
			return nil, oops.Errorf(`failed to create group "%v": %w`, group.Name, err)
		}
		log.Infof(`Group "%v" node list:`, group.Name)
		for _, d := range dialers {
			log.Infoln("\t" + d.Name)
		}
		if len(dialers) == 0 {
			log.Infoln("\t<Empty>")
		}
		groupOption, err := ParseGroupOverrideOption(group, *global)
		finalOption := option
		if err == nil && groupOption != nil {
			newDialers := make([]*dialer.Dialer, 0)
			for _, d := range dialers {
				newDialer := d.CloneForStatsScope(group.Name)
				newDialer.GlobalOption = groupOption
				newDialers = append(newDialers, newDialer)
			}
			log.Infof(`Group "%v"'s check option has been override.`, group.Name)
			dialers = newDialers
			finalOption = groupOption
		}
		id := uint8(len(outbounds))
		dialerGroup := outbound.NewDialerGroup(finalOption, group.Name, outbound.GroupKindNormal, dialers, annos, *policy,
			core.outboundAliveChangeCallback(id, group.Name, global.NoConnectivityTrySniff, noConnectivityOutbound))
		outbounds = append(outbounds, dialerGroup)
	}

	// Generate outboundName2Id from outbounds.
	if len(outbounds) > int(consts.OutboundUserDefinedMax) {
		return nil, oops.Errorf("too many outbounds")
	}
	outboundName2Id := make(map[string]uint8)
	for i, o := range outbounds {
		if _, exist := outboundName2Id[o.Name]; exist {
			return nil, oops.Errorf("duplicated outbound name: %v", o.Name)
		}
		outboundName2Id[o.Name] = uint8(i)
	}

	/// Routing.
	// Apply rules optimizers.
	locationFinder := assets.NewLocationFinder(externGeoDataDirs)
	var rules []*config_parser.RoutingRule
	if rules, err = routing.ApplyRulesOptimizers(routingA.Rules,
		&routing.AliasOptimizer{},
		&routing.DatReaderOptimizer{LocationFinder: locationFinder},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	); err != nil {
		return nil, oops.Errorf("ApplyRulesOptimizers error:\n%w", err)
	}
	routingA.Rules = nil // Release.
	if log.IsLevelEnabled(log.DebugLevel) {
		var debugBuilder strings.Builder
		for _, rule := range rules {
			debugBuilder.WriteString(rule.String(true, false, false) + "\n")
		}
		log.Debugf("RoutingA:\n%vfallback: %v\n", debugBuilder.String(), routingA.Fallback)
	}
	// Parse rules and build. BuildUserspace is in-memory only and is safe to
	// run during the validation phase; BuildKernspace is deferred to Activate.
	builder, err := NewRoutingMatcherBuilder(rules, outboundName2Id, bpf, routingA.Fallback, core.ifmgr)
	if err != nil {
		return nil, oops.Errorf("NewRoutingMatcherBuilder: %w", err)
	}
	criticalOutbounds := builder.criticalOutbounds(len(outbounds))
	routingMatcher, err := builder.BuildUserspace()
	if err != nil {
		return nil, oops.Errorf("RoutingMatcherBuilder.BuildUserspace: %w", err)
	}
	// Back skip_while_noalive rule evaluation with the core's in-memory
	// mirror of outbound connectivity.
	routingMatcher.outboundUsable = core.outboundUsable

	wanInterface, autoWan := splitWanInterfaces(global.WanInterface)

	ctx, cancel := context.WithCancel(context.Background())
	tcpSetupCtx, cancelTCPSetups := context.WithCancel(ctx)
	plane = &ControlPlane{
		core:                      core,
		outbounds:                 outbounds,
		criticalOutbounds:         criticalOutbounds,
		noConnectivityOutbound:    noConnectivityOutbound,
		tcpConnections:            new(tcpConnectionTracker),
		udpTaskPool:               newUdpTaskPool[netip.AddrPort](DefaultNatTimeoutUDP),
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
		PrometheusRegistry:        prometheusRegistry,
	}
	// Stop connectivity checks after DNS forwarders have been retired. A
	// forwarder close is bounded, so a broken tunneled Conn.Close cannot block
	// the remainder of control-plane shutdown indefinitely.
	plane.deferFuncs = append(plane.deferFuncs, plane.closeOutbounds)

	/// DNS upstream.
	dnsUpstream, err := dns.New(dnsConfig, &dns.NewOption{
		LocationFinder:        locationFinder,
		UpstreamReadyCallback: plane.cacheDnsUpstream,
		InterfaceManager:      core.ifmgr,
	})
	if err != nil {
		return nil, err
	}
	if err = dnsUpstream.CheckUpstreamsFormat(); err != nil {
		return nil, err
	}
	/// Dns controller.
	fixedDomainTtl, err := ParseFixedDomainTtl(dnsConfig.FixedDomainTtl)
	if err != nil {
		return nil, err
	}
	if plane.dnsController, err = NewDnsController(dnsUpstream, &DnsControllerOption{
		MatchBitmap: func(fqdn string) []uint32 {
			return plane.routingMatcher.domainMatcher.MatchDomainBitmap(fqdn)
		},
		DomainRegistry:    core.domainRegistry,
		BestDialerChooser: plane.chooseBestDnsDialer,
		IpVersionPrefer:   dnsConfig.IpVersionPrefer,
		FixedDomainTtl:    fixedDomainTtl,
		SoMarkFromDae:     global.SoMarkFromDae,
	}); err != nil {
		return nil, err
	}
	plane.deferFuncs = append(plane.deferFuncs, plane.dnsController.Close)
	// TODO: 在 DNS Config 不变的情况下，保留 DNSCache

	return plane, nil
}

// Activate commits the in-memory control plane to the kernel:
//   - writes routing rules to BPF maps,
//   - drops stale domain routing entries inherited from the previous plane
//     (when reloading without an adopted domain registry),
//   - binds eBPF programs to LAN/WAN interfaces and the dae netns,
//   - runs the initial connectivity check for outbound dialers.
//
// It must be called exactly once after NewControlPlane succeeds. An activation
// failure is terminal: the BPF state may be partially committed, so the caller
// must close the plane and exit rather than retrying or restoring the old plane.
func (c *ControlPlane) Activate() error {
	core := c.core
	core.lifecycleMu.Lock()
	defer core.lifecycleMu.Unlock()
	if core.closed.Err() != nil {
		return net.ErrClosed
	}
	if !core.isReload {
		if err := cleanupLegacyTCFilters(); err != nil {
			return err
		}
	}
	builder := c.routingMatcherBuilder
	c.routingMatcherBuilder = nil

	if err := builder.BuildKernspace(); err != nil {
		return oops.Errorf("RoutingMatcherBuilder.BuildKernspace: %w", err)
	}

	// This is the first point at which the candidate plane is committed.
	// The caller has already retired the previous plane on reload, so it is
	// now safe to discard stale identities and reload-scoped gauge series.
	c.reconcileStats()
	common.ResetReloadMetrics()

	// On reload without an adopted registry, evict domain routing entries
	// inherited from the previous plane so that they cannot leak into the
	// new rule set. An adopted registry is already in sync with the map and
	// must not be wiped.
	if core.isReload && !core.domainRegistry.Adopted() {
		log.Warnln("Reload without an adopted domain registry: wiping the inherited kernel domain map; domain routing restarts from scratch")
		var key [4]uint32
		var val bpfDomainRouting
		iter := core.bpf.DomainRoutingMap.Iterate()
		for iter.Next(&key, &val) {
			if err := core.bpf.DomainRoutingMap.Delete(&key); err != nil {
				return oops.Errorf("failed to wipe inherited domain routing entry %v: %w", key, err)
			}
		}
		if err := iter.Err(); err != nil {
			return oops.Errorf("failed to iterate inherited domain routing map: %w", err)
		}
	}

	core.netmon.Register(func(previous, current component.HostNetworkSnapshot) {
		if c.ctx.Err() != nil {
			return
		}
		if current.ConnectivityChanged(previous) {
			c.requestConnectivityRechecks()
		}
		if c.autoWan {
			c.requestHostReconcile()
		}
	})

	// Run initial connectivity checks. We wait for completion so that
	// OutboundConnectivityMap reflects a sensible state before traffic starts.
	core.setOutboundRecoveryCallback(c.requestConnectivityRechecks)
	wg := new(sync.WaitGroup)
	for _, g := range c.outbounds {
		if g.Kind == outbound.GroupKindNormal {
			if err := g.InitializeConnectivity(); err != nil {
				return oops.Errorf("initialize outbound %q availability: %w", g.Name, err)
			}
		}
	}
	for _, g := range c.outbounds {
		for _, d := range g.Dialers {
			// Initialize all four map entries before asynchronous checks allow
			// traffic to start with an absent connectivity state.
			d.NotifyStatusChange()
			d.ActivateCheck(wg)
		}
	}
	wg.Wait()
	log.Infof("Initialization is completed. Start to Proxying...")
	for i, g := range c.outbounds {
		if consts.OutboundIndex(i).IsReserved() {
			continue
		}
		g.PrintLatency()
	}

	/// Bind to links. Binding should be advance of dialerGroups to avoid un-routable old connection.
	if err := core.setupExitHandler(); err != nil {
		return oops.Errorf("failed to setup exit handler: %w", err)
	}
	if err := core.bindDaens(); err != nil {
		return oops.Errorf("bindDaens: %w", err)
	}
	core.ifmgr.SetResetCallback(core.resetHostTCXLinks)
	hostEnabled := len(c.lanInterface) > 0 || len(c.wanInterface) > 0 || c.autoWan
	if hostEnabled {
		core.ifmgr.SetChangeCallback(c.requestHostReconcile)
	}
	if len(c.lanInterface) > 0 {
		if c.autoConfigKernelParameter {
			_ = SetIpv4forward("1")
			_ = setForwarding("all", consts.IpVersionStr_6, "1")
		}
		for _, ifname := range c.lanInterface {
			if err := core.bindLan(ifname, c.autoConfigKernelParameter); err != nil {
				return err
			}
		}
	}
	wanEnabled := len(c.wanInterface) > 0 || c.autoWan
	retryHost := false
	if wanEnabled {
		if err := core.ifmgr.RegisterWithPatternSync("*", nil, nil, core.invalidateWanLink); err != nil {
			return oops.Errorf("register WAN link deletion handler: %w", err)
		}
		if err := core.setupSkPidMonitor(); err != nil {
			return oops.Wrapf(err, "setup WAN socket identity monitor")
		}
		for _, ifname := range c.wanInterface {
			if err := core.bindWan(ifname, c.prepareWanInterface); err != nil {
				return err
			}
		}
		retryHost = c.reconcileWan()
	}
	if hostEnabled {
		c.hostReconcileDone = make(chan struct{})
		go c.runHostReconciler()
		if retryHost {
			c.requestHostReconcile()
		}
	}
	SetAnyfromSoMark(c.soMarkFromDae)
	return nil
}

func (c *ControlPlane) prepareWanInterface(ifname string) {
	if len(c.lanInterface) == 0 || !c.autoConfigKernelParameter {
		return
	}
	// IPv6 forwarding suppresses accept_ra=1. Routers that also consume an
	// upstream RA need mode 2 instead.
	acceptRa := sysctl.Keyf("net.ipv6.conf.%v.accept_ra", ifname)
	if val, _ := acceptRa.Get(); val == "1" {
		_ = acceptRa.Set("2", false)
	}
}

func (c *ControlPlane) reconcileWan() bool {
	if c.ctx.Err() != nil {
		return false
	}
	var snapshot *component.HostNetworkSnapshot
	if c.autoWan {
		current := c.core.netmon.Snapshot()
		if current.Revision() != 0 {
			for _, intf := range current.Interfaces {
				c.prepareWanInterface(intf.Name)
			}
			snapshot = &current
		}
	}
	return c.core.reconcileWan(snapshot)
}

func reconcileLanLinks(links []netlink.Link, patterns []string, bind func(netlink.Link) error) (retry bool) {
	for _, link := range links {
		if link.Attrs().Name == hostLinkName {
			continue
		}
		for _, pattern := range patterns {
			matched, _ := path.Match(pattern, link.Attrs().Name)
			if !matched {
				continue
			}
			if err := bind(link); err != nil {
				log.Errorf("bind LAN interface %s: %v", link.Attrs().Name, err)
				retry = true
			}
			break
		}
	}
	return retry
}

func (c *ControlPlane) reconcileLan() bool {
	if c.ctx.Err() != nil || len(c.lanInterface) == 0 {
		return false
	}
	links, err := netlink.LinkList()
	if err != nil {
		log.Errorf("list LAN interfaces: %v", err)
		return true
	}
	return reconcileLanLinks(links, c.lanInterface, func(link netlink.Link) error {
		return c.core.prepareAndBindLanLink(link, c.autoConfigKernelParameter)
	})
}

func (c *ControlPlane) reconcileHostInterfaces() bool {
	retry := c.reconcileLan()
	return c.reconcileWan() || retry
}

func (c *ControlPlane) requestHostReconcile() {
	if c.ctx.Err() != nil {
		return
	}
	select {
	case c.hostReconcileCh <- struct{}{}:
	default:
	}
}

func (c *ControlPlane) runHostReconciler() {
	defer close(c.hostReconcileDone)
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	var retryCh <-chan time.Time
	reconcile := func() {
		if c.reconcileHostInterfaces() {
			if retryCh == nil {
				timer.Reset(5 * time.Second)
				retryCh = timer.C
			}
			return
		}
		if retryCh != nil {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			retryCh = nil
		}
	}
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.hostReconcileCh:
			reconcile()
		case <-retryCh:
			retryCh = nil
			reconcile()
		}
	}
}

func (c *ControlPlane) requestConnectivityRechecks() {
	if c.ctx.Err() != nil {
		return
	}
	seen := make(map[*dialer.Dialer]struct{})
	for _, group := range c.outbounds {
		if group.Kind != outbound.GroupKindNormal {
			continue
		}
		for _, d := range group.Dialers {
			if !d.ChecksConnectivity() {
				continue
			}
			if _, ok := seen[d]; ok {
				continue
			}
			seen[d] = struct{}{}
			d.NotifyConnectivityRecheck()
		}
	}
}

func (c *ControlPlane) reconcileStats() {
	nodesByKey := make(map[string]stats.NodeIdentity)
	groups := make([]string, 0, len(c.outbounds))
	for _, group := range c.outbounds {
		if group.Kind == outbound.GroupKindNormal {
			groups = append(groups, group.Name)
		}
		for _, d := range group.Dialers {
			key := d.StatsKey()
			nodesByKey[key] = stats.NodeIdentity{
				Key:    key,
				Subtag: d.Property.SubscriptionTag,
				Name:   d.Name,
			}
		}
	}
	nodes := make([]stats.NodeIdentity, 0, len(nodesByKey))
	for _, node := range nodesByKey {
		nodes = append(nodes, node)
	}
	stats.Reconcile(nodes, groups)
}

func ParseFixedDomainTtl(ks []config.KeyableString) (map[string]int, error) {
	m := make(map[string]int)
	for _, k := range ks {
		key, value, _ := strings.Cut(string(k), ":")
		key = dnsmessage.CanonicalName(strings.TrimSpace(key))
		ttl, err := strconv.ParseUint(strings.TrimSpace(value), 0, 31)
		if err != nil {
			return nil, oops.Errorf("failed to parse ttl: %v", err)
		}
		m[key] = int(ttl)
	}
	return m, nil
}

func ParseGroupOverrideOption(group config.Group, global config.Global) (*dialer.GlobalOption, error) {
	result := global
	changed := false
	if group.UdpCheckDns != nil {
		result.UdpCheckDns = group.UdpCheckDns
		changed = true
	}
	if group.CheckInterval != 0 {
		result.CheckInterval = group.CheckInterval
		changed = true
	}
	if group.CheckIntervalMax != 0 {
		result.CheckIntervalMax = group.CheckIntervalMax
		changed = true
	}
	if group.CheckTolerance != 0 {
		result.CheckTolerance = group.CheckTolerance
		changed = true
	}
	if changed {
		option := dialer.NewGlobalOption(&result)
		return option, nil
	}
	return nil, nil
}

// EjectBpf releases this plane's cleanup ownership of the shared BPF state and
// returns it for a reload candidate. The state remains unowned until InjectBpf.
func (c *ControlPlane) EjectBpf() *bpfState {
	return c.core.EjectBpf()
}

// InjectBpf makes this plane responsible for closing the shared BPF state.
func (c *ControlPlane) InjectBpf() {
	c.core.InjectBpf()
}

// InheritDomainRegistry transfers the finite domain -> IP registrations of a
// retired plane into this plane's registry, recomputing every domain's match
// bitmap with this plane's routing rules, and syncs the shared kernel domain
// map to the adopted state. Plane-local no-expiry upstream observations are
// rebuilt by the new resolver. This must be called after the old plane is
// retired (its writers stopped, its kernel programs detached) and before
// Activate, which then skips wiping the kernel map. Domain routing and
// sniff verification therefore survive a reload instead of waiting for every
// domain to be re-resolved.
//
// It panics if the old plane is not fully closed: adoption rewrites the
// shared kernel map while the old plane's TCX programs might still read
// it (old rules with new-rule bitmaps = misrouting), and the old
// registry's writers would fight the adopted state.
func (c *ControlPlane) InheritDomainRegistry(old *ControlPlane) {
	if !old.closedDone.Load() {
		panic("InheritDomainRegistry: old control plane is not fully closed")
	}
	c.core.domainRegistry.AdoptFrom(
		old.core.domainRegistry,
		c.routingMatcher.domainMatcher.MatchDomainBitmap,
		time.Now(),
	)
}

func (c *ControlPlane) cacheDnsUpstream(dnsUpstream *dns.Upstream) {
	// Register resolved upstream addresses without expiry so hostname-based
	// domain routing remains valid for the upstream's lifetime.
	fqdn := dnsmessage.CanonicalName(dnsUpstream.Hostname)

	if dnsUpstream.Ip4.IsValid() {
		c.dnsController.registerAddressNoExpiry(
			queryInfo{qname: fqdn, qtype: dnsmessage.TypeA}, dnsUpstream.Ip4,
		)
	}

	if dnsUpstream.Ip6.IsValid() {
		c.dnsController.registerAddressNoExpiry(
			queryInfo{qname: fqdn, qtype: dnsmessage.TypeAAAA}, dnsUpstream.Ip6,
		)
	}
}

// verified 返回 domain 是不是 dst 的域名
// shouldReroute 返回 Kernel 是否有可能没有正确 Route
// SniffVerifyMode_Loose 在这个域名存在时, 通过认证
// SniffVerifyMode_Strict 在这个域名尝试过对应的 DNS 解析时, 通过认证
func (c *ControlPlane) verifySniff(ctx context.Context, dst netip.AddrPort, domain string) (verified bool, shouldReroute bool, err error) {
	if err = ctx.Err(); err != nil {
		return
	}
	if domain == "" {
		return
	}
	fqdn := dnsmessage.CanonicalName(domain)
	// Historical pairing remains valid for sniff verification after the
	// corresponding kernel contribution expires or is capacity-evicted. Keep
	// that trust decision separate from whether the current kernel map could
	// route this connection accurately.
	verification := c.core.domainRegistry.Verify(queryInfo{qname: fqdn, qtype: common.AddrToDnsType(dst.Addr())}, dst.Addr())
	if verification.Registered {
		shouldReroute = !verification.KernelCovered
		switch c.sniffVerifyMode {
		case consts.SniffVerifyMode_None, consts.SniffVerifyMode_Loose:
			verified = true
		case consts.SniffVerifyMode_Strict:
			verified = verification.Paired
		}
	} else {
		// Successful sniff without DNS lookup record.
		shouldReroute = true
		// Check if the domain is in real-domain set (bloom filter).
		switch c.sniffVerifyMode {
		case consts.SniffVerifyMode_None:
			verified = true
		case consts.SniffVerifyMode_Strict:
			verified = false
		case consts.SniffVerifyMode_Loose:
			// TODO: 产生一个真的DNS查询? 这样能被缓存
			c.muRealDomainSet.Lock()
			verified = c.realDomainSet.TestString(fqdn)
			c.muRealDomainSet.Unlock()
			if !verified {
				// TODO: 这里可能可以直接使用正常的 DNS 解析流程, 从而可以得到缓存
				ip46, resolveErr := netutils.ResolveIp46Context(ctx, fqdn)
				if resolveErr != nil {
					if ctxErr := ctx.Err(); ctxErr != nil {
						err = ctxErr
					}
					return
				}
				if ip46.IsValid() {
					// Add it to real-domain set.
					c.muRealDomainSet.Lock()
					c.realDomainSet.AddString(fqdn)
					c.muRealDomainSet.Unlock()
					verified = true
				}
			}
		}
	}
	return
}

func (c *ControlPlane) ChooseDialTarget(outbound consts.OutboundIndex, dst netip.AddrPort, domain string, override bool) (dialTarget string, dialIp bool) {
	if override {
		if strings.HasPrefix(domain, "[") && strings.HasSuffix(domain, "]") {
			// Sniffed domain may be like `[2606:4700:20::681a:d1f]`. We should remove the brackets.
			domain = domain[1 : len(domain)-1]
		}
		if _, err := netip.ParseAddr(domain); err == nil {
			// domain is IPv4 or IPv6 (has colon)
			dialTarget = net.JoinHostPort(domain, strconv.Itoa(int(dst.Port())))
			dialIp = true
		} else if _, _, err := net.SplitHostPort(domain); err == nil {
			// domain is already domain:port
			dialTarget = domain
		} else {
			dialTarget = net.JoinHostPort(domain, strconv.Itoa(int(dst.Port())))
		}
		log.WithFields(log.Fields{
			"from": dst.String(),
			"to":   dialTarget,
		}).Debugln("Rewrite dial target to domain")
	} else {
		dialTarget = dst.String()
		dialIp = true
	}
	return
}

type Listener struct {
	tcpListener net.Listener
	packetConn  net.PacketConn
}

// controlPlaneIngress owns only the duplicated descriptors used by one plane.
// The original Listener remains open across reloads so packets can queue for
// the successor after these descriptors are closed.
type controlPlaneIngress struct {
	closeOnce  sync.Once
	closeErr   error
	closeFuncs []func() error
	loops      sync.WaitGroup
}

func (i *controlPlaneIngress) close() error {
	i.closeOnce.Do(func() {
		var errs []error
		for j := len(i.closeFuncs) - 1; j >= 0; j-- {
			if err := i.closeFuncs[j](); err != nil {
				errs = append(errs, err)
			}
		}
		i.closeErr = errors.Join(errs...)
	})
	return i.closeErr
}

func (c *ControlPlane) openIngress(listener *Listener) (tcpListener net.Listener, serveUdpConn *net.UDPConn, ingress *controlPlaneIngress, err error) {
	c.ingressMu.Lock()
	defer c.ingressMu.Unlock()
	if c.ingressRetired {
		return nil, nil, nil, net.ErrClosed
	}
	if c.ingress != nil {
		return nil, nil, nil, errors.New("control plane ingress is already open")
	}

	ingress = new(controlPlaneIngress)
	ownedIngress := ingress
	defer func() {
		if err != nil {
			_ = ownedIngress.close()
		}
	}()

	tcpFile, err := listener.tcpListener.(*net.TCPListener).File()
	if err != nil {
		return nil, nil, nil, oops.Errorf("failed to retrieve copy of the underlying TCP connection file")
	}
	ingress.closeFuncs = append(ingress.closeFuncs, tcpFile.Close)
	if err = c.core.bpf.ListenSocketMap.Update(uint32(0), uint64(tcpFile.Fd()), ebpf.UpdateAny); err != nil {
		return nil, nil, nil, err
	}
	tcpListener, err = net.FileListener(tcpFile)
	if err != nil {
		return nil, nil, nil, oops.Errorf("failed to duplicate the TCP listener: %w", err)
	}
	ingress.closeFuncs = append(ingress.closeFuncs, tcpListener.Close)

	udpFile, err := listener.packetConn.(*net.UDPConn).File()
	if err != nil {
		return nil, nil, nil, oops.Errorf("failed to retrieve copy of the underlying UDP connection file")
	}
	ingress.closeFuncs = append(ingress.closeFuncs, udpFile.Close)
	if err = c.core.bpf.ListenSocketMap.Update(uint32(1), uint64(udpFile.Fd()), ebpf.UpdateAny); err != nil {
		return nil, nil, nil, err
	}
	udpPacketConn, err := net.FilePacketConn(udpFile)
	if err != nil {
		return nil, nil, nil, oops.Errorf("failed to duplicate the UDP socket: %w", err)
	}
	ingress.closeFuncs = append(ingress.closeFuncs, udpPacketConn.Close)
	serveUdpConn = udpPacketConn.(*net.UDPConn)

	// Register both loops before publishing ingress. Close may run as soon as
	// this function unlocks and must not race a zero-count Wait with Add.
	ingress.loops.Add(2)
	c.ingress = ingress
	return tcpListener, serveUdpConn, ingress, nil
}

func (c *ControlPlane) closeIngress() (*controlPlaneIngress, error) {
	c.ingressMu.Lock()
	c.ingressRetired = true
	ingress := c.ingress
	c.ingressMu.Unlock()
	if ingress == nil {
		return nil, nil
	}
	return ingress, ingress.close()
}

func (l *Listener) Close() error {
	var (
		err  error
		err2 error
	)
	if err, err2 = l.tcpListener.Close(), l.packetConn.Close(); err2 != nil {
		if err == nil {
			err = err2
		} else {
			err = oops.Errorf("%w: %v", err, err2)
		}
	}
	return err
}

func (c *ControlPlane) Serve(readyChan chan<- bool, listener *Listener) (err error) {
	sentReady := false
	defer func() {
		if !sentReady {
			readyChan <- false
		}
	}()
	// Serve on duplicates of the shared listener sockets. Close retires these
	// duplicates before waiting for setup, leaving queued traffic on the shared
	// sockets for the next plane.
	tcpListener, serveUdpConn, ingress, err := c.openIngress(listener)
	if err != nil {
		return err
	}

	go func() {
		defer ingress.loops.Done()
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
			}
			lconn, err := tcpListener.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					log.Errorf("%+v", oops.Wrapf(err, "Error when accept"))
				}
				break
			}
			if !c.tcpConnections.beginSetup(lconn) {
				continue
			}
			go serveTCPConnection(c, lconn, c.tcpSetupCtx, c.tcpConnections)
		}
	}()
	go func() {
		defer ingress.loops.Done()
		buf := pool.GetBuffer(consts.EthernetMtu)
		oob := pool.GetBuffer(120)
		defer pool.PutBuffer(buf)
		defer pool.PutBuffer(oob)
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
			}
			n, oobn, _, src, err := serveUdpConn.ReadMsgUDPAddrPort(buf, oob)
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					log.Errorf("%+v", oops.Wrapf(err, "ReadFromUDPAddrPort: %v", src.String()))
				}
				break
			}
			dst := RetrieveOriginalDest(oob[:oobn])

			src = common.ConvergeAddrPort(src)
			dst = common.ConvergeAddrPort(dst)

			/// Handle DNS
			// To keep consistency with kernel program, we only sniff DNS request sent to 53.
			if dst.Port() == 53 {
				routingResult, err := c.core.RetrieveRoutingResult(src, netip.AddrPort{}, unix.IPPROTO_UDP)
				if err != nil {
					log.Warningf("%+v", oops.Wrapf(err, "No AddrPort presented"))
					continue
				}
				if routingResult.Must == 0 {
					var dnsMessage dnsmessage.Msg
					if err := dnsMessage.Unpack(buf[:n]); err == nil {
						c.dnsController.Handle(&dnsMessage, &udpRequest{
							src:           src,
							dst:           dst,
							routingResult: routingResult,
						})
						continue
					}
				}
			}

			data := pool.GetBuffer(n)
			copy(data, buf[:n])
			taskCtx, cancelTask := context.WithTimeout(c.ctx, consts.DefaultDialTimeout)

			// Debug:
			// t := time.Now()
			if !c.udpTaskPool.emit(src, func() {
				defer cancelTask()
				defer pool.PutBuffer(data)
				if e := c.handlePkt(taskCtx, data, src, dst, false, ""); e != nil && taskCtx.Err() == nil {
					if log.IsLevelEnabled(log.DebugLevel) {
						log.Warnf("%+v", oops.Wrapf(e, "handlePkt"))
					} else {
						log.Warnf("%v", oops.Wrapf(e, "handlePkt"))
					}
				}
			}) {
				cancelTask()
				pool.PutBuffer(data)
			}
			// if d := time.Since(t); d > 100*time.Millisecond {
			// 	log.Println(d)
			// }
		}
	}()
	sentReady = true
	readyChan <- true
	<-c.ctx.Done()
	return nil
}

func (c *ControlPlane) ListenAndServe(readyChan chan<- bool, port uint16) (listener *Listener, err error) {
	// Listen.
	var listenConfig = net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return dialer.TproxyControl(c)
		},
	}
	listenAddr := net.JoinHostPort("", strconv.Itoa(int(port)))
	tcpListener, err := listenConfig.Listen(context.TODO(), "tcp", listenAddr)
	if err != nil {
		return nil, oops.Errorf("listenTCP: %w", err)
	}
	packetConn, err := listenConfig.ListenPacket(context.TODO(), "udp", listenAddr)
	if err != nil {
		_ = tcpListener.Close()
		return nil, oops.Errorf("listenUDP: %w", err)
	}
	listener = &Listener{
		tcpListener: tcpListener,
		packetConn:  packetConn,
	}
	defer func() {
		if err != nil {
			_ = listener.Close()
		}
	}()

	// Serve
	if err = c.Serve(readyChan, listener); err != nil {
		return nil, oops.Errorf("failed to serve: %w", err)
	}

	return listener, nil
}

func (c *ControlPlane) chooseBestDnsDialer(
	req *udpRequest,
	dnsUpstream *dns.Upstream,
) (*dialArgument, error) {
	/// Choose the best l4proto+ipversion dialer, and change taregt DNS to the best ipversion DNS upstream for DNS request.
	// Get available ipversions and l4protos for DNS upstream.
	ipversions, l4protos := dnsUpstream.SupportedNetworks()
	var (
		bestNetworkType   common.NetworkType
		bestDialer        *dialer.Dialer
		bestOutbound      *outbound.DialerGroup
		bestOutboundIndex consts.OutboundIndex
		bestTarget        netip.AddrPort
		dialMark          uint32
	)
	var networkType common.NetworkType
	// Get the first available path in upstream preference order.
	searching := true
	for _, ver := range ipversions {
		for _, proto := range l4protos {
			networkType.L4Proto = proto
			networkType.IpVersion = ver
			var dAddr netip.Addr
			switch ver {
			case consts.IpVersionStr_4:
				dAddr = dnsUpstream.Ip4
			case consts.IpVersionStr_6:
				dAddr = dnsUpstream.Ip6
			default:
				return nil, oops.Errorf("unexpected ipversion: %v", ver)
			}
			target := netip.AddrPortFrom(dAddr, dnsUpstream.Port)
			outboundIndex, mark, _, err := c.Route(req.src, target, dnsUpstream.Hostname, proto.ToL4ProtoType(), req.routingResult)
			if err != nil {
				return nil, err
			}
			if int(outboundIndex) >= len(c.outbounds) {
				return nil, oops.Errorf("bad outbound index: %v", outboundIndex)
			}
			dialerGroup := c.outbounds[outboundIndex]
			// DNS always dial IP.
			d, err := dialerGroup.Select(&networkType)
			if err != nil {
				continue
			}
			bestDialer = d
			bestOutbound = dialerGroup
			bestOutboundIndex = outboundIndex
			bestNetworkType = networkType
			bestTarget = target
			dialMark = mark
			searching = false
			break
		}
		if !searching {
			break
		}
	}
	if bestDialer == nil {
		return nil, oops.Errorf("no proper dialer for DNS upstream: %v", dnsUpstream.String())
	}
	if log.IsLevelEnabled(log.TraceLevel) {
		log.WithFields(log.Fields{
			"ipversions": ipversions,
			"l4protos":   l4protos,
			"upstream":   dnsUpstream.String(),
			"choose":     string(bestNetworkType.L4Proto) + "+" + string(bestNetworkType.IpVersion),
			"use":        bestTarget.String(),
			"outbound":   bestOutbound.Name,
			"dialer":     bestDialer.Name,
		}).Traceln("Choose DNS path")
	}
	return &dialArgument{
		networkType:      bestNetworkType,
		Dialer:           bestDialer,
		connectionDialer: c.directDialerForMark(bestOutboundIndex, dialMark),
		Outbound:         bestOutbound,
		Target:           bestTarget,
		Mark:             dialMark,
	}, nil
}

func (c *ControlPlane) StopAndAbortConnections() (err error) {
	c.abortConnections.Store(true)
	var errs []error
	// Retire ingress first: closing a large connection set must not leave the
	// old Accept/Read calls consuming traffic intended for the successor.
	if _, ingressErr := c.closeIngress(); ingressErr != nil {
		errs = append(errs, ingressErr)
	}
	if c.tcpConnections != nil {
		for _, conn := range c.tcpConnections.stopAndSnapshot() {
			if err = conn.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if c.udpEndpoints != nil {
		c.udpEndpoints.closeAll()
	}
	return errors.Join(errs...)
}

// closeOutbounds stops the connectivity checks of all outbound groups.
func (c *ControlPlane) closeOutbounds() (err error) {
	return closeDialerGroups(c.outbounds)
}

func closeDialerGroups(groups []*outbound.DialerGroup) (err error) {
	transports := make(map[any]*dialer.Dialer)
	for _, g := range groups {
		for _, d := range g.Dialers {
			transports[d.TransportID()] = d
		}
		if e := g.Close(); e != nil {
			if err != nil {
				err = oops.Errorf("%w; %v", err, e)
			} else {
				err = e
			}
		}
	}
	for _, d := range transports {
		if e := d.CloseTransport(); e != nil {
			err = errors.Join(err, e)
		}
	}
	return err
}

func (c *ControlPlane) retireTraffic() error {
	// Closing duplicated ingress first prevents blocked Accept/Read calls from
	// consuming traffic after retirement. TCP setup is canceled independently;
	// accepted UDP tasks drain before the plane context is canceled. Their task
	// contexts can expire while queued and bound context-aware setup operations.
	ingress, ingressErr := c.closeIngress()
	if c.tcpConnections != nil {
		c.tcpConnections.stopAccepting()
	}
	if c.cancelTCPSetups != nil {
		c.cancelTCPSetups()
	}
	if ingress != nil {
		ingress.loops.Wait()
	}
	if c.udpTaskPool != nil {
		c.udpTaskPool.close()
	}
	if c.tcpConnections != nil {
		c.tcpConnections.waitForSetups()
	}
	if c.abortConnections.Load() && c.udpEndpoints != nil {
		// StopAndAbortConnections performs an initial sweep. Repeat after the
		// task drain to catch an endpoint published by an already-accepted task.
		c.udpEndpoints.closeAll()
	}
	if c.cancel != nil {
		c.cancel()
	}
	return ingressErr
}

func (c *ControlPlane) Close() (err error) {
	c.core.lifecycleMu.Lock()
	defer c.core.lifecycleMu.Unlock()
	err = c.retireTraffic()
	if c.hostReconcileDone != nil {
		<-c.hostReconcileDone
	}
	// Invoke defer funcs in reverse order.
	for i := len(c.deferFuncs) - 1; i >= 0; i-- {
		if e := c.deferFuncs[i](); e != nil {
			if err != nil {
				err = oops.Errorf("%w; %v", err, e)
			} else {
				err = e
			}
		}
	}
	if coreErr := c.core.closeLocked(); coreErr != nil {
		if err != nil {
			err = oops.Errorf("%w; %v", err, coreErr)
		} else {
			err = coreErr
		}
	}
	if err == nil {
		c.closedDone.Store(true)
	}
	return err
}
