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
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/pool"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"

	"github.com/daeuniverse/outbound/transport/grpc"
	"github.com/daeuniverse/outbound/transport/meek"
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
)

type ControlPlane struct {
	core       *controlPlaneCore
	deferFuncs []func() error

	// TODO: add mutex?
	outbounds              []*outbound.DialerGroup
	noConnectivityOutbound consts.OutboundIndex
	inConnections          sync.Map

	dnsController *DnsController

	routingMatcher        *RoutingMatcher
	routingMatcherBuilder *RoutingMatcherBuilder

	ctx    context.Context
	cancel context.CancelFunc

	muRealDomainSet sync.Mutex
	realDomainSet   *bloom.BloomFilter

	wanInterface []string
	lanInterface []string

	// Fields below are saved at NewControlPlane and consumed by Activate.
	autoConfigKernelParameter  bool
	enableLocalTcpFastRedirect bool

	dialTargetOverride bool
	rerouteMode        consts.RerouteMode
	sniffingTimeout    time.Duration
	sniffVerifyMode    consts.SniffVerifyMode
	tproxyPortProtect  bool
	soMarkFromDae      uint32

	// closedDone is set once Close has fully run (all defer funcs executed,
	// kernel filters detached). InheritDomainRegistry asserts it on the
	// retired plane before rewriting the shared kernel domain map.
	closedDone atomic.Bool

	PrometheusRegistry *prometheus.Registry
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
	// TODO: Some users reported that enabling GSO on the client wgrpcould affect the performance of watching YouTube, so we disabled it by default.
	if _, ok := os.LookupEnv("QUIC_GO_DISABLE_GSO"); !ok {
		os.Setenv("QUIC_GO_DISABLE_GSO", "1")
	}

	kernelVersion, e := internal.KernelVersion()
	if e != nil {
		return nil, oops.Errorf("failed to get kernel version: %w", e)
	}
	/// Check linux kernel requirements.
	// Check version from high to low to reduce the number of user upgrading kernel.
	if err := features.HaveProgramHelper(ebpf.SchedCLS, asm.FnLoop); err != nil {
		return nil, oops.Errorf("%w: your kernel version %v does not support bpf_loop (needed by routing); expect >=%v; upgrade your kernel and try again",
			err,
			kernelVersion.String(),
			consts.BpfLoopFeatureVersion.String())
	}
	if requirement := consts.ChecksumFeatureVersion; kernelVersion.Less(requirement) {
		return nil, oops.Errorf("your kernel version %v does not support checksum related features; expect >=%v; upgrade your kernel and try again",
			kernelVersion.String(),
			requirement.String())
	}
	if requirement := consts.BpfTimerFeatureVersion; len(global.WanInterface) > 0 && kernelVersion.Less(requirement) {
		return nil, oops.Errorf("your kernel version %v does not support bind to WAN; expect >=%v; remove wan_interface in config file and try again",
			kernelVersion.String(),
			requirement.String())
	}
	if requirement := consts.SkAssignFeatureVersion; len(global.LanInterface) > 0 && kernelVersion.Less(requirement) {
		return nil, oops.Errorf("your kernel version %v does not support bind to LAN; expect >=%v; remove lan_interface in config file and try again",
			kernelVersion.String(),
			requirement.String())
	}
	if kernelVersion.Less(consts.BasicFeatureVersion) {
		return nil, oops.Errorf("your kernel version %v does not satisfy basic requirement; expect >=%v",
			kernelVersion.String(),
			consts.BasicFeatureVersion.String())
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
	if _bpf == nil {
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
	var bpf *bpfObjects
	if _bpf != nil {
		if _bpf, ok := _bpf.(*bpfObjects); ok {
			bpf = _bpf
		} else {
			return nil, oops.Errorf("unexpected bpf type: %T", _bpf)
		}
	} else {
		bpf = new(bpfObjects)
		if err = fullLoadBpfObjects(bpf, &loadBpfOptions{
			PinPath:             pinPath,
			BigEndianTproxyPort: uint32(common.Htons(global.TproxyPort)),
			CollectionOptions:   collectionOpts,
		}); err != nil {
			err = oops.Wrapf(err, "load eBPF objects")
			if log.IsLevelEnabled(log.PanicLevel) {
				log.Panicf("%+v", err)
			}
			return nil, err
		}
	}
	log.Infof("Loaded eBPF programs and maps")
	core := newControlPlaneCore(
		bpf,
		&kernelVersion,
		_bpf != nil,
	)
	defer func() {
		if err != nil {
			// Flip back.
			core.Flip()
			_ = core.Close()
		}
	}()

	prometheusRegistry := prometheus.NewRegistry()
	common.InitPrometheus(prometheusRegistry)

	/// DialerGroups (outbounds).
	if global.AllowInsecure {
		log.Warnln("AllowInsecure is enabled, but it is not recommended. Please make sure you have to turn it on.")
	}
	option := dialer.NewGlobalOption(global)

	consts.VerifyRerouteMode(string(global.RerouteMode))
	consts.VerifySniffVerifyMode(string(global.SniffVerifyMode))

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
	routingMatcher, err := builder.BuildUserspace()
	if err != nil {
		return nil, oops.Errorf("RoutingMatcherBuilder.BuildUserspace: %w", err)
	}
	// Back skip_while_noalive rule evaluation with the core's in-memory
	// mirror of outbound connectivity.
	routingMatcher.outboundUsable = core.outboundUsable

	ctx, cancel := context.WithCancel(context.Background())
	plane := &ControlPlane{
		core:                       core,
		outbounds:                  outbounds,
		noConnectivityOutbound:     noConnectivityOutbound,
		routingMatcher:             routingMatcher,
		routingMatcherBuilder:      builder,
		ctx:                        ctx,
		cancel:                     cancel,
		realDomainSet:              bloom.NewWithEstimates(2048, 0.001),
		lanInterface:               common.Deduplicate(global.LanInterface),
		wanInterface:               global.WanInterface,
		autoConfigKernelParameter:  global.AutoConfigKernelParameter,
		enableLocalTcpFastRedirect: global.EnableLocalTcpFastRedirect,
		dialTargetOverride:         global.DialTargetOverride,
		rerouteMode:                global.RerouteMode,
		sniffVerifyMode:            global.SniffVerifyMode,
		sniffingTimeout:            sniffingTimeout,
		tproxyPortProtect:          global.TproxyPortProtect,
		soMarkFromDae:              global.SoMarkFromDae,
		PrometheusRegistry:         prometheusRegistry,
	}
	// Stop connectivity checks after DNS forwarders have been retired. A
	// forwarder close is bounded, so a broken tunneled Conn.Close cannot block
	// the remainder of control-plane shutdown indefinitely.
	plane.deferFuncs = append(plane.deferFuncs, plane.closeOutbounds)
	defer func() {
		if err != nil {
			cancel()
		}
	}()

	/// DNS upstream.
	dnsUpstream, err := dns.New(dnsConfig, &dns.NewOption{
		LocationFinder:          locationFinder,
		UpstreamReadyCallback:   plane.cacheDnsUpstream,
		UpstreamResolverNetwork: "udp",
		InterfaceManager:        core.ifmgr,
	})
	if err != nil {
		return nil, err
	}
	// Init immediately to avoid DNS leaking in the very beginning because param control_plane_dns_routing will
	// be set in callback.
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
// It must be called exactly once after NewControlPlane succeeds. Failures here
// are not recoverable: the BPF state may be partially committed, so the caller
// is expected to close the plane and exit.
func (c *ControlPlane) Activate() error {
	core := c.core
	core.lifecycleMu.Lock()
	defer core.lifecycleMu.Unlock()
	if core.closed.Err() != nil {
		return net.ErrClosed
	}
	builder := c.routingMatcherBuilder
	c.routingMatcherBuilder = nil

	// Reset the global grpc/meek transport caches so dials made from now on
	// use the new configuration. This belongs to the commit phase: during
	// the build phase of a reload the previous plane is still serving and
	// must keep its cached transports, and a failed build must not wipe them.
	grpc.CleanGlobalClientConnectionCache()
	meek.CleanGlobalRoundTripperCache()

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

	// Run initial connectivity checks. We wait for completion so that
	// OutboundConnectivityMap reflects a sensible state before traffic starts.
	wg := new(sync.WaitGroup)
	for _, g := range c.outbounds {
		for _, d := range g.Dialers {
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
	if len(c.lanInterface) > 0 {
		if c.autoConfigKernelParameter {
			_ = SetIpv4forward("1")
			_ = setForwarding("all", consts.IpVersionStr_6, "1")
		}
		for _, ifname := range c.lanInterface {
			core.bindLan(ifname, c.autoConfigKernelParameter)
		}
	}
	if len(c.wanInterface) > 0 {
		if err := core.setupSkPidMonitor(); err != nil {
			log.Warnf("%+v", oops.Wrapf(err, "cgroup2 is not enabled; pname routing cannot be used"))
		}
		if c.enableLocalTcpFastRedirect {
			if err := core.setupLocalTcpFastRedirect(); err != nil {
				log.Warnf("%+v", oops.Wrapf(err, "failed to setup local tcp fast redirect"))
			}
		}
		for _, ifname := range c.wanInterface {
			if len(c.lanInterface) > 0 && c.autoConfigKernelParameter {
				// FIXME: Code is not elegant here.
				// bindLan setting conf.ipv6.all.forwarding=1 suppresses accept_ra=1,
				// thus we set it 2 as a workaround.
				// See https://sysctl-explorer.net/net/ipv6/accept_ra/ for more information.
				acceptRa := sysctl.Keyf("net.ipv6.conf.%v.accept_ra", ifname)
				if val, _ := acceptRa.Get(); val == "1" {
					_ = acceptRa.Set("2", false)
				}
			}
			core.bindWan(ifname, c.autoConfigKernelParameter)
		}
	}
	if err := core.bindDaens(); err != nil {
		return oops.Errorf("bindDaens: %w", err)
	}
	return nil
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
	// if group.TcpCheckUrl != nil {
	// 	result.TcpCheckUrl = group.TcpCheckUrl
	// 	changed = true
	// }
	// if group.TcpCheckHttpMethod != "" {
	// 	result.TcpCheckHttpMethod = group.TcpCheckHttpMethod
	// 	changed = true
	// }
	if group.UdpCheckDns != nil {
		result.UdpCheckDns = group.UdpCheckDns
		changed = true
	}
	if group.CheckInterval != 0 {
		result.CheckInterval = group.CheckInterval
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

// EjectBpf will resect bpf from destroying life-cycle of control plane.
func (c *ControlPlane) EjectBpf() *bpfObjects {
	return c.core.EjectBpf()
}
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
// shared kernel map while the old plane's tc filters might still read
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
		typ := dnsmessage.TypeA
		answers := []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   dnsmessage.CanonicalName(fqdn),
				Rrtype: typ,
				Class:  dnsmessage.ClassINET,
				Ttl:    0, // Must be zero.
			},
			A: dnsUpstream.Ip4.AsSlice(),
		}}
		c.dnsController.registerAnswersNoExpiry(queryInfo{qname: fqdn, qtype: typ}, answers)
	}

	if dnsUpstream.Ip6.IsValid() {
		typ := dnsmessage.TypeAAAA
		answers := []dnsmessage.RR{&dnsmessage.AAAA{
			Hdr: dnsmessage.RR_Header{
				Name:   dnsmessage.CanonicalName(fqdn),
				Rrtype: typ,
				Class:  dnsmessage.ClassINET,
				Ttl:    0, // Must be zero.
			},
			AAAA: dnsUpstream.Ip6.AsSlice(),
		}}
		c.dnsController.registerAnswersNoExpiry(queryInfo{qname: fqdn, qtype: typ}, answers)
	}
}

// verified 返回 domain 是不是 dst 的域名
// shouldReroute 返回 Kernel 是否有可能没有正确 Route
// SniffVerifyMode_Loose 在这个域名存在时, 通过认证
// SniffVerifyMode_Strict 在这个域名尝试过对应的 DNS 解析时, 通过认证
func (c *ControlPlane) VerifySniff(outbound consts.OutboundIndex, dst netip.AddrPort, domain string) (verified bool, shouldReroute bool) {
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
				if ip46, err := netutils.ResolveIp46(fqdn); err == nil && ip46.IsValid() {
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
	port        uint16
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
	// Serve on duplicates of the shared listener sockets. The duplicates are
	// closed when this plane is retired, so the loops below stop accepting
	// immediately instead of racing the next plane for the shared listener;
	// connections and packets already queued on the shared sockets are left
	// for the next plane.
	tcpFile, err := listener.tcpListener.(*net.TCPListener).File()
	if err != nil {
		return oops.Errorf("failed to retrieve copy of the underlying TCP connection file")
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		return tcpFile.Close()
	})
	if err := c.core.bpf.ListenSocketMap.Update(consts.ZeroKey, uint64(tcpFile.Fd()), ebpf.UpdateAny); err != nil {
		return err
	}
	tcpListener, err := net.FileListener(tcpFile)
	if err != nil {
		return oops.Errorf("failed to duplicate the TCP listener: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, tcpListener.Close)

	udpFile, err := listener.packetConn.(*net.UDPConn).File()
	if err != nil {
		return oops.Errorf("failed to retrieve copy of the underlying UDP connection file")
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		return udpFile.Close()
	})
	if err := c.core.bpf.ListenSocketMap.Update(consts.OneKey, uint64(udpFile.Fd()), ebpf.UpdateAny); err != nil {
		return err
	}
	udpPacketConn, err := net.FilePacketConn(udpFile)
	if err != nil {
		return oops.Errorf("failed to duplicate the UDP socket: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, udpPacketConn.Close)
	serveUdpConn := udpPacketConn.(*net.UDPConn)

	sentReady = true
	readyChan <- true
	go func() {
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
			go func(lconn net.Conn) {
				c.inConnections.Store(lconn, struct{}{})
				defer c.inConnections.Delete(lconn)
				if err := c.handleConn(lconn); err != nil && c.ctx.Err() == nil {
					if log.IsLevelEnabled(log.DebugLevel) {
						log.Warnf("%+v", oops.Wrapf(err, "handleConn"))
					} else {
						log.Warnf("%v", oops.Wrapf(err, "handleConn"))
					}
				}
			}(lconn)
		}
	}()
	go func() {
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

			// Debug:
			// t := time.Now()
			DefaultUdpTaskPool.EmitTask(src, func() {
				defer pool.PutBuffer(data)
				if e := c.handlePkt(serveUdpConn, data, src, dst, false); e != nil && c.ctx.Err() == nil {
					if log.IsLevelEnabled(log.DebugLevel) {
						log.Warnf("%+v", oops.Wrapf(e, "handlePkt"))
					} else {
						log.Warnf("%v", oops.Wrapf(e, "handlePkt"))
					}
				}
			})
			// if d := time.Since(t); d > 100*time.Millisecond {
			// 	log.Println(d)
			// }
		}
	}()
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
	listenAddr := net.JoinHostPort("0.0.0.0", strconv.Itoa(int(port)))
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
		port:        port,
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
		l4proto      consts.L4ProtoStr
		ipversion    consts.IpVersionStr
		bestDialer   *dialer.Dialer
		bestOutbound *outbound.DialerGroup
		bestTarget   netip.AddrPort
		// dialMark     uint32
	)
	var networkType common.NetworkType
	// Get the min latency path.
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
			// TODO: Mark
			outboundIndex, _, _, err := c.Route(req.src, netip.AddrPortFrom(dAddr, dnsUpstream.Port), dnsUpstream.Hostname, proto.ToL4ProtoType(), req.routingResult)
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
			l4proto = proto
			ipversion = ver
			// dialMark = mark
			break
		}
	}
	if bestDialer == nil {
		return nil, oops.Errorf("no proper dialer for DNS upstream: %v", dnsUpstream.String())
	}
	switch ipversion {
	case consts.IpVersionStr_4:
		bestTarget = netip.AddrPortFrom(dnsUpstream.Ip4, dnsUpstream.Port)
	case consts.IpVersionStr_6:
		bestTarget = netip.AddrPortFrom(dnsUpstream.Ip6, dnsUpstream.Port)
	}
	if log.IsLevelEnabled(log.TraceLevel) {
		log.WithFields(log.Fields{
			"ipversions": ipversions,
			"l4protos":   l4protos,
			"upstream":   dnsUpstream.String(),
			"choose":     string(l4proto) + "+" + string(ipversion),
			"use":        bestTarget.String(),
			"outbound":   bestOutbound.Name,
			"dialer":     bestDialer.Name,
		}).Traceln("Choose DNS path")
	}
	return &dialArgument{
		networkType: networkType,
		Dialer:      bestDialer,
		Outbound:    bestOutbound,
		Target:      bestTarget,
		// mark:         dialMark,
	}, nil
}

func (c *ControlPlane) AbortConnections() (err error) {
	var errs []error
	c.inConnections.Range(func(key, value any) bool {
		if err = key.(net.Conn).Close(); err != nil {
			errs = append(errs, err)
		}
		return true
	})
	return errors.Join(errs...)
}

// closeOutbounds stops the connectivity checks of all outbound groups.
func (c *ControlPlane) closeOutbounds() (err error) {
	for _, g := range c.outbounds {
		if e := g.Close(); e != nil {
			if err != nil {
				err = oops.Errorf("%w; %v", err, e)
			} else {
				err = e
			}
		}
	}
	return err
}

func (c *ControlPlane) Close() (err error) {
	c.core.lifecycleMu.Lock()
	defer c.core.lifecycleMu.Unlock()
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
	c.cancel()
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
