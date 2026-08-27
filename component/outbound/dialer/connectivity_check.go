/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
)

const (
	checkBackoffInitialInterval = time.Second
	initialCheckInterval        = 180 * time.Second
	initialCheckMaxInterval     = time.Hour
	discoveryCheckInterval      = 15 * time.Minute
	// initialCheckTimeout is the maximum time startup waits for a dialer's
	// initial result. The checker keeps retrying in the background afterwards.
	initialCheckTimeout = 60 * time.Second
)

type checkDNSOption struct {
	DnsPort uint16
	*netutils.Ip46
}

func parseCheckDNSOption(dnsHostPort []string) (*checkDNSOption, error) {
	if len(dnsHostPort) == 0 {
		return nil, oops.Errorf("parseCheckDNSOption: bad format: empty")
	}

	host, rawPort, err := net.SplitHostPort(dnsHostPort[0])
	if err != nil {
		return nil, oops.Wrapf(err, "parseCheckDNSOption: failed to split host and port")
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil {
		return nil, oops.Errorf("bad port: %v", err)
	}
	var ip46 *netutils.Ip46
	if len(dnsHostPort) > 1 {
		ip46 = new(netutils.Ip46)
		for _, raw := range dnsHostPort[1:] {
			addr, err := netip.ParseAddr(raw)
			if err != nil {
				return nil, oops.Wrapf(err, "parseCheckDNSOption: invalid IP address")
			}
			if addr.Is4() || addr.Is4In6() {
				ip46.Ip4 = addr
			} else if addr.Is6() {
				ip46.Ip6 = addr
			}
			if ip46.Ip4.IsValid() && ip46.Ip6.IsValid() {
				break
			}
		}
	} else {
		ip46, err = netutils.ParseOrResolveIp46(host)
		if err != nil {
			return nil, oops.Wrapf(err, "parseCheckDNSOption: failed to resolve ip for %v", host)
		}
		if !ip46.IsValid() {
			return nil, oops.Errorf("ResolveIp46: no valid ip for %v", host)
		}
	}
	return &checkDNSOption{DnsPort: uint16(port), Ip46: ip46}, nil
}

type CheckDnsOptionRaw struct {
	opt *checkDNSOption
	mu  sync.Mutex
	Raw []string
}

func (c *CheckDnsOptionRaw) Option() (*checkDNSOption, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.opt == nil {
		opt, err := parseCheckDNSOption(c.Raw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse udp_check_dns: %w", err)
		}
		c.opt = opt
	}
	return c.opt, nil
}

type checkOption struct {
	networkType *common.NetworkType
	probe       func(context.Context, *common.NetworkType) (bool, error)
}

func (d *Dialer) checkDNSConnectivity(ctx context.Context, networkType *common.NetworkType) (bool, error) {
	opt, err := d.CheckDnsOptionRaw.Option()
	if err != nil {
		return false, err
	}

	var ip netip.Addr
	switch networkType.IpVersion {
	case consts.IpVersionStr_4:
		ip = opt.Ip4
	case consts.IpVersionStr_6:
		ip = opt.Ip6
	}
	if !ip.IsValid() {
		log.WithFields(log.Fields{
			"link":    d.CheckDnsOptionRaw.Raw,
			"node":    d.Name,
			"network": networkType.String(),
		}).Debugln("Skip connectivity check due to no DNS record")
		return false, nil
	}
	return d.dnsCheck(ctx, netip.AddrPortFrom(ip, opt.DnsPort), string(networkType.L4Proto))
}

func (d *Dialer) createCheckOptions() []*checkOption {
	networkTypes := []*common.NetworkType{
		{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_6},
		{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4},
		{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_6},
		{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4},
	}
	options := make([]*checkOption, 0, len(networkTypes))
	for _, networkType := range networkTypes {
		options = append(options, &checkOption{networkType: networkType, probe: d.checkDNSConnectivity})
	}
	return options
}

func (d *Dialer) ActivateCheck(wg *sync.WaitGroup) {
	d.mu.Lock()
	if d.group == nil || d.initialCheck == InitialCheckDisabled || d.checkActivated || d.ctx.Err() != nil {
		d.mu.Unlock()
		return
	}
	d.checkActivated = true
	blocking := d.initialCheck == InitialCheckBlocking
	d.checkWG.Add(1)
	d.mu.Unlock()

	checker := newConnectivityChecker(d, d.createCheckOptions())
	go func() {
		defer d.checkWG.Done()
		checker.run()
	}()
	if !blocking {
		return
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-d.readyCh:
		case <-time.After(initialCheckTimeout):
			log.WithField("node", d.Name).Warnf(
				"Initial check not finished in %v; startup continues and checking remains active",
				initialCheckTimeout,
			)
		case <-d.ctx.Done():
		}
	}()
}

// RequestConnectivityCheck asks the checker to run as soon as practical.
// Requests are coalesced with an in-flight round.
func (d *Dialer) RequestConnectivityCheck() {
	d.mu.Lock()
	if d.ctx.Err() != nil {
		d.mu.Unlock()
		return
	}
	d.checkRequested = true
	d.mu.Unlock()
	d.signalConnectivityCheck()
}

func (d *Dialer) signalConnectivityCheck() {
	select {
	case <-d.ctx.Done():
	case d.checkCh <- struct{}{}:
	default:
	}
}

func (d *Dialer) connectivityCheckRequested() bool {
	d.mu.RLock()
	requested := d.checkRequested
	d.mu.RUnlock()
	return requested
}

func (d *Dialer) beginConnectivityCheck() bool {
	d.mu.Lock()
	requested := d.checkRequested
	d.checkRequested = false
	d.mu.Unlock()
	return requested
}

// ReportDataPlaneFailure asks a probe to confirm a failure observed outside
// health checking. The first report determines the failure episode start.
func (d *Dialer) ReportDataPlaneFailure() {
	d.mu.Lock()
	if d.ctx.Err() != nil {
		d.mu.Unlock()
		return
	}
	if d.initialCheck != InitialCheckDisabled && d.healthy && d.failureReportedAt.IsZero() {
		d.failureReportedAt = time.Now()
	}
	d.checkRequested = true
	stats.RecordNodeConnFail(d.StatsKey())
	d.mu.Unlock()
	d.signalConnectivityCheck()
}

func jitterCheckInterval(interval time.Duration) time.Duration {
	spread := interval / 5
	if spread <= 0 {
		return interval
	}
	return interval - spread + time.Duration(fastrand.Int63n(int64(2*spread+1)))
}

type checkKind uint8

const (
	checkInitial checkKind = iota
	checkHealth
	checkDiscovery
)

type probeResult struct {
	option  *checkOption
	ok      bool
	latency time.Duration
	err     error
}

type checkResult struct {
	kind       checkKind
	primary    int
	seq        uint64
	connectErr error
	probes     []probeResult
}

type appliedCheck struct {
	accepted         bool
	success          bool
	initialDone      bool
	pendingDiscovery bool
	primary          int
	requested        bool
}

type connectivityChecker struct {
	d       *Dialer
	options []*checkOption
	results chan checkResult

	running     bool
	runningKind checkKind
	cancel      context.CancelFunc
	observedSeq uint64
	primary     int
	initialDone bool
	readyOnce   sync.Once

	initialInterval time.Duration
	healthInterval  time.Duration
	backingOff      bool
	staggerNext     bool
	healthDue       bool
	discoveryDue    bool

	healthTimer        *time.Timer
	discoveryTimer     *time.Timer
	discoveryScheduled bool
}

func newConnectivityChecker(d *Dialer, options []*checkOption) *connectivityChecker {
	healthTimer := time.NewTimer(time.Hour)
	healthTimer.Stop()
	discoveryTimer := time.NewTimer(time.Hour)
	discoveryTimer.Stop()
	healthInterval := d.CheckInterval
	if healthInterval > 0 {
		healthInterval = time.Duration(fastrand.Int63n(int64(healthInterval)))
	}
	return &connectivityChecker{
		d:               d,
		options:         options,
		results:         make(chan checkResult, 1),
		primary:         -1,
		initialInterval: initialCheckInterval,
		healthInterval:  healthInterval,
		healthTimer:     healthTimer,
		discoveryTimer:  discoveryTimer,
	}
}

func (c *connectivityChecker) closeReady() {
	c.readyOnce.Do(func() { close(c.d.readyCh) })
}

func (c *connectivityChecker) start(kind checkKind) {
	if c.running {
		if kind == checkDiscovery {
			c.discoveryDue = true
		} else if c.runningKind == checkDiscovery {
			c.healthDue = true
		}
		return
	}
	if kind != checkDiscovery {
		c.healthTimer.Stop()
	}
	if kind == checkDiscovery {
		c.discoveryTimer.Stop()
		c.discoveryScheduled = false
	}
	ctx, cancel := context.WithCancel(c.d.ctx)
	if kind != checkDiscovery {
		if c.d.beginConnectivityCheck() {
			c.resetForRequest()
		}
	}
	c.running = true
	c.runningKind = kind
	c.cancel = cancel
	primary := c.primary
	go func() { c.results <- c.perform(ctx, kind, primary) }()
}

func (c *connectivityChecker) scheduleHealth(delay time.Duration) {
	c.healthTimer.Reset(delay)
}

func (c *connectivityChecker) scheduleDiscovery(pending bool) {
	if !pending || !c.d.Healthy() {
		c.discoveryTimer.Stop()
		c.discoveryScheduled = false
		return
	}
	if !c.discoveryScheduled {
		c.discoveryTimer.Reset(discoveryCheckInterval)
		c.discoveryScheduled = true
	}
}

func (c *connectivityChecker) nextHealthKind() (checkKind, bool) {
	if !c.initialDone {
		return checkInitial, true
	}
	return checkHealth, c.primary >= 0
}

func (c *connectivityChecker) requestHealth() {
	kind, ok := c.nextHealthKind()
	if ok {
		c.start(kind)
	} else {
		c.d.beginConnectivityCheck()
	}
}

func (c *connectivityChecker) resetForRequest() {
	c.initialInterval = initialCheckInterval
	c.healthInterval = c.d.CheckInterval
	c.backingOff = false
	c.staggerNext = true
}

func (c *connectivityChecker) handleSessionEvent(event netproxy.StateEvent) {
	c.observedSeq = max(c.observedSeq, event.Seq)
	advanced := c.d.applySessionState(event)
	if c.running {
		if c.runningKind == checkDiscovery && (advanced || event.State == netproxy.SessionConnected && !c.d.healthyAt(event.Seq)) {
			c.healthDue = true
		}
		return
	}
	if event.State == netproxy.SessionClosed {
		return
	}
	if event.State == netproxy.SessionConnected {
		if !c.d.healthyAt(event.Seq) {
			c.requestHealth()
		}
	} else if advanced {
		c.requestHealth()
	}
}

func (c *connectivityChecker) drainSessionEvents(sessionEvents <-chan netproxy.StateEvent, seq uint64) <-chan netproxy.StateEvent {
	for sessionEvents != nil && c.observedSeq < seq {
		select {
		case event, ok := <-sessionEvents:
			if !ok {
				return nil
			}
			c.handleSessionEvent(event)
		case <-c.d.ctx.Done():
			return sessionEvents
		}
	}
	return sessionEvents
}

func (c *connectivityChecker) run() {
	var sessionEvents <-chan netproxy.StateEvent
	if c.d.session != nil {
		sessionEvents = c.d.session.WatchState(c.d.ctx)
	}
	c.start(checkInitial)
	defer c.healthTimer.Stop()
	defer c.discoveryTimer.Stop()

	for {
		select {
		case <-c.d.ctx.Done():
			if c.running {
				c.cancel()
				<-c.results
			}
			return

		case event, ok := <-sessionEvents:
			if !ok {
				sessionEvents = nil
				continue
			}
			c.handleSessionEvent(event)

		case <-c.d.checkCh:
			if !c.d.connectivityCheckRequested() {
				continue
			}
			c.resetForRequest()
			if c.running {
				if c.runningKind == checkDiscovery {
					c.healthDue = true
				}
				continue
			}
			c.requestHealth()

		case <-c.healthTimer.C:
			if c.running {
				c.healthDue = true
			} else {
				c.requestHealth()
			}

		case <-c.discoveryTimer.C:
			c.discoveryScheduled = false
			if c.running {
				c.discoveryDue = true
			} else if c.initialDone && c.d.Healthy() {
				c.start(checkDiscovery)
			}

		case result := <-c.results:
			if c.d.session != nil {
				sessionEvents = c.drainSessionEvents(sessionEvents, result.seq)
			}
			c.running = false
			c.cancel()
			c.cancel = nil
			if c.d.ctx.Err() != nil {
				return
			}
			applied := c.d.applyCheck(result)
			if !applied.accepted {
				c.healthDue = true
			} else {
				if applied.requested {
					c.resetForRequest()
				}
				c.primary = applied.primary
				switch result.kind {
				case checkInitial:
					if applied.initialDone {
						c.initialDone = true
						c.closeReady()
						if applied.success {
							delay := c.healthInterval
							c.healthInterval = c.d.CheckInterval
							c.backingOff = false
							if c.staggerNext {
								delay = jitterCheckInterval(c.healthInterval)
								c.staggerNext = false
							}
							c.scheduleHealth(delay)
						}
					} else {
						c.scheduleHealth(c.initialInterval)
						c.initialInterval = min(c.initialInterval*2, initialCheckMaxInterval)
					}
				case checkHealth:
					if applied.success {
						c.healthInterval = c.d.CheckInterval
						c.backingOff = false
					} else if c.backingOff {
						c.healthInterval = min(c.healthInterval*2, c.d.CheckIntervalMax)
					} else {
						c.healthInterval = checkBackoffInitialInterval
						c.backingOff = true
					}
					delay := c.healthInterval
					if applied.success && c.staggerNext {
						delay = jitterCheckInterval(delay)
						c.staggerNext = false
					}
					c.scheduleHealth(delay)
				}
				c.scheduleDiscovery(applied.pendingDiscovery)
			}

			if c.healthDue {
				c.healthDue = false
				c.requestHealth()
				continue
			}
			if c.discoveryDue {
				c.discoveryDue = false
				if c.initialDone && c.d.Healthy() {
					c.start(checkDiscovery)
				}
			}
		}
	}
}

func (c *connectivityChecker) perform(ctx context.Context, kind checkKind, primary int) checkResult {
	result := checkResult{kind: kind, primary: primary}
	if kind == checkDiscovery {
		session, hasSession := c.d.sessionSnapshot()
		result.seq = session.Seq
		if hasSession && session.State != netproxy.SessionConnected {
			result.connectErr = netproxy.ErrNotConnected
			return result
		}
	} else {
		seq, err := c.connect(ctx)
		result.seq = seq
		if err != nil {
			result.connectErr = err
			return result
		}
	}

	states := c.d.networkStates()
	switch kind {
	case checkInitial:
		result.probes = c.probeMany(ctx, c.optionsFor(states, networkUnknown), 1)
	case checkDiscovery:
		result.probes = c.probeMany(ctx, c.optionsFor(states, networkUnknown, networkUnavailable), 1)
	case checkHealth:
		confirmed := c.optionsFor(states, networkUsable, networkUnavailable)
		first, rest := preferredOption(confirmed, primary)
		if first == nil {
			return result
		}
		firstResult := c.probeOption(ctx, first, 2)
		result.probes = append(result.probes, firstResult)
		if firstResult.ok || ctx.Err() != nil {
			return result
		}
		result.probes = append(result.probes, c.probeMany(ctx, rest, 2)...)
	}
	return result
}

func (c *connectivityChecker) connect(ctx context.Context) (uint64, error) {
	if c.d.session == nil {
		return 0, nil
	}
	snapshot := c.d.session.Snapshot()
	if snapshot.State != netproxy.SessionConnected {
		if err := c.d.session.Connect(ctx); err != nil {
			return c.d.session.Snapshot().Seq, err
		}
	}
	snapshot = c.d.session.Snapshot()
	if snapshot.State != netproxy.SessionConnected {
		return snapshot.Seq, netproxy.ErrNotConnected
	}
	return snapshot.Seq, nil
}

func (d *Dialer) networkStates() [4]networkState {
	d.mu.RLock()
	states := d.networks
	d.mu.RUnlock()
	return states
}

func (c *connectivityChecker) optionsFor(states [4]networkState, wanted ...networkState) []*checkOption {
	options := make([]*checkOption, 0, len(c.options))
	for _, option := range c.options {
		state := states[common.NetworkTypeToIndex(option.networkType)]
		for _, candidate := range wanted {
			if state == candidate {
				options = append(options, option)
				break
			}
		}
	}
	return options
}

func preferredOption(options []*checkOption, primary int) (*checkOption, []*checkOption) {
	if len(options) == 0 {
		return nil, nil
	}
	for i, option := range options {
		if common.NetworkTypeToIndex(option.networkType) == primary {
			return option, append(append(make([]*checkOption, 0, len(options)-1), options[:i]...), options[i+1:]...)
		}
	}
	return options[0], options[1:]
}

func (c *connectivityChecker) probeMany(ctx context.Context, options []*checkOption, attempts int) []probeResult {
	results := make([]probeResult, len(options))
	var wg sync.WaitGroup
	for i, option := range options {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = c.probeOption(ctx, option, attempts)
		}()
	}
	wg.Wait()
	return results
}

func (c *connectivityChecker) probeOption(ctx context.Context, option *checkOption, attempts int) probeResult {
	first := c.d.probe(ctx, option)
	if first.ok || attempts == 1 || ctx.Err() != nil {
		return first
	}
	retry := c.d.probe(ctx, option)
	if retry.ok {
		return retry
	}
	return first
}

func (d *Dialer) applyCheck(result checkResult) appliedCheck {
	d.mu.Lock()
	if d.ctx.Err() != nil {
		d.mu.Unlock()
		return appliedCheck{}
	}
	session, hasSession := d.sessionSnapshot()
	if hasSession && session.Seq != result.seq {
		d.mu.Unlock()
		return appliedCheck{}
	}
	if result.connectErr != nil {
		requested := d.checkRequested
		if result.kind != checkDiscovery {
			d.checkRequested = false
		}
		previousHealthy := d.healthy
		pendingDiscovery := false
		for _, state := range d.networks {
			pendingDiscovery = pendingDiscovery || state == networkUnknown || state == networkUnavailable
		}
		group := d.group
		d.mu.Unlock()
		d.logHealthResult(previousHealthy, false, 0, nil, result)
		if group != nil {
			group.group.DialerChanged(d)
		}
		return appliedCheck{
			accepted:         true,
			pendingDiscovery: pendingDiscovery,
			primary:          result.primary,
			requested:        requested,
		}
	}
	if hasSession && session.State != netproxy.SessionConnected {
		d.mu.Unlock()
		return appliedCheck{}
	}

	changed := false
	primary := result.primary
	var successResult *probeResult
	for i := range result.probes {
		probe := &result.probes[i]
		index := common.NetworkTypeToIndex(probe.option.networkType)
		previous := d.networks[index]
		switch result.kind {
		case checkInitial, checkDiscovery:
			if probe.ok {
				d.networks[index] = networkUsable
			} else if previous == networkUnknown && errors.Is(probe.err, netproxy.UnsupportedTunnelTypeError) {
				d.networks[index] = networkUnsupported
			}
		case checkHealth:
			if probe.ok {
				d.networks[index] = networkUsable
			} else {
				d.networks[index] = networkUnavailable
			}
		}
		changed = changed || previous != d.networks[index]
		if successResult == nil && probe.ok {
			successResult = probe
			if result.kind != checkDiscovery {
				primary = index
			}
		}
	}

	pendingDiscovery := false
	unknown := false
	for _, state := range d.networks {
		unknown = unknown || state == networkUnknown
		pendingDiscovery = pendingDiscovery || state == networkUnknown || state == networkUnavailable
	}
	success := successResult != nil && result.connectErr == nil
	initialDone := result.kind != checkInitial || success || !unknown
	group := d.group

	if result.kind == checkDiscovery {
		d.mu.Unlock()
		if changed && group != nil {
			group.group.DialerChanged(d)
		}
		return appliedCheck{
			accepted:         true,
			success:          d.Healthy(),
			initialDone:      initialDone,
			pendingDiscovery: pendingDiscovery,
			primary:          primary,
		}
	}

	requested := d.checkRequested
	d.checkRequested = false
	previousHealthy := d.healthy
	d.healthy = success
	d.healthSeq = result.seq
	failureReportedAt := d.failureReportedAt
	d.failureReportedAt = time.Time{}
	var latency time.Duration
	var networkType *common.NetworkType
	if successResult != nil {
		latency = successResult.latency
		networkType = successResult.option.networkType
	} else if len(result.probes) > 0 {
		networkType = result.probes[0].option.networkType
	}
	if group != nil {
		sample := latency
		if !success {
			sample = group.timeoutPenalty
		}
		if group.movingAverage == 0 {
			group.movingAverage = sample
		} else {
			group.movingAverage = time.Duration(float64(group.movingAverage)*(1-group.emaAlpha) + float64(sample)*group.emaAlpha)
		}
		group.latencies.AppendSample(sample, !success)
	}
	d.mu.Unlock()

	d.logHealthResult(previousHealthy, success, latency, networkType, result)
	stats.RecordNode(d.StatsKey(), d.Property.SubscriptionTag, d.Name, success, true, failureReportedAt)
	if group != nil {
		group.group.DialerChanged(d)
	}
	return appliedCheck{
		accepted:         true,
		success:          success,
		initialDone:      initialDone,
		pendingDiscovery: pendingDiscovery,
		primary:          primary,
		requested:        requested,
	}
}

func (d *Dialer) logHealthResult(previousHealthy, success bool, latency time.Duration, networkType *common.NetworkType, result checkResult) {
	fields := log.Fields{"node": d.Name}
	if networkType != nil {
		fields["network"] = networkType.String()
	}
	if success {
		fields["last"] = latency.Truncate(time.Millisecond).String()
		if stats, ok := d.LatencyStats(); ok {
			fields["avg_10"] = stats.Avg10.Truncate(time.Millisecond).String()
			fields["mov_avg"] = stats.MovingAvg.Truncate(time.Millisecond).String()
		}
		if previousHealthy {
			log.WithFields(fields).Debugln("Connectivity Check")
		} else {
			log.WithFields(fields).Infoln("Connectivity Check")
		}
		return
	}
	err := result.connectErr
	if err == nil && len(result.probes) > 0 {
		err = result.probes[0].err
	}
	if previousHealthy {
		log.WithFields(fields).Warnln(oops.Wrapf(err, "Connectivity Check Failed"))
	} else {
		log.WithFields(fields).Infoln(oops.Wrapf(err, "Connectivity Check Failed"))
	}
}

func (d *Dialer) applySessionState(event netproxy.StateEvent) bool {
	if event.State == netproxy.SessionConnected {
		return false
	}
	d.mu.Lock()
	if d.ctx.Err() != nil || event.Seq <= d.healthSeq {
		d.mu.Unlock()
		return false
	}
	wasHealthy := d.healthy
	failureReportedAt := d.failureReportedAt
	d.healthy = false
	d.healthSeq = event.Seq
	d.failureReportedAt = time.Time{}
	group := d.group
	d.mu.Unlock()
	if wasHealthy {
		stats.RecordNode(d.StatsKey(), d.Property.SubscriptionTag, d.Name, false, false, failureReportedAt)
		if group != nil {
			group.group.DialerChanged(d)
		}
	}
	return true
}

func (d *Dialer) healthyAt(seq uint64) bool {
	d.mu.RLock()
	healthy := d.healthy && d.healthSeq == seq
	d.mu.RUnlock()
	return healthy
}

func (d *Dialer) probe(ctx context.Context, option *checkOption) probeResult {
	start := time.Now()
	ok, err := option.probe(ctx, option.networkType)
	if ok {
		return probeResult{option: option, ok: true, latency: time.Since(start)}
	}
	if err == nil {
		err = oops.Errorf("check func not working")
	} else if strings.HasSuffix(err.Error(), "network is unreachable") {
		err = oops.Errorf("network is unreachable")
	}
	return probeResult{option: option, err: err}
}

func (d *Dialer) dnsCheck(ctx context.Context, dns netip.AddrPort, network string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
	defer cancel()
	addrs, err := netutils.ResolveNetipContext(ctx, d.Dialer, dns, consts.UdpCheckLookupHost, dnsmessage.TypeA, network)
	if err != nil {
		return false, err
	}
	if len(addrs) == 0 {
		return false, oops.Errorf("bad DNS response: no record")
	}
	return true, nil
}
