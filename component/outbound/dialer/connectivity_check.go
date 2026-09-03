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
	supportRetryInitialInterval = 2 * time.Second
	supportRetryMultiplier      = 4
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

func (d *Dialer) ActivateCheck(start <-chan struct{}) {
	d.mu.Lock()
	if d.checkActivated || d.ctx.Err() != nil {
		d.mu.Unlock()
		return
	}
	if d.initialCheck == InitialCheckDisabled {
		d.checkActivated = true
		d.mu.Unlock()
		stats.DefaultStore.RecordNodeState(d.StatsKey(), true, time.Time{})
		return
	}
	if d.group == nil {
		d.mu.Unlock()
		return
	}
	d.checkActivated = true
	d.checkWG.Add(1)
	d.mu.Unlock()

	checker := newConnectivityChecker(d, d.checkDNSConnectivity)
	go func() {
		defer d.checkWG.Done()
		checker.run(start)
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
	startedConfirmation := false
	if d.initialCheck != InitialCheckDisabled && d.healthy && d.failureReportedAt.IsZero() {
		d.failureReportedAt = time.Now()
		startedConfirmation = true
	}
	d.checkRequested = true
	group := d.group
	stats.DefaultStore.RecordNodeConnFail(d.StatsKey())
	d.mu.Unlock()
	if startedConfirmation {
		d.notifyGroup(group, SelectionForceNone)
	}
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
	checkSupport
)

var checkKindName = [...]string{"initial", "health", "support_retry"}

type probeResult struct {
	network common.NetworkIndex
	latency time.Duration
	err     error
}

type checkResult struct {
	kind       checkKind
	seq        uint64
	connectErr error
	probes     []probeResult
}

type appliedCheck struct {
	success       bool
	requested     bool
	healthApplied bool
}

type connectivityChecker struct {
	d       *Dialer
	probe   func(context.Context, *common.NetworkType) (bool, error)
	results chan checkResult

	runningKind checkKind
	cancel      context.CancelFunc
	observedSeq uint64

	retryInterval  time.Duration
	healthInterval time.Duration
	backingOff     bool
	staggerNext    bool
	healthDue      bool
	supportDue     bool

	healthTimer      *time.Timer
	supportTimer     *time.Timer
	supportScheduled bool
}

func newConnectivityChecker(d *Dialer, probe func(context.Context, *common.NetworkType) (bool, error)) *connectivityChecker {
	healthTimer := time.NewTimer(time.Hour)
	healthTimer.Stop()
	supportTimer := time.NewTimer(time.Hour)
	supportTimer.Stop()
	healthInterval := d.CheckInterval
	if healthInterval > 0 {
		healthInterval = time.Duration(fastrand.Int63n(int64(healthInterval)))
	}
	retryInterval := initialRetryInterval(d.CheckIntervalMax)
	return &connectivityChecker{
		d:              d,
		probe:          probe,
		results:        make(chan checkResult, 1),
		retryInterval:  retryInterval,
		healthInterval: healthInterval,
		healthTimer:    healthTimer,
		supportTimer:   supportTimer,
	}
}

func (c *connectivityChecker) start(kind checkKind) {
	if kind != checkSupport {
		c.healthTimer.Stop()
	}
	if kind == checkSupport {
		c.supportTimer.Stop()
		c.supportScheduled = false
	}
	ctx, cancel := context.WithCancel(c.d.ctx)
	if kind != checkSupport {
		if c.d.beginConnectivityCheck() {
			c.resetForRequest()
		}
	}
	c.runningKind = kind
	c.cancel = cancel
	go func() { c.results <- c.perform(ctx, kind) }()
}

func (c *connectivityChecker) scheduleSupport() {
	if !c.supportPending() {
		c.supportTimer.Stop()
		c.supportScheduled = false
		return
	}
	if !c.supportScheduled {
		c.supportTimer.Reset(jitterRetryInterval(c.retryInterval, c.d.CheckIntervalMax))
		c.supportScheduled = true
	}
}

func (c *connectivityChecker) requestHealth() {
	if !c.d.initialCheckCompleted() {
		c.start(checkInitial)
		return
	}
	if firstSupportedNetwork(c.d.networkStates()).Valid() {
		c.start(checkHealth)
		return
	}
	if c.d.beginConnectivityCheck() {
		c.resetForRequest()
	}
	c.scheduleSupport()
}

func (c *connectivityChecker) resetForRequest() {
	retryInterval := initialRetryInterval(c.d.CheckIntervalMax)
	c.retryInterval = retryInterval
	c.healthInterval = c.d.CheckInterval
	c.backingOff = false
	c.staggerNext = true
	c.supportTimer.Stop()
	c.supportScheduled = false
}

func (c *connectivityChecker) handleSessionEvent(event netproxy.StateEvent) {
	c.observedSeq = max(c.observedSeq, event.Seq)
	advanced := c.d.applySessionState(event)
	needsRecovery := event.State == netproxy.SessionConnected && !c.d.healthyAt(event.Seq)
	if needsRecovery {
		c.d.RequestConnectivityCheck()
	}
	if c.cancel != nil {
		if c.runningKind == checkSupport && (advanced || needsRecovery) {
			c.healthDue = true
		}
		return
	}
	if event.State == netproxy.SessionClosed {
		return
	}
	if event.State == netproxy.SessionConnected {
		if needsRecovery {
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

func (c *connectivityChecker) run(start <-chan struct{}) {
	select {
	case <-c.d.ctx.Done():
		return
	case <-start:
	}

	var sessionEvents <-chan netproxy.StateEvent
	if c.d.session != nil {
		sessionEvents = c.d.session.WatchState(c.d.ctx)
	}
	c.start(checkInitial)
	defer c.healthTimer.Stop()
	defer c.supportTimer.Stop()

	for {
		select {
		case <-c.d.ctx.Done():
			if c.cancel != nil {
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
			if c.cancel != nil {
				if c.runningKind == checkSupport {
					c.healthDue = true
				}
				continue
			}
			c.requestHealth()

		case <-c.healthTimer.C:
			if c.cancel != nil {
				c.healthDue = true
			} else {
				c.requestHealth()
			}

		case <-c.supportTimer.C:
			c.supportScheduled = false
			if c.cancel != nil {
				c.supportDue = true
			} else if c.supportPending() {
				c.start(checkSupport)
			}

		case result := <-c.results:
			if c.d.session != nil {
				sessionEvents = c.drainSessionEvents(sessionEvents, result.seq)
			}
			if !c.finish(result) {
				return
			}
		}
	}
}

func (c *connectivityChecker) finish(result checkResult) bool {
	c.cancel()
	c.cancel = nil
	if c.d.ctx.Err() != nil {
		return false
	}

	applied, ok := c.d.applyCheck(result)
	if ok {
		c.updateSchedule(result.kind, applied)
	} else {
		c.healthDue = true
	}
	c.startDeferredCheck()
	return true
}

func (c *connectivityChecker) updateSchedule(kind checkKind, applied appliedCheck) {
	if applied.requested {
		c.resetForRequest()
	}
	switch kind {
	case checkInitial:
		c.updateInitialSchedule(applied.success)
	case checkHealth:
		c.updateHealthSchedule(applied.success)
	case checkSupport:
		c.retryInterval = nextRetryInterval(c.retryInterval, c.d.CheckIntervalMax)
		if applied.healthApplied {
			c.healthDue = false
			c.updateHealthSchedule(true)
		}
	}
	c.scheduleSupport()
}

func (c *connectivityChecker) updateInitialSchedule(success bool) {
	if !c.d.initialCheckCompleted() {
		c.healthTimer.Reset(jitterRetryInterval(c.retryInterval, c.d.CheckIntervalMax))
		c.retryInterval = nextRetryInterval(c.retryInterval, c.d.CheckIntervalMax)
		return
	}
	c.retryInterval = initialRetryInterval(c.d.CheckIntervalMax)
	if !success {
		return
	}
	delay := c.healthInterval
	c.healthInterval = c.d.CheckInterval
	c.backingOff = false
	if c.staggerNext {
		delay = jitterCheckInterval(c.healthInterval)
		c.staggerNext = false
	}
	c.healthTimer.Reset(delay)
}

func (c *connectivityChecker) updateHealthSchedule(success bool) {
	if success {
		c.healthInterval = c.d.CheckInterval
		c.backingOff = false
	} else if c.backingOff {
		c.healthInterval = min(c.healthInterval*2, c.d.CheckIntervalMax)
	} else {
		c.healthInterval = checkBackoffInitialInterval
		c.backingOff = true
	}
	delay := c.healthInterval
	if success && c.staggerNext {
		delay = jitterCheckInterval(delay)
		c.staggerNext = false
	}
	c.healthTimer.Reset(delay)
}

func (c *connectivityChecker) startDeferredCheck() {
	if c.healthDue {
		c.healthDue = false
		c.requestHealth()
		return
	}
	if c.supportDue {
		c.supportDue = false
		if c.supportPending() {
			c.start(checkSupport)
		}
	}
}

func nextRetryInterval(interval, maximum time.Duration) time.Duration {
	if maximum <= 0 {
		maximum = supportRetryInitialInterval
	}
	if interval >= maximum/time.Duration(supportRetryMultiplier) {
		return maximum
	}
	return min(interval*time.Duration(supportRetryMultiplier), maximum)
}

func initialRetryInterval(maximum time.Duration) time.Duration {
	if maximum > 0 {
		return min(supportRetryInitialInterval, maximum)
	}
	return supportRetryInitialInterval
}

func jitterRetryInterval(interval, maximum time.Duration) time.Duration {
	delay := jitterCheckInterval(interval)
	if maximum > 0 {
		return min(delay, maximum)
	}
	return delay
}

func (c *connectivityChecker) perform(ctx context.Context, kind checkKind) checkResult {
	result := checkResult{kind: kind}
	seq, err := c.connect(ctx)
	result.seq = seq
	if err != nil {
		result.connectErr = err
		return result
	}

	states := c.d.networkStates()
	switch kind {
	case checkInitial:
		result.probes = c.probeMany(ctx, states, networkUntested, 1)
	case checkSupport:
		result.probes = c.probeMany(ctx, states, networkUnknown, 1)
	case checkHealth:
		first := firstSupportedNetwork(states)
		if !first.Valid() {
			return result
		}
		firstResult := c.probeNetwork(ctx, first, 2)
		result.probes = append(result.probes, firstResult)
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

func (d *Dialer) networkStates() [common.NetworkTypeCount]networkState {
	d.mu.RLock()
	states := d.networks
	d.mu.RUnlock()
	return states
}

func (c *connectivityChecker) supportPending() bool {
	pending := false
	for _, state := range c.d.networkStates() {
		if state == networkUntested {
			return false
		}
		if state == networkUnknown {
			pending = true
		}
	}
	return pending
}

func (c *connectivityChecker) probeMany(ctx context.Context, states [common.NetworkTypeCount]networkState, wanted networkState, attempts int) []probeResult {
	results := make([]probeResult, 0, common.NetworkTypeCount)
	for _, network := range canonicalNetworkOrder {
		if states[network] == wanted {
			results = append(results, probeResult{network: network})
		}
	}
	var wg sync.WaitGroup
	for i := range results {
		network := results[i].network
		wg.Go(func() {
			results[i] = c.probeNetwork(ctx, network, attempts)
		})
	}
	wg.Wait()
	return results
}

func (c *connectivityChecker) probeNetwork(ctx context.Context, network common.NetworkIndex, attempts int) probeResult {
	first := c.runProbe(ctx, network)
	if first.err == nil || attempts == 1 || ctx.Err() != nil {
		return first
	}
	retry := c.runProbe(ctx, network)
	if retry.err == nil {
		return retry
	}
	return first
}

type probeTransition struct {
	probe    probeResult
	previous networkState
	current  networkState
}

func (d *Dialer) applyCapabilityResultsLocked(result checkResult) []probeTransition {
	transitions := make([]probeTransition, 0, len(result.probes))
	for _, probe := range result.probes {
		index := probe.network
		previous := d.networks[index]
		if previous == networkUntested || previous == networkUnknown {
			switch {
			case probe.err == nil:
				d.networks[index] = networkSupported
			case errors.Is(probe.err, netproxy.UnsupportedTunnelTypeError):
				d.networks[index] = networkUnsupported
			case previous == networkUntested:
				d.networks[index] = networkUnknown
			}
		}
		transitions = append(transitions, probeTransition{
			probe:    probe,
			previous: previous,
			current:  d.networks[index],
		})
	}
	return transitions
}

var canonicalNetworkOrder = [...]common.NetworkIndex{
	common.NetworkTCP6,
	common.NetworkTCP4,
	common.NetworkUDP6,
	common.NetworkUDP4,
}

func firstSupportedNetwork(states [common.NetworkTypeCount]networkState) common.NetworkIndex {
	for _, index := range canonicalNetworkOrder {
		if states[index] == networkSupported {
			return index
		}
	}
	return common.NetworkInvalid
}

func resultProbe(result checkResult, index common.NetworkIndex) *probeResult {
	for i := range result.probes {
		if result.probes[i].network == index {
			return &result.probes[i]
		}
	}
	return nil
}

func firstSupportConfirmed(transition probeTransition) bool {
	return (transition.previous == networkUntested || transition.previous == networkUnknown) && transition.current == networkSupported
}

func (d *Dialer) takePendingForceLocked() SelectionForceMask {
	if !d.healthy {
		return SelectionForceNone
	}
	force := d.pendingForce
	d.pendingForce = SelectionForceNone
	return force
}

func (d *Dialer) applyCheck(result checkResult) (appliedCheck, bool) {
	d.mu.Lock()
	if d.ctx.Err() != nil {
		d.mu.Unlock()
		return appliedCheck{}, false
	}
	session, hasSession := d.sessionSnapshot()
	if hasSession && session.Seq != result.seq {
		d.mu.Unlock()
		return appliedCheck{}, false
	}
	if result.connectErr != nil {
		return d.applyConnectErrorLocked(result, session, hasSession), true
	}
	if hasSession && session.State != netproxy.SessionConnected {
		d.mu.Unlock()
		return appliedCheck{}, false
	}

	switch result.kind {
	case checkInitial, checkSupport:
		return d.applyCapabilityCheckLocked(result), true
	case checkHealth:
		return d.applyHealthCheckLocked(result), true
	default:
		d.mu.Unlock()
		return appliedCheck{}, false
	}
}

func (d *Dialer) applyConnectErrorLocked(result checkResult, session netproxy.StateEvent, hasSession bool) appliedCheck {
	requested := false
	if result.kind != checkSupport {
		requested = d.checkRequested
		d.checkRequested = false
	}
	previousHealthy := d.healthyLocked(session, hasSession)
	group := d.group
	d.mu.Unlock()
	if result.kind != checkSupport {
		d.logCheckOutcome(previousHealthy, false, nil, nil, result)
		d.notifyGroup(group, SelectionForceNone)
	}
	return appliedCheck{requested: requested}
}

func (d *Dialer) applyCapabilityCheckLocked(result checkResult) appliedCheck {
	initial := result.kind == checkInitial
	transitions := d.applyCapabilityResultsLocked(result)
	discovered := SelectionForceNone
	for _, transition := range transitions {
		if firstSupportConfirmed(transition) {
			discovered |= SelectionForceFor(transition.probe.network)
		}
	}

	previousHealthy := d.healthy
	failureReportedAt := d.failureReportedAt
	canonicalIndex := firstSupportedNetwork(d.networks)
	canonicalResult := resultProbe(result, canonicalIndex)
	if !initial && !discovered.Contains(canonicalIndex) {
		canonicalResult = nil
	}
	healthApplied := initial || canonicalResult != nil
	if healthApplied {
		d.healthy = canonicalResult != nil && canonicalResult.err == nil
		d.healthSeq = result.seq
		d.failureReportedAt = time.Time{}
		if d.group != nil && canonicalResult != nil {
			d.group.recordLatency(canonicalResult.latency, true)
		}
	}
	requested := false
	if healthApplied {
		requested = d.checkRequested
		d.checkRequested = false
	}

	d.pendingForce |= discovered
	forceSelection := d.takePendingForceLocked()
	currentHealthy := d.healthy
	group := d.group
	d.mu.Unlock()

	d.logCheckOutcome(previousHealthy, currentHealthy, canonicalResult, transitions, result)
	if healthApplied {
		stats.DefaultStore.RecordNodeCheck(d.StatsKey(), currentHealthy, failureReportedAt)
	}
	if initial || previousHealthy != currentHealthy || forceSelection != SelectionForceNone {
		d.notifyGroup(group, forceSelection)
	}
	return appliedCheck{
		success:       currentHealthy,
		requested:     requested,
		healthApplied: healthApplied,
	}
}

func (d *Dialer) applyHealthCheckLocked(result checkResult) appliedCheck {
	requested := d.checkRequested
	d.checkRequested = false
	previousHealthy := d.healthy
	failureReportedAt := d.failureReportedAt
	var canonicalResult *probeResult
	if len(result.probes) > 0 {
		canonicalResult = &result.probes[0]
	}
	d.healthy = canonicalResult != nil && canonicalResult.err == nil
	d.healthSeq = result.seq
	d.failureReportedAt = time.Time{}
	if d.group != nil && canonicalResult != nil {
		d.group.recordLatency(canonicalResult.latency, canonicalResult.err == nil)
	}
	forceSelection := d.takePendingForceLocked()
	group := d.group
	currentHealthy := d.healthy
	d.mu.Unlock()

	d.logCheckOutcome(previousHealthy, currentHealthy, canonicalResult, nil, result)
	stats.DefaultStore.RecordNodeCheck(d.StatsKey(), currentHealthy, failureReportedAt)
	d.notifyGroup(group, forceSelection)
	return appliedCheck{success: currentHealthy, requested: requested}
}

func (d *Dialer) logCheckOutcome(previousHealthy, success bool, canonical *probeResult, transitions []probeTransition, result checkResult) {
	if result.kind == checkInitial {
		if result.connectErr != nil {
			log.WithField("node", d.Name).WithError(result.connectErr).Debug("Connectivity initial check failed")
		}
		for _, transition := range transitions {
			fields := log.Fields{
				"node":    d.Name,
				"network": transition.probe.network.String(),
			}
			entry := log.WithFields(fields)
			if transition.probe.err == nil {
				entry.WithField("latency", transition.probe.latency.Truncate(time.Millisecond).String()).Debug("Connectivity initial check succeeded")
			} else {
				entry.WithError(transition.probe.err).Debug("Connectivity initial check failed")
			}
		}
	}

	for _, transition := range transitions {
		if firstSupportConfirmed(transition) {
			log.WithFields(log.Fields{
				"cause":   checkKindName[result.kind],
				"network": transition.probe.network.String(),
				"node":    d.Name,
			}).Info("Connectivity mode supported")
			continue
		}
		if result.kind == checkSupport && transition.previous != transition.current {
			log.WithFields(log.Fields{
				"network": transition.probe.network.String(),
				"node":    d.Name,
				"state":   supportState(transition.current),
			}).Debug("Connectivity support state changed")
		}
	}

	if result.kind == checkSupport && !previousHealthy && success {
		fields := log.Fields{"node": d.Name}
		if canonical != nil {
			fields["network"] = canonical.network.String()
		}
		log.WithFields(fields).Info("Connectivity recovered")
	}
	if result.kind != checkHealth {
		return
	}
	fields := log.Fields{"node": d.Name}
	if canonical != nil {
		fields["network"] = canonical.network.String()
		if canonical.err == nil {
			fields["last"] = canonical.latency.Truncate(time.Millisecond).String()
			if latencyStats, ok := d.latencyStats(); ok {
				fields["avg_10"] = latencyStats.Avg10.Truncate(time.Millisecond).String()
				fields["mov_avg"] = latencyStats.MovingAvg.Truncate(time.Millisecond).String()
			}
			log.WithFields(fields).Debug("Connectivity Check")
		} else {
			log.WithFields(fields).WithError(canonical.err).Debug("Connectivity probe failed")
		}
	} else if result.connectErr != nil {
		log.WithFields(fields).WithError(result.connectErr).Debug("Connectivity probe failed")
	}
	if previousHealthy && !success {
		err := result.connectErr
		if err == nil && canonical != nil {
			err = canonical.err
		}
		log.WithFields(fields).Warn(oops.Wrapf(err, "Connectivity Check Failed"))
	} else if !previousHealthy && success {
		log.WithFields(fields).Info("Connectivity recovered")
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
		entry := log.WithFields(log.Fields{"node": d.Name, "session_state": event.State})
		if event.Cause != nil {
			entry = entry.WithError(event.Cause)
		}
		entry.Warn("Connectivity Check Failed")
		stats.DefaultStore.RecordNodeState(d.StatsKey(), false, failureReportedAt)
		d.notifyGroup(group, SelectionForceNone)
	}
	return true
}

func (d *Dialer) healthyAt(seq uint64) bool {
	d.mu.RLock()
	healthy := d.healthy && d.healthSeq == seq
	d.mu.RUnlock()
	return healthy
}

func (c *connectivityChecker) runProbe(ctx context.Context, network common.NetworkIndex) probeResult {
	start := time.Now()
	ok, err := c.probe(ctx, network.NetworkType())
	if ok {
		return probeResult{network: network, latency: time.Since(start)}
	}
	if err == nil {
		err = oops.Errorf("check func not working")
	} else if strings.HasSuffix(err.Error(), "network is unreachable") {
		err = oops.Errorf("network is unreachable")
	}
	return probeResult{network: network, err: err}
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
