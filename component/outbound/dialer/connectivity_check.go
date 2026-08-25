/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
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
	checkBackoffInitialInterval    = time.Second
	healthCheckHedgeMinDelay       = 100 * time.Millisecond
	healthCheckHedgeMaxDelay       = time.Second
	initialCheckInterval           = 180 * time.Second
	initialCheckMaxInterval        = time.Hour
	capabilityCheckInitialInterval = 15 * time.Minute
	capabilityCheckMaxInterval     = 24 * time.Hour
	// initialCheckTimeout is the maximum time the control plane startup waits
	// for a dialer's initial connectivity check. The check itself keeps
	// retrying in the background with exponential backoff after the timeout.
	initialCheckTimeout = 60 * time.Second
)

func (d *Dialer) Alive() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.Dialer.Alive() && d.alive
}

// SelectionState returns coherent aggregate health, mode health, and capability.
func (d *Dialer) SelectionState(typ *common.NetworkType) (alive bool, support NetworkSupportState) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	index := common.NetworkTypeToIndex(typ)
	support = d.support[index]
	return d.Dialer.Alive() && d.alive && d.modeAlive[index], support
}

func (d *Dialer) ConfirmedSupport(typ *common.NetworkType) bool {
	return d.SupportState(typ) == NetworkSupportConfirmed
}

func (d *Dialer) SupportState(typ *common.NetworkType) NetworkSupportState {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.support[common.NetworkTypeToIndex(typ)]
}

// SetSupported resolves an unknown capability for tests that do not run real
// connectivity probes. Confirmed and unsupported states remain unchanged.
func (d *Dialer) SetSupported(typ *common.NetworkType, ok bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ctx.Err() != nil {
		return
	}
	index := common.NetworkTypeToIndex(typ)
	if d.support[index] != NetworkSupportUnknown {
		return
	}
	state := NetworkSupportUnsupported
	if ok {
		state = NetworkSupportConfirmed
		d.modeAlive[index] = true
	}
	d.support[index] = state
}

func (d *Dialer) setModeAlive(networkType *common.NetworkType, alive bool) bool {
	if networkType == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	index := common.NetworkTypeToIndex(networkType)
	changed := d.modeAlive[index] != alive
	d.modeAlive[index] = alive
	return changed
}

type checkDNSOption struct {
	DnsPort uint16
	*netutils.Ip46
}

func parseCheckDNSOption(dnsHostPort []string) (opt *checkDNSOption, err error) {
	if len(dnsHostPort) == 0 {
		return nil, oops.Errorf("parseCheckDNSOption: bad format: empty")
	}

	host, _port, err := net.SplitHostPort(dnsHostPort[0])
	if err != nil {
		return nil, oops.Wrapf(err, "parseCheckDNSOption: failed to split host and port")
	}
	port, err := strconv.ParseUint(_port, 10, 16)
	if err != nil {
		return nil, oops.Errorf("bad port: %v", err)
	}
	var ip46 *netutils.Ip46
	if len(dnsHostPort) > 1 {
		ip46 = new(netutils.Ip46)
		for _, raw := range dnsHostPort[1:] {
			addr, err := netip.ParseAddr(raw)
			if err != nil {
				return nil, oops.Errorf("parseCheckDNSOption: invalid IP address: %w", err)
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
	return &checkDNSOption{
		DnsPort: uint16(port),
		Ip46:    ip46,
	}, nil
}

type CheckDnsOptionRaw struct {
	opt *checkDNSOption
	mu  sync.Mutex
	Raw []string
}

func (c *CheckDnsOptionRaw) Option() (opt *checkDNSOption, err error) {
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
	probe       func(context.Context, *common.NetworkType) (ok bool, err error)
}

func (d *Dialer) checkDNSConnectivity(ctx context.Context, networkType *common.NetworkType) (ok bool, err error) {
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
			"dialer":  d.Name,
			"network": networkType.String(),
		}).Debugln("Skip check due to no DNS record.")
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
	checkOpts := make([]*checkOption, 0, len(networkTypes))
	for _, networkType := range networkTypes {
		checkOpts = append(checkOpts, &checkOption{
			networkType: networkType,
			probe:       d.checkDNSConnectivity,
		})
	}
	return checkOpts
}

func (d *Dialer) ActivateCheck(wg *sync.WaitGroup) {
	d.mu.Lock()
	if len(d.registeredDialerGroups) == 0 || !d.needAliveState || d.checkActivated || d.ctx.Err() != nil {
		d.mu.Unlock()
		return
	}
	d.checkActivated = true
	checkAsync := d.checkAsync
	d.checkWG.Add(1)
	d.mu.Unlock()

	checkOpts := d.createCheckOptions()

	if !checkAsync {
		wg.Add(1)
	}

	done := make(chan struct{})
	go func() {
		defer d.checkWG.Done()
		// At startup all modes are unknown. Inconclusive failures are retried
		// with backoff until one mode works or every mode is unsupported.
		checkOpt := d.runInitialCheck(checkOpts)
		if d.ctx.Err() != nil {
			return
		}
		close(done)
		if checkOpt == nil {
			return
		}
		// Regular health checks use one confirmed type. Unknown capability is
		// rediscovered separately with a much slower backoff.
		d.runCheckLoop(checkOpt, checkOpts)
	}()
	if !checkAsync {
		go func() {
			select {
			case <-done:
			case <-time.After(initialCheckTimeout):
				log.WithFields(log.Fields{
					"node": d.Name,
				}).Warnf("Initial check not finished in %v, startup continues and check keeps running in background", initialCheckTimeout)
			case <-d.ctx.Done():
			}
			wg.Done()
		}()
	}
}

// NotifyCheck requests a health check. Requests are coalesced.
func (d *Dialer) NotifyCheck() {
	select {
	case <-d.ctx.Done():
	case d.checkCh <- struct{}{}:
	default:
	}
}

// NotifyConnectivityRecheck wakes only aggregate health after a local network
// change. Remote capability and mode-specific recovery keep their own timer.
func (d *Dialer) NotifyConnectivityRecheck() { d.NotifyCheck() }

func jitterCheckInterval(interval time.Duration) time.Duration {
	spread := interval / 5
	if spread <= 0 {
		return interval
	}
	return interval - spread + time.Duration(fastrand.Int63n(int64(2*spread+1)))
}

type healthCheckResult struct {
	networkType *common.NetworkType
	ok          bool
	latency     time.Duration
	err         error
	modeFailed  bool
}

type connectivityCheckLoop struct {
	d       *Dialer
	primary *checkOption
	options []*checkOption

	healthTimer    *time.Timer
	healthInterval time.Duration
	lastLatency    time.Duration
	backingOff     bool
	staggerNext    bool

	capabilityTimer    *time.Timer
	capabilityInterval time.Duration

	recoveryTimer  *time.Timer
	recoveryActive bool

	disconnectNotified bool
}

func newConnectivityCheckLoop(d *Dialer, primary *checkOption, options []*checkOption) *connectivityCheckLoop {
	healthInterval := d.CheckInterval
	if healthInterval > 0 {
		healthInterval = time.Duration(fastrand.Int63n(int64(healthInterval)))
	}
	capabilityTimer := time.NewTimer(time.Hour)
	recoveryTimer := time.NewTimer(time.Hour)
	recoveryTimer.Stop()
	d.mu.RLock()
	lastLatency := d.lastLatency
	d.mu.RUnlock()
	loop := &connectivityCheckLoop{
		d:                  d,
		primary:            primary,
		options:            options,
		healthTimer:        time.NewTimer(healthInterval),
		healthInterval:     healthInterval,
		lastLatency:        lastLatency,
		capabilityTimer:    capabilityTimer,
		capabilityInterval: capabilityCheckInitialInterval,
		recoveryTimer:      recoveryTimer,
	}
	loop.scheduleCapabilityCheck()
	return loop
}

func healthCheckHedgeDelay(lastLatency time.Duration) time.Duration {
	return min(max(lastLatency*2, healthCheckHedgeMinDelay), healthCheckHedgeMaxDelay)
}

func (c *connectivityCheckLoop) scheduleCapabilityCheck() {
	if !c.d.hasPendingCapabilityCheck(c.options) {
		c.capabilityTimer.Stop()
		return
	}
	c.capabilityTimer.Reset(jitterCheckInterval(c.capabilityInterval))
}

func (c *connectivityCheckLoop) scheduleModeRecovery() {
	if !c.d.hasPendingModeRecovery(c.options) {
		if c.recoveryActive {
			c.recoveryTimer.Stop()
			c.recoveryActive = false
		}
		return
	}
	if c.recoveryActive {
		return
	}
	c.recoveryTimer.Reset(jitterCheckInterval(capabilityCheckInitialInterval))
	c.recoveryActive = true
}

func (c *connectivityCheckLoop) discoverCapabilities() (ok, attempted bool) {
	if !c.d.Dialer.Alive() {
		return true, false
	}
	_, changed := c.d.checkCapabilities(c.options, capabilityCheckRuntime)
	if c.d.ctx.Err() != nil {
		return false, true
	}
	if c.d.Alive() && changed {
		c.d.NotifyStatusChange()
	}
	return true, true
}

func (c *connectivityCheckLoop) notifyTransportDisconnect() {
	c.d.mu.RLock()
	healthWasAlive := c.d.alive
	c.d.mu.RUnlock()
	if healthWasAlive && !c.disconnectNotified {
		c.d.NotifyStatusChange()
		c.disconnectNotified = true
	}
}

func (d *Dialer) ensureConnected() error {
	d.connectMu.Lock()
	defer d.connectMu.Unlock()
	// Group-specific checkers share a transport. Recheck under their shared
	// lock so a waiter cannot reset the session just established by its peer.
	if d.Dialer.Alive() {
		return nil
	}
	return d.Dialer.Connect()
}

func (c *connectivityCheckLoop) checkHealth() healthCheckResult {
	var result healthCheckResult
	if c.primary != nil {
		result.networkType = c.primary.networkType
	}
	if !c.d.Dialer.Alive() {
		c.notifyTransportDisconnect()
		result.err = c.d.ensureConnected()
		if result.err != nil && c.d.ctx.Err() == nil {
			result.err = c.d.ensureConnected()
		}
	}
	if result.err != nil || c.d.ctx.Err() != nil {
		return result
	}
	if c.primary != nil {
		checked := c.checkHealthOption(c.primary)
		checked.modeFailed = result.modeFailed
		result = checked
	}
	if result.ok || c.d.ctx.Err() != nil {
		return result
	}
	result.modeFailed = c.d.setModeAlive(result.networkType, false) || result.modeFailed

	c.d.mu.RLock()
	support := c.d.support
	c.d.mu.RUnlock()
	var attempted [4]bool
	if c.primary != nil {
		attempted[common.NetworkTypeToIndex(c.primary.networkType)] = true
	}
	for _, candidate := range c.options {
		index := common.NetworkTypeToIndex(candidate.networkType)
		if attempted[index] || support[index] != NetworkSupportConfirmed {
			continue
		}
		attempted[index] = true
		candidateResult := c.checkHealthOption(candidate)
		candidateResult.modeFailed = result.modeFailed
		result = candidateResult
		if candidateResult.ok {
			c.primary = candidate
			return candidateResult
		}
		result.modeFailed = c.d.setModeAlive(candidateResult.networkType, false) || result.modeFailed
	}
	return result
}

func (c *connectivityCheckLoop) checkHealthOption(option *checkOption) healthCheckResult {
	ctx, cancel := context.WithCancel(c.d.ctx)
	defer cancel()
	results := make(chan healthCheckResult, 2)
	probe := func() {
		ok, latency, err := c.d.check(ctx, option)
		results <- healthCheckResult{networkType: option.networkType, ok: ok, latency: latency, err: err}
	}
	go probe()
	timer := time.NewTimer(healthCheckHedgeDelay(c.lastLatency))
	defer timer.Stop()
	var first healthCheckResult
	var hedged bool
	select {
	case first = <-results:
	case <-timer.C:
		hedged = true
		go probe()
		first = <-results
	}
	if first.ok {
		return first
	}
	if ctx.Err() != nil {
		return first
	}
	if !hedged {
		go probe()
	}
	second := <-results
	if second.ok {
		return second
	}
	return first
}

func (c *connectivityCheckLoop) publishHealth(result healthCheckResult) {
	if result.ok {
		c.healthInterval = c.d.CheckInterval
		if c.staggerNext {
			c.healthInterval = jitterCheckInterval(c.healthInterval)
			c.staggerNext = false
		}
		c.lastLatency = result.latency
		c.backingOff = false
	} else if !c.backingOff {
		c.backingOff = true
		c.healthInterval = checkBackoffInitialInterval
	}

	c.d.updateHealth(result.ok, result.latency, result.networkType, result.err)
	c.d.NotifyStatusChange()
	c.disconnectNotified = !result.ok
	c.healthTimer.Reset(c.healthInterval)
	if result.modeFailed {
		c.scheduleModeRecovery()
	}
}

func (c *connectivityCheckLoop) run() {
	for {
		select {
		case <-c.d.ctx.Done():
			return
		case <-c.capabilityTimer.C:
			ok, attempted := c.discoverCapabilities()
			if !ok {
				return
			}
			if attempted {
				c.capabilityInterval = min(c.capabilityInterval*2, capabilityCheckMaxInterval)
			}
			c.scheduleCapabilityCheck()
			continue
		case <-c.recoveryTimer.C:
			c.recoveryActive = false
			if !c.d.Dialer.Alive() {
				c.scheduleModeRecovery()
				continue
			}
			if c.d.recoverModeHealth(c.options) && c.d.Alive() {
				c.d.NotifyStatusChange()
			}
			c.scheduleModeRecovery()
			continue
		case <-c.d.checkCh:
			c.staggerNext = true
		case <-c.healthTimer.C:
			if c.backingOff {
				c.healthInterval = min(c.healthInterval*2, c.d.CheckIntervalMax)
			}
		}

		if c.d.ctx.Err() != nil {
			return
		}
		result := c.checkHealth()
		if c.d.ctx.Err() != nil {
			return
		}
		c.publishHealth(result)
	}
}

func (d *Dialer) runCheckLoop(checkOpt *checkOption, checkOpts []*checkOption) {
	newConnectivityCheckLoop(d, checkOpt, checkOpts).run()
}

func (d *Dialer) runInitialCheck(checkOpts []*checkOption) *checkOption {
	checkInterval := initialCheckInterval
	retryTimer := time.NewTimer(time.Hour)
	for {
		if d.ctx.Err() != nil {
			return nil
		}
		opt, _ := d.checkCapabilities(checkOpts, capabilityCheckInitial)
		if d.ctx.Err() != nil {
			return nil
		}
		d.NotifyStatusChange()
		if opt != nil {
			return opt
		}
		if !d.hasPendingCapabilityCheck(checkOpts) {
			// Every configured mode is definitively unsupported. Capability
			// discovery is complete even though the node cannot be used.
			return nil
		}
		// All network types failed. Back off before trying every type again.
		retryTimer.Reset(checkInterval)
		select {
		case <-d.ctx.Done():
			return nil
		case <-d.checkCh:
			checkInterval = initialCheckInterval
		case <-retryTimer.C:
			checkInterval = min(checkInterval*2, initialCheckMaxInterval)
		}
	}
}

type capabilityCheckResult struct {
	option  *checkOption
	ok      bool
	latency time.Duration
	err     error
}

type capabilityCheckMode uint8

const (
	// Both phases classify only unknown capability. Runtime checks leave
	// aggregate health unchanged and never reconnect a dead transport.
	capabilityCheckInitial capabilityCheckMode = iota
	capabilityCheckRuntime
)

func pendingCapabilityOptions(checkOpts []*checkOption, support [4]NetworkSupportState) []*checkOption {
	unknown := make([]*checkOption, 0, len(checkOpts))
	var seen [4]bool
	for _, opt := range checkOpts {
		i := common.NetworkTypeToIndex(opt.networkType)
		if support[i] == NetworkSupportUnknown && !seen[i] {
			unknown = append(unknown, opt)
			seen[i] = true
		}
	}
	return unknown
}

func pendingModeRecoveryOptions(checkOpts []*checkOption, support [4]NetworkSupportState, modeAlive [4]bool) []*checkOption {
	pending := make([]*checkOption, 0, len(checkOpts))
	var seen [4]bool
	for _, opt := range checkOpts {
		i := common.NetworkTypeToIndex(opt.networkType)
		if support[i] == NetworkSupportConfirmed && !modeAlive[i] && !seen[i] {
			pending = append(pending, opt)
			seen[i] = true
		}
	}
	return pending
}

func (d *Dialer) probeCapabilities(checkOpts []*checkOption) []capabilityCheckResult {
	var wg sync.WaitGroup
	results := make([]capabilityCheckResult, len(checkOpts))
	for i, opt := range checkOpts {
		results[i].option = opt
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := &results[i]
			result.ok, result.latency, result.err = d.check(d.ctx, opt)
			entry := log.WithFields(log.Fields{
				"network": opt.networkType.String(),
				"node":    d.Name,
			})
			if result.ok {
				entry.WithField("last", result.latency.Truncate(time.Millisecond).String()).Infoln("Connectivity Capability Check")
			} else if log.IsLevelEnabled(log.TraceLevel) {
				entry.Infof("%+v\n", oops.Wrapf(result.err, "Connectivity Capability Check Failed"))
			} else {
				entry.Infoln(oops.Wrapf(result.err, "Connectivity Capability Check Failed"))
			}
		}()
	}
	wg.Wait()
	return results
}

func (d *Dialer) hasPendingCapabilityCheck(checkOpts []*checkOption) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(pendingCapabilityOptions(checkOpts, d.support)) > 0
}

func (d *Dialer) hasPendingModeRecovery(checkOpts []*checkOption) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(pendingModeRecoveryOptions(checkOpts, d.support, d.modeAlive)) > 0
}

func (d *Dialer) checkCapabilities(checkOpts []*checkOption, mode capabilityCheckMode) (best *checkOption, changed bool) {
	if d.ctx.Err() != nil {
		return nil, false
	}
	d.mu.RLock()
	support := d.support
	d.mu.RUnlock()
	pending := pendingCapabilityOptions(checkOpts, support)
	if len(pending) == 0 {
		return nil, false
	}
	if mode != capabilityCheckInitial && !d.Dialer.Alive() {
		return nil, false
	}
	if mode == capabilityCheckInitial {
		if err := d.ensureConnected(); err != nil {
			if d.ctx.Err() == nil {
				d.Update(false, 0, nil, err)
			}
			return nil, false
		}
	}
	results := d.probeCapabilities(pending)
	d.mu.Lock()
	if d.ctx.Err() != nil {
		d.mu.Unlock()
		return nil, false
	}
	for _, result := range results {
		i := common.NetworkTypeToIndex(result.option.networkType)
		if support[i] != d.support[i] {
			continue
		}
		switch {
		case result.ok:
			// Success proves support. Later health failures never change this
			// terminal capability verdict.
			if d.support[i] == NetworkSupportUnknown {
				d.support[i] = NetworkSupportConfirmed
				changed = true
			}
			if !d.modeAlive[i] {
				d.modeAlive[i] = true
				changed = true
			}
		case d.support[i] == NetworkSupportUnknown && errors.Is(result.err, netproxy.UnsupportedTunnelTypeError):
			// Unsupported is a terminal capability verdict and requires this
			// explicit typed error; reachability failures are not evidence.
			d.support[i] = NetworkSupportUnsupported
			changed = true
		}
	}
	d.mu.Unlock()

	var latency time.Duration
	var firstErr error
	for _, result := range results {
		if result.ok {
			best, latency = result.option, result.latency
			firstErr = nil
			break
		}
		if firstErr == nil {
			firstErr = result.err
		}
	}
	if mode == capabilityCheckInitial {
		var networkType *common.NetworkType
		if best != nil {
			networkType = best.networkType
		}
		d.Update(best != nil, latency, networkType, firstErr)
	}
	return best, changed
}

func (d *Dialer) recoverModeHealth(checkOpts []*checkOption) bool {
	d.mu.RLock()
	support := d.support
	modeAlive := d.modeAlive
	d.mu.RUnlock()
	pending := pendingModeRecoveryOptions(checkOpts, support, modeAlive)
	if len(pending) == 0 {
		return false
	}
	results := d.probeCapabilities(pending)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ctx.Err() != nil {
		return false
	}
	changed := false
	for _, result := range results {
		i := common.NetworkTypeToIndex(result.option.networkType)
		if result.ok && d.support[i] == NetworkSupportConfirmed && !d.modeAlive[i] {
			d.modeAlive[i] = true
			changed = true
		}
	}
	return changed
}

func (d *Dialer) RegisterDialerGroup(g DialerGroup) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.registeredDialerGroups[g] = struct{}{}
	d.Latencies10[g] = NewLatenciesN(10)
	d.MovingAverage[g] = 0
}

func (d *Dialer) UnregisterDialerGroup(g DialerGroup) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.registeredDialerGroups, g)
	delete(d.Latencies10, g)
	delete(d.MovingAverage, g)
}

func (d *Dialer) NotifyStatusChange() {
	if !d.needAliveState {
		return
	}
	// Inform DialerGroups to update state.
	// Copy under the lock because callbacks call back into Dialer.Alive.
	d.mu.RLock()
	groups := slices.Collect(maps.Keys(d.registeredDialerGroups))
	d.mu.RUnlock()
	for _, g := range groups {
		g.NotifyStatusChange(d)
	}
}

// ReportUnavailable 意味着在测速之外, Dialer 似乎不可用了
func (d *Dialer) ReportUnavailable() {
	stats.RecordNodeConnFail(d.StatsKey())
	if !d.Alive() {
		d.NotifyStatusChange()
	}
	d.NotifyCheck()
}

func (d *Dialer) Update(ok bool, latency time.Duration, networkType *common.NetworkType, err error) {
	d.updateHealth(ok, latency, networkType, err)
}

func (d *Dialer) updateHealth(ok bool, latency time.Duration, networkType *common.NetworkType, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ctx.Err() != nil {
		return
	}
	if networkType != nil {
		d.modeAlive[common.NetworkTypeToIndex(networkType)] = ok
	}
	for g := range d.registeredDialerGroups {
		groupLatency := latency
		if !ok {
			groupLatency = g.GetTimeoutPenalty()
		}
		alpha := g.GetEmaAlpha()
		if d.MovingAverage[g] == 0 {
			d.MovingAverage[g] = groupLatency
		} else {
			d.MovingAverage[g] = time.Duration(float64(d.MovingAverage[g])*(1-alpha) + float64(groupLatency)*alpha)
		}
		d.Latencies10[g].AppendSample(groupLatency, !ok)
		fields := log.Fields{"node": d.Name}
		if networkType != nil {
			fields["network"] = networkType.String()
		}
		if ok {
			avg, _ := d.Latencies10[g].AvgLatency()
			fields["last"] = groupLatency.Truncate(time.Millisecond).String()
			fields["avg_10"] = avg.Truncate(time.Millisecond)
			fields["mov_avg"] = d.MovingAverage[g].Truncate(time.Millisecond)
			if !d.alive {
				log.WithFields(fields).Infoln("Connectivity Check")
			} else {
				log.WithFields(fields).Debugln("Connectivity Check")
			}
		} else {
			if d.alive {
				log.WithFields(fields).Warnln(oops.Wrapf(err, "Connectivity Check Failed"))
			} else {
				log.WithFields(fields).Infoln(oops.Wrapf(err, "Connectivity Check Failed"))
			}
		}
	}
	d.alive = ok
	if ok {
		d.lastLatency = latency
	}
	stats.RecordNode(d.StatsKey(), d.Property.SubscriptionTag, d.Name, ok, true)
}

func (d *Dialer) check(ctx context.Context, opts *checkOption) (ok bool, latency time.Duration, err error) {
	start := time.Now()
	if ok, err = opts.probe(ctx, opts.networkType); ok {
		// Calc latency.
		latency = time.Since(start)
	} else {
		if err == nil {
			err = oops.Errorf("check func not working")
		} else if strings.HasSuffix(err.Error(), "network is unreachable") { // Append timeout if there is any error or unexpected status code.
			err = oops.Errorf("network is unreachable")
		}
	}
	return
}

func (d *Dialer) dnsCheck(ctx context.Context, dns netip.AddrPort, network string) (ok bool, err error) {
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
