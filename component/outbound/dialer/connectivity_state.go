/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"errors"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

// networkState records what the path can carry. Failures never change it:
// only probes that settle a mode do, and a reload relearns every mode.
// Reachability is separate, in pathHealth.phase and pathHealth.failing.
type networkState uint8

const (
	networkUntested networkState = iota
	networkUnknown
	networkSupported
	networkUnsupported
)

type healthPhase uint8

const (
	healthUnhealthy healthPhase = iota
	healthHealthy
	healthConfirming
)

func (p healthPhase) usable() bool {
	return p == healthHealthy || p == healthConfirming
}

// networkMask is a set of network modes.
type networkMask uint8

func (m networkMask) has(index common.NetworkIndex) bool { return m&(1<<index) != 0 }

func (m *networkMask) set(index common.NetworkIndex, on bool) {
	if on {
		*m |= 1 << index
	} else {
		*m &^= 1 << index
	}
}

// pathHealth contains shared reachability, capabilities and successful observations.
// It is protected by pathRuntime.mu; it carries no group monitoring policy.
type pathHealth struct {
	phase              healthPhase
	readiness          uint64
	observedSessionSeq uint64
	networks           [common.NetworkTypeCount]networkState
	// failing marks supported modes whose latest probe failed. They carry no
	// traffic, cannot represent the path and are probed again by health checks.
	failing networkMask
	// relearn marks supported modes a reload asked to settle again. They keep
	// serving until a probe succeeds or the protocol rejects the mode.
	relearn      networkMask
	pendingForce SelectionForceMask
	lastLatency  time.Duration
	measuredAt   time.Time
}

func (d *pathRuntime) sessionSnapshot() netproxy.StateEvent {
	if d.session == nil {
		return netproxy.StateEvent{}
	}
	return d.session.Snapshot()
}

func (d *pathRuntime) healthyLocked(session netproxy.StateEvent) bool {
	return d.ctx.Err() == nil && d.health.phase.usable() && (d.session == nil || session.Accepting && d.health.readiness == session.ReadinessVersion)
}

// Usable keeps serving an admitted path, including while a reported failure
// is being confirmed.
func (d *Dialer) Usable(networkType *common.NetworkType) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return !d.closed && d.healthyLocked(d.sessionSnapshot()) && d.servesLocked(networkType.Index())
}

// Alive is a node's own proof of validity: its last representative check
// succeeded for the current session and no failure is pending. Sleep and
// reconnection change readiness, so a dormant path is never alive.
func (d *Dialer) Alive(networkType *common.NetworkType) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return !d.closed && d.aliveLocked(networkType.Index())
}

func (d *pathRuntime) aliveLocked(network common.NetworkIndex) bool {
	return d.health.phase == healthHealthy && d.healthyLocked(d.sessionSnapshot()) && d.servesLocked(network)
}

// servesLocked reports a supported mode whose latest probe did not fail.
func (d *pathRuntime) servesLocked(network common.NetworkIndex) bool {
	return d.health.networks[network] == networkSupported && !d.health.failing.has(network)
}

func (d *pathRuntime) representativeLocked() common.NetworkIndex {
	return representative(d.health.networks, d.health.failing)
}

// awaitingRecoveryLocked reports a confirmed failure that no check has
// resolved yet. Its retry schedule, not session churn, decides the next attempt.
func (d *pathRuntime) awaitingRecoveryLocked() bool {
	return d.failures.failedBefore && !d.health.phase.usable()
}

func (d *pathRuntime) awaitingRecovery() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.awaitingRecoveryLocked()
}

// discoveryModesLocked lists the modes a capability sweep tests: unknown ones
// and those a reload asked to relearn. The representative is relearned by its
// own health probes, so a sweep never decides the path's health.
func (d *pathRuntime) discoveryModesLocked() []common.NetworkIndex {
	representative := d.representativeLocked()
	var networks []common.NetworkIndex
	for _, network := range canonicalNetworkOrder {
		state := d.health.networks[network]
		if state == networkUnknown || state == networkSupported && d.health.relearn.has(network) && network != representative {
			networks = append(networks, network)
		}
	}
	return networks
}

// RelearnCapabilities settles every mode again, as a reload does for other
// learned node facts. Supported modes keep serving until a probe settles
// them; unsupported ones become unknown, so selection can test them again.
func (d *pathRuntime) RelearnCapabilities() {
	d.mu.Lock()
	if d.ctx.Err() != nil || !d.checksConnectivity {
		d.mu.Unlock()
		return
	}
	for i, state := range d.health.networks {
		switch state {
		case networkUnsupported:
			d.health.networks[i] = networkUnknown
		case networkSupported:
			d.health.relearn.set(common.NetworkIndex(i), true)
		}
	}
	d.statusRevision++
	if !d.checks.paused {
		// Restart the discovery round, like any other environment change.
		d.checks.pending |= checkRequestEnvironment
	}
	d.mu.Unlock()
	d.signalConnectivityCheck()
	d.notifyGroups(SelectionForceNone)
}

// markHealthyLocked ends the outage that confirmFailureLocked started.
func (d *pathRuntime) markHealthyLocked() {
	d.health.phase = healthHealthy
	d.failures.downSince = time.Time{}
}

func (d *pathRuntime) initialCheckCompleted() bool {
	d.mu.RLock()
	done := d.initialCheckCompletedLocked()
	d.mu.RUnlock()
	return done
}

func (d *pathRuntime) initialCheckCompletedLocked() bool {
	for _, state := range d.health.networks {
		if state == networkUntested {
			return false
		}
	}
	return true
}

func (d *pathRuntime) reportDataPlaneFailure(failure netproxy.Failure) {
	d.mu.Lock()
	if d.ctx.Err() != nil {
		d.mu.Unlock()
		return
	}
	startedConfirmation := false
	session := d.sessionSnapshot()
	if d.checksConnectivity && d.health.phase == healthHealthy && d.healthyLocked(session) {
		d.health.phase = healthConfirming
		d.failures.reportedAt = time.Now()
		d.failures.generation++
		d.failures.last = failureSnapshot(failure, d.failures.generation)
		d.statusRevision++
		d.checks.pending |= checkRequestDataPlane
		startedConfirmation = true
	}
	d.mu.Unlock()
	d.recordConnectionFailure()
	if startedConfirmation {
		d.notifyGroups(SelectionForceNone)
		d.signalConnectivityCheck()
	}
}

func (d *pathRuntime) networkStates() [common.NetworkTypeCount]networkState {
	d.mu.RLock()
	states := d.health.networks
	d.mu.RUnlock()
	return states
}

// applyReachabilityLocked records the outcome of each probed supported mode.
// Capability is unchanged: a mode that stops answering is failing, not
// unsupported, unless a reload asked to relearn it.
func (d *pathRuntime) applyReachabilityLocked(result checkResult) {
	for _, probe := range result.probes {
		if d.health.networks[probe.network] != networkSupported {
			continue
		}
		rejected := errors.Is(probe.err, netproxy.UnsupportedTunnelTypeError)
		if d.health.relearn.has(probe.network) && (probe.err == nil || rejected) {
			d.health.relearn.set(probe.network, false)
			if rejected {
				d.health.networks[probe.network] = networkUnsupported
				d.health.failing.set(probe.network, false)
				continue
			}
		}
		d.health.failing.set(probe.network, probe.err != nil)
	}
}

func (d *pathRuntime) applyCapabilityResultsLocked(result checkResult) {
	for _, probe := range result.probes {
		index := probe.network
		previous := d.health.networks[index]
		if previous == networkUntested || previous == networkUnknown {
			switch {
			case probe.err == nil:
				d.health.networks[index] = networkSupported
			case errors.Is(probe.err, netproxy.UnsupportedTunnelTypeError):
				d.health.networks[index] = networkUnsupported
			case previous == networkUntested:
				d.health.networks[index] = networkUnknown
			}
		}
	}
}

// pathView is the state that decides which modes a path serves: its phase,
// and each mode's capability and reachability.
type pathView struct {
	phase    healthPhase
	networks [common.NetworkTypeCount]networkState
	failing  networkMask
}

func (d *pathRuntime) viewLocked() pathView {
	return pathView{phase: d.health.phase, networks: d.health.networks, failing: d.health.failing}
}

// confirmed lists the modes whose support was confirmed since before.
func (v pathView) confirmed(before pathView) SelectionForceMask {
	force := SelectionForceNone
	for network, state := range v.networks {
		if state == networkSupported && before.networks[network] != networkSupported {
			force |= SelectionForceFor(common.NetworkIndex(network))
		}
	}
	return force
}

// publish is the single exit of applied probe results. It logs every mode
// that changed between the views and notifies groups of any change, or
// always when notify is set.
func (d *pathRuntime) publish(kind checkKind, before, after pathView, force SelectionForceMask, notify bool) {
	confirmed := after.confirmed(before)
	var supported, unsupported []string
	for _, network := range canonicalNetworkOrder {
		state := after.networks[network]
		if confirmed.Contains(network) {
			supported = append(supported, network.String())
		} else if kind != checkInitial && state == networkUnsupported && before.networks[network] != state {
			unsupported = append(unsupported, network.String())
		}
		// Only a usable path reports single modes; a lost path reports itself.
		if !after.phase.usable() {
			continue
		}
		fields := log.Fields{"node": d.name, "network": network.String()}
		switch failed, failing := before.failing.has(network), after.failing.has(network); {
		case !failed && failing:
			log.WithFields(fields).Warn("Connectivity mode lost; other modes keep serving")
		case failed && !failing && state == networkSupported:
			log.WithFields(fields).Info("Connectivity mode recovered")
		}
	}
	if len(supported) > 0 {
		log.WithFields(log.Fields{
			"cause":    checkKindName[kind],
			"networks": supported,
			"node":     d.name,
		}).Debug("Connectivity modes supported")
	}
	if len(unsupported) > 0 {
		log.WithFields(log.Fields{
			"cause":    checkKindName[kind],
			"networks": unsupported,
			"node":     d.name,
		}).Debug("Connectivity modes unsupported")
	}
	if notify || before != after || force != SelectionForceNone {
		d.notifyGroups(force)
	}
}

var canonicalNetworkOrder = [...]common.NetworkIndex{
	common.NetworkTCP6,
	common.NetworkTCP4,
	common.NetworkUDP6,
	common.NetworkUDP4,
}

func firstSupportedNetwork(states [common.NetworkTypeCount]networkState) common.NetworkIndex {
	return representative(states, 0)
}

// representative is the first supported mode in canonical order that has not
// failed. Its probe answers for the whole path.
func representative(states [common.NetworkTypeCount]networkState, failing networkMask) common.NetworkIndex {
	for _, index := range canonicalNetworkOrder {
		if states[index] == networkSupported && !failing.has(index) {
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

func (d *pathRuntime) takePendingForceLocked() SelectionForceMask {
	if !d.health.phase.usable() {
		return SelectionForceNone
	}
	force := d.health.pendingForce
	d.health.pendingForce = SelectionForceNone
	return force
}

func (d *pathRuntime) applyCheck(result checkResult) (appliedCheck, bool) {
	d.mu.Lock()
	if d.ctx.Err() != nil {
		d.mu.Unlock()
		return appliedCheck{}, false
	}
	if d.checks.pending&checkRequestEnvironment != 0 {
		d.mu.Unlock()
		return appliedCheck{}, false
	}
	session := d.sessionSnapshot()
	observedReadiness := result.readiness
	if d.session != nil && session.ReadinessVersion != observedReadiness {
		d.mu.Unlock()
		return appliedCheck{}, false
	}
	if result.kind == checkCapacity {
		if result.connectErr != nil {
			d.failures.last = failureSnapshot(primaryNodeFailure(result.connectErr), d.failures.generation)
			d.statusRevision++
		}
		d.mu.Unlock()
		return appliedCheck{success: result.connectErr == nil}, true
	}
	if result.connectErr != nil || recoveryBlockedReason(result.failure()) != "" {
		return d.applyConnectErrorLocked(result, session), true
	}
	if d.session != nil && !session.Accepting {
		d.mu.Unlock()
		return appliedCheck{}, false
	}
	if !d.checksConnectivity {
		d.markHealthyLocked()
		d.health.readiness = observedReadiness
		d.statusRevision++
		d.mu.Unlock()
		d.recordAvailability(true, false, time.Time{})
		d.notifyGroups(SelectionForceNone)
		return appliedCheck{success: true, healthApplied: true}, true
	}

	before := d.viewLocked()
	switch result.kind {
	case checkInitial, checkSupport:
		return d.applyCapabilityCheckLocked(result, before), true
	case checkHealth:
		return d.applyHealthCheckLocked(result, before), true
	case checkSelection:
		return d.applySelectionCheckLocked(result, before), true
	default:
		d.mu.Unlock()
		return appliedCheck{}, false
	}
}

func (d *pathRuntime) applyConnectErrorLocked(result checkResult, session netproxy.StateEvent) appliedCheck {
	failureReportedAt := d.failures.reportedAt
	previousHealthy := d.healthyLocked(session)
	blocksHealth := result.kind != checkSupport || recoveryBlockedReason(result.failure()) != ""
	if blocksHealth {
		d.confirmFailureLocked()
		d.health.phase = healthUnhealthy
		d.health.readiness = result.readiness
		d.failures.reportedAt = time.Time{}
		d.checks.pending &^= checkRequestDataPlane | checkRequestVerification
		d.checks.verify = false
		d.statusRevision++
		if d.failures.last == nil {
			d.failures.last = failureSnapshot(primaryNodeFailure(result.failure()), d.failures.generation)
		}
	}
	d.mu.Unlock()
	if blocksHealth {
		d.logCheckOutcome(previousHealthy, false, nil, result)
		if d.ChecksConnectivity() {
			d.recordAvailability(false, true, failureReportedAt)
		} else {
			d.recordAvailability(false, false, failureReportedAt)
		}
		d.notifyGroups(SelectionForceNone)
	}
	return appliedCheck{}
}

func (d *pathRuntime) applyHealthResultLocked(result checkResult, success bool) time.Time {
	failureReportedAt := d.failures.reportedAt
	// A representative result answers a pending verification either way.
	d.checks.verify = false
	d.health.readiness = result.readiness
	d.statusRevision++
	if !success {
		d.confirmFailureLocked()
		if err := result.failure(); err != nil && d.failures.last == nil {
			d.failures.last = failureSnapshot(primaryNodeFailure(err), d.failures.generation)
		}
		d.health.phase = healthUnhealthy
		d.failures.reportedAt = time.Time{}
		d.checks.pending &^= checkRequestDataPlane | checkRequestVerification
		return failureReportedAt
	}
	if d.health.phase != healthConfirming || result.generation >= d.failures.generation {
		d.recordRecoverySuccessLocked()
		d.markHealthyLocked()
		d.failures.reportedAt = time.Time{}
		session := d.sessionSnapshot()
		if session.Cause == nil && !session.RecoveryRequired {
			d.failures.last = nil
		}
	}
	return failureReportedAt
}

func (d *pathRuntime) applyCapabilityCheckLocked(result checkResult, before pathView) appliedCheck {
	initial := result.kind == checkInitial
	d.applyCapabilityResultsLocked(result)
	d.applyReachabilityLocked(result)
	discovered := d.viewLocked().confirmed(before)

	previousHealthy := before.phase.usable()
	canonicalIndex := d.representativeLocked()
	canonicalResult := resultProbe(result, canonicalIndex)
	if !initial && !discovered.Contains(canonicalIndex) {
		canonicalResult = nil
	}
	// Selection checks may already have established health before the remaining
	// capabilities are discovered. Missing modes cannot invalidate that check.
	healthApplied := canonicalResult != nil || initial && !canonicalIndex.Valid()
	failureReportedAt := d.failures.reportedAt
	if healthApplied {
		failureReportedAt = d.applyHealthResultLocked(result, canonicalResult != nil && canonicalResult.err == nil)
		if canonicalResult != nil {
			d.recordLatencyLocked(canonicalResult.latency, canonicalResult.err == nil)
		}
	}
	d.health.pendingForce |= discovered
	forceSelection := d.takePendingForceLocked()
	currentHealthy := d.health.phase.usable()
	after := d.viewLocked()
	d.mu.Unlock()

	d.logCheckOutcome(previousHealthy, currentHealthy, canonicalResult, result)
	if healthApplied {
		d.recordAvailability(currentHealthy, true, failureReportedAt)
	}
	d.publish(result.kind, before, after, forceSelection, initial)
	return appliedCheck{
		success:       currentHealthy,
		healthApplied: healthApplied,
	}
}

// applyHealthCheckLocked lets the representative answer for the path. A usable
// path fails when its representative fails, even if another mode answered: a
// new representative does not bypass failure_recovery. A failed path recovers
// through whichever supported mode answers first in canonical order. Without
// the usable path's representative, a result changes only reachability.
// A rejection settles capability, not health: when the protocol rejects a
// relearned representative, the next supported mode represents the path.
func (d *pathRuntime) applyHealthCheckLocked(result checkResult, before pathView) appliedCheck {
	previousHealthy := d.health.phase.usable()
	previous, failing := d.representativeLocked(), d.health.failing
	d.applyReachabilityLocked(result)
	answering := representative(d.health.networks, failing)
	if !previousHealthy {
		answering = d.representativeLocked()
	}
	canonical := resultProbe(result, answering)
	if previousHealthy && canonical == nil {
		if answering != previous {
			// The new representative has not answered yet: prove it at once.
			d.checks.pending |= checkRequestVerification
		}
		// Keep the representative observation's timestamp and latency.
		force := d.takePendingForceLocked()
		success := d.health.phase == healthHealthy && d.healthyLocked(d.sessionSnapshot())
		d.statusRevision++
		after := d.viewLocked()
		d.mu.Unlock()
		d.publish(result.kind, before, after, force, true)
		return appliedCheck{success: success}
	}
	success := canonical != nil && canonical.err == nil
	if canonical == nil && len(result.probes) > 0 {
		canonical = &result.probes[0] // Reports why no mode recovered.
	}
	failureReportedAt := d.applyHealthResultLocked(result, success)
	if canonical != nil {
		d.recordLatencyLocked(canonical.latency, success)
	}
	forceSelection := d.takePendingForceLocked()
	currentHealthy := d.health.phase.usable()
	after := d.viewLocked()
	d.mu.Unlock()

	d.logCheckOutcome(previousHealthy, currentHealthy, canonical, result)
	d.recordAvailability(currentHealthy, true, failureReportedAt)
	d.publish(result.kind, before, after, forceSelection, true)
	return appliedCheck{success: currentHealthy}
}

func (d *pathRuntime) logCheckOutcome(previousHealthy, success bool, canonical *probeResult, result checkResult) {
	if result.kind == checkInitial {
		if result.connectErr != nil {
			log.WithField("node", d.name).WithError(result.connectErr).Debug("Connectivity initial check failed")
		}
		for _, probe := range result.probes {
			entry := log.WithFields(log.Fields{"node": d.name, "network": probe.network.String()})
			if probe.err == nil {
				entry.WithField("latency", probe.latency.Truncate(time.Millisecond).String()).Trace("Connectivity initial check succeeded")
			} else {
				entry.WithError(probe.err).Debug("Connectivity initial check failed")
			}
		}
	}

	if result.kind == checkSupport && !previousHealthy && success {
		fields := log.Fields{"node": d.name}
		if canonical != nil {
			fields["network"] = canonical.network.String()
		}
		log.WithFields(fields).Info("Connectivity recovered")
	}
	if result.kind != checkHealth {
		return
	}
	fields := log.Fields{"node": d.name}
	if canonical != nil {
		fields["network"] = canonical.network.String()
		if canonical.err == nil {
			fields["last"] = canonical.latency.Truncate(time.Millisecond).String()
			log.WithFields(fields).Trace("Connectivity probe succeeded")
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
		log.WithFields(fields).WithError(err).Warn("Node connectivity lost; checking recovery in background")
	} else if !previousHealthy && success {
		log.WithFields(fields).Info("Connectivity recovered")
	}
}

func (d *pathRuntime) applySessionState(event netproxy.StateEvent) bool {
	d.mu.Lock()
	if d.ctx.Err() != nil || event.Seq <= d.health.observedSessionSeq {
		d.mu.Unlock()
		return false
	}
	d.health.observedSessionSeq = event.Seq
	d.statusRevision++
	if event.Cause != nil {
		failure := primaryNodeFailure(event.Cause)
		if failure.Origin == netproxy.OriginLocalCleanup && failure.Code == "idle" {
			clear(d.failures.resources)
			// Sleep invalidates readiness, not the last health observation or
			// availability history. The next generation requires a fresh check.
			d.mu.Unlock()
			d.notifyGroups(SelectionForceNone)
			return false
		}
	}
	resourceFailure := false
	if event.Cause != nil {
		failure := primaryNodeFailure(event.Cause)
		if failure.Scope == netproxy.ScopeUnknown && event.State == netproxy.SessionDisconnected && (d.health.phase.usable() || event.EpisodeID != 0) {
			// The owner has supplied the missing resource-lifetime evidence.
			failure.Scope = netproxy.ScopeSharedResource
		}
		if (failure.Layer == netproxy.LayerUnknown || failure.Layer == "") && event.Layer != "" {
			failure.Layer = event.Layer
		}
		if failure.Resource == (netproxy.ResourceRef{}) {
			failure.Resource = event.Resource
		}
		shared := failure.Scope == netproxy.ScopeSharedResource
		resourceFailure = d.observeResourceFailureLocked(event, shared)
		if resourceFailure || !shared && d.failures.last == nil {
			d.failures.last = failureSnapshot(failure, event.EpisodeID)
		}
	} else {
		d.observeResourceFailureLocked(event, false)
	}
	if event.Accepting {
		unchecked := !d.checksConnectivity
		if unchecked {
			d.markHealthyLocked()
			d.health.readiness = event.ReadinessVersion
			if event.Cause == nil && !event.RecoveryRequired {
				d.failures.last = nil
			}
		} else if d.health.phase.usable() && d.health.readiness == event.ReadinessVersion && event.Cause == nil && !event.RecoveryRequired {
			d.failures.last = nil
		}
		d.mu.Unlock()
		if resourceFailure {
			d.recordResourceFailure()
			d.recordConnectionFailure()
		}
		if unchecked {
			d.recordAvailability(true, false, time.Time{})
			d.notifyGroups(SelectionForceNone)
		}
		return false
	}
	wasHealthy := d.health.phase.usable()
	if wasHealthy {
		d.recovery.Attempt = 0
	}
	readinessChanged := d.health.readiness != event.ReadinessVersion
	if event.Cause != nil && primaryNodeFailure(event.Cause).Origin != netproxy.OriginLocalCleanup {
		d.confirmFailureLocked()
	}
	failureReportedAt := d.failures.reportedAt
	d.health.phase = healthUnhealthy
	d.health.readiness = event.ReadinessVersion
	d.failures.reportedAt = time.Time{}
	d.checks.pending &^= checkRequestDataPlane | checkRequestVerification
	d.checks.verify = false
	diagnostic := d.failures.last
	d.mu.Unlock()
	if resourceFailure {
		d.recordResourceFailure()
		d.recordConnectionFailure()
	}
	if wasHealthy {
		fields := log.Fields{"node": d.name, "state": event.State}
		if diagnostic != nil {
			fields["scope"] = diagnostic.Scope
			fields["layer"] = diagnostic.Layer
			fields["reason"] = diagnostic.Reason
			fields["operation"] = diagnostic.Phase
			if diagnostic.Code != "" {
				fields["code"] = diagnostic.Code
			}
		}
		entry := log.WithFields(fields)
		if event.Cause != nil {
			entry = entry.WithError(event.Cause)
		}
		if event.Cause == nil || primaryNodeFailure(event.Cause).Origin == netproxy.OriginLocalCleanup {
			entry.Debug("Outbound session stopped accepting connections")
		} else {
			entry.Warn("Outbound session unavailable")
		}
		d.recordAvailability(false, false, failureReportedAt)
		d.notifyGroups(SelectionForceNone)
	}
	return readinessChanged
}

func (d *pathRuntime) healthyAt(seq uint64) bool {
	d.mu.RLock()
	healthy := d.health.phase.usable() && d.health.readiness == seq
	d.mu.RUnlock()
	return healthy
}
