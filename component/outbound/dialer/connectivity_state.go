/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"errors"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

// networkState records irreversible mode capability. Reachability is shared
// by all supported modes through pathHealth.phase.
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

// pathHealth contains shared reachability, capabilities and successful observations.
// It is protected by pathRuntime.mu; it carries no group monitoring policy.
type pathHealth struct {
	phase              healthPhase
	readiness          uint64
	observedSessionSeq uint64
	networks           [common.NetworkTypeCount]networkState
	pendingForce       SelectionForceMask
	proofSequence      uint64
	proofs             [common.NetworkTypeCount]HealthProof
	lastLatency        time.Duration
	measuredAt         time.Time
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

func (d *Dialer) Usable(networkType *common.NetworkType) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return !d.closed && d.healthyLocked(d.sessionSnapshot()) && d.health.networks[networkType.Index()] == networkSupported
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

type probeTransition struct {
	probe    probeResult
	previous networkState
	current  networkState
}

func (d *pathRuntime) applyCapabilityResultsLocked(result checkResult) []probeTransition {
	transitions := make([]probeTransition, 0, len(result.probes))
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
		transitions = append(transitions, probeTransition{
			probe:    probe,
			previous: previous,
			current:  d.health.networks[index],
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
	if result.connectErr != nil {
		return d.applyConnectErrorLocked(result, session), true
	}
	if d.session != nil && !session.Accepting {
		d.mu.Unlock()
		return appliedCheck{}, false
	}
	if !d.checksConnectivity {
		d.health.phase = healthHealthy
		d.health.readiness = observedReadiness
		d.statusRevision++
		d.mu.Unlock()
		d.recordAvailability(true, false, time.Time{})
		d.notifyGroups(SelectionForceNone)
		return appliedCheck{success: true, healthApplied: true}, true
	}

	switch result.kind {
	case checkInitial, checkSupport:
		return d.applyCapabilityCheckLocked(result), true
	case checkHealth:
		return d.applyHealthCheckLocked(result), true
	case checkSelection:
		return d.applySelectionCheckLocked(result), true
	default:
		d.mu.Unlock()
		return appliedCheck{}, false
	}
}

func (d *pathRuntime) applyConnectErrorLocked(result checkResult, session netproxy.StateEvent) appliedCheck {
	failureReportedAt := d.failures.reportedAt
	previousHealthy := d.healthyLocked(session)
	if result.kind != checkSupport {
		d.confirmFailureLocked()
		d.health.phase = healthUnhealthy
		d.health.readiness = result.readiness
		d.failures.reportedAt = time.Time{}
		d.checks.pending &^= checkRequestDataPlane
		d.statusRevision++
		if d.failures.last == nil {
			d.failures.last = failureSnapshot(primaryNodeFailure(result.connectErr), d.failures.generation)
		}
	}
	d.mu.Unlock()
	if result.kind != checkSupport {
		d.logCheckOutcome(previousHealthy, false, nil, nil, result)
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
	d.health.readiness = result.readiness
	d.statusRevision++
	if !success {
		d.confirmFailureLocked()
		if err := result.failure(); err != nil && d.failures.last == nil {
			d.failures.last = failureSnapshot(primaryNodeFailure(err), d.failures.generation)
		}
		d.health.phase = healthUnhealthy
		d.failures.reportedAt = time.Time{}
		d.checks.pending &^= checkRequestDataPlane
		return failureReportedAt
	}
	if d.health.phase != healthConfirming || result.generation >= d.failures.generation {
		d.recordRecoverySuccessLocked()
		d.health.phase = healthHealthy
		d.failures.reportedAt = time.Time{}
		session := d.sessionSnapshot()
		if session.Cause == nil && !session.RecoveryRequired {
			d.failures.last = nil
		}
	}
	return failureReportedAt
}

func (d *pathRuntime) applyCapabilityCheckLocked(result checkResult) appliedCheck {
	initial := result.kind == checkInitial
	transitions := d.applyCapabilityResultsLocked(result)
	discovered := SelectionForceNone
	for _, transition := range transitions {
		if firstSupportConfirmed(transition) {
			discovered |= SelectionForceFor(transition.probe.network)
		}
	}

	previousPhase := d.health.phase
	previousHealthy := previousPhase.usable()
	canonicalIndex := firstSupportedNetwork(d.health.networks)
	canonicalResult := resultProbe(result, canonicalIndex)
	if !initial && !discovered.Contains(canonicalIndex) {
		canonicalResult = nil
	}
	// Selection checks may already have established health before the remaining
	// capabilities are discovered. Missing modes cannot invalidate that proof.
	healthApplied := canonicalResult != nil || initial && !canonicalIndex.Valid()
	failureReportedAt := d.failures.reportedAt
	if healthApplied {
		failureReportedAt = d.applyHealthResultLocked(result, canonicalResult != nil && canonicalResult.err == nil)
		if canonicalResult != nil {
			d.recordLatencyLocked(canonicalResult.latency, canonicalResult.err == nil)
		}
	}
	d.recordHealthProofsLocked(result)

	d.health.pendingForce |= discovered
	forceSelection := d.takePendingForceLocked()
	currentHealthy := d.health.phase.usable()
	phaseChanged := previousPhase != d.health.phase
	d.mu.Unlock()

	d.logCheckOutcome(previousHealthy, currentHealthy, canonicalResult, transitions, result)
	if healthApplied {
		d.recordAvailability(currentHealthy, true, failureReportedAt)
	}
	if initial || phaseChanged || forceSelection != SelectionForceNone {
		d.notifyGroups(forceSelection)
	}
	return appliedCheck{
		success:       currentHealthy,
		healthApplied: healthApplied,
	}
}

func (d *pathRuntime) applyHealthCheckLocked(result checkResult) appliedCheck {
	previousHealthy := d.health.phase.usable()
	var canonicalResult *probeResult
	if len(result.probes) > 0 {
		canonicalResult = &result.probes[0]
	}
	failureReportedAt := d.applyHealthResultLocked(result, canonicalResult != nil && canonicalResult.err == nil)
	if canonicalResult != nil {
		d.recordLatencyLocked(canonicalResult.latency, canonicalResult.err == nil)
	}
	d.recordHealthProofsLocked(result)
	forceSelection := d.takePendingForceLocked()
	currentHealthy := d.health.phase.usable()
	d.mu.Unlock()

	d.logCheckOutcome(previousHealthy, currentHealthy, canonicalResult, nil, result)
	d.recordAvailability(currentHealthy, true, failureReportedAt)
	d.notifyGroups(forceSelection)
	return appliedCheck{success: currentHealthy}
}

func (d *pathRuntime) logCheckOutcome(previousHealthy, success bool, canonical *probeResult, transitions []probeTransition, result checkResult) {
	if result.kind == checkInitial {
		if result.connectErr != nil {
			log.WithField("node", d.name).WithError(result.connectErr).Debug("Connectivity initial check failed")
		}
		for _, transition := range transitions {
			fields := log.Fields{
				"node":    d.name,
				"network": transition.probe.network.String(),
			}
			entry := log.WithFields(fields)
			if transition.probe.err == nil {
				entry.WithField("latency", transition.probe.latency.Truncate(time.Millisecond).String()).Trace("Connectivity initial check succeeded")
			} else {
				entry.WithError(transition.probe.err).Debug("Connectivity initial check failed")
			}
		}
	}

	var supported, unsupported []string
	for _, transition := range transitions {
		if firstSupportConfirmed(transition) {
			supported = append(supported, transition.probe.network.String())
		} else if result.kind == checkSupport && transition.previous != transition.current && transition.current == networkUnsupported {
			unsupported = append(unsupported, transition.probe.network.String())
		}
	}
	if len(supported) > 0 {
		log.WithFields(log.Fields{
			"cause":    checkKindName[result.kind],
			"networks": supported,
			"node":     d.name,
		}).Debug("Connectivity modes supported")
	}
	if len(unsupported) > 0 {
		log.WithFields(log.Fields{
			"cause":    checkKindName[result.kind],
			"networks": unsupported,
			"node":     d.name,
		}).Debug("Connectivity modes unsupported")
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
			// availability history. The next generation requires a fresh proof.
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
			d.health.phase = healthHealthy
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
	d.checks.pending &^= checkRequestDataPlane
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
