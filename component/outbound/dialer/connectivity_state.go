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

func (d *pathRuntime) reportDataPlaneFailure(failure netproxy.Failure) {
	d.mu.Lock()
	if d.ctx.Err() != nil {
		d.mu.Unlock()
		return
	}
	startedConfirmation := false
	session := d.sessionSnapshot()
	if d.checksConnectivity && d.health == healthHealthy && d.healthyLocked(session) {
		d.health = healthConfirming
		d.failureReportedAt = time.Now()
		d.failureGeneration++
		d.lastFailure = failureSnapshot(failure, d.failureGeneration)
		d.statusRevision++
		d.pendingCheck |= checkRequestDataPlane
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
	states := d.networks
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

func (d *pathRuntime) takePendingForceLocked() SelectionForceMask {
	if !d.health.usable() {
		return SelectionForceNone
	}
	force := d.pendingForce
	d.pendingForce = SelectionForceNone
	return force
}

func (d *pathRuntime) applyCheck(result checkResult) (appliedCheck, bool) {
	d.mu.Lock()
	if d.ctx.Err() != nil {
		d.mu.Unlock()
		return appliedCheck{}, false
	}
	if d.pendingCheck&checkRequestEnvironment != 0 {
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
			d.lastFailure = failureSnapshot(primaryNodeFailure(result.connectErr), d.failureGeneration)
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
		d.health = healthHealthy
		d.healthSeq = observedReadiness
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
	default:
		d.mu.Unlock()
		return appliedCheck{}, false
	}
}

func (d *pathRuntime) applyConnectErrorLocked(result checkResult, session netproxy.StateEvent) appliedCheck {
	failureReportedAt := d.failureReportedAt
	previousHealthy := d.healthyLocked(session)
	if result.kind != checkSupport {
		d.health = healthUnhealthy
		d.healthSeq = result.readiness
		d.failureReportedAt = time.Time{}
		d.pendingCheck &^= checkRequestDataPlane
		d.statusRevision++
		if d.lastFailure == nil {
			d.lastFailure = failureSnapshot(primaryNodeFailure(result.connectErr), d.failureGeneration)
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
	failureReportedAt := d.failureReportedAt
	d.healthSeq = result.readiness
	d.statusRevision++
	if !success {
		if err := result.failure(); err != nil && d.lastFailure == nil {
			d.lastFailure = failureSnapshot(primaryNodeFailure(err), d.failureGeneration)
		}
		d.health = healthUnhealthy
		d.failureReportedAt = time.Time{}
		d.pendingCheck &^= checkRequestDataPlane
		return failureReportedAt
	}
	if d.health != healthConfirming || result.generation >= d.failureGeneration {
		d.health = healthHealthy
		d.failureReportedAt = time.Time{}
		session := d.sessionSnapshot()
		if session.Cause == nil && !session.RecoveryRequired {
			d.lastFailure = nil
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

	previousPhase := d.health
	previousHealthy := previousPhase.usable()
	canonicalIndex := firstSupportedNetwork(d.networks)
	canonicalResult := resultProbe(result, canonicalIndex)
	if !initial && !discovered.Contains(canonicalIndex) {
		canonicalResult = nil
	}
	healthApplied := initial || canonicalResult != nil
	failureReportedAt := d.failureReportedAt
	if healthApplied {
		failureReportedAt = d.applyHealthResultLocked(result, canonicalResult != nil && canonicalResult.err == nil)
		if canonicalResult != nil {
			d.recordLatencyLocked(canonicalResult.latency, canonicalResult.err == nil)
		}
	}

	d.pendingForce |= discovered
	forceSelection := d.takePendingForceLocked()
	currentHealthy := d.health.usable()
	phaseChanged := previousPhase != d.health
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
	previousHealthy := d.health.usable()
	var canonicalResult *probeResult
	if len(result.probes) > 0 {
		canonicalResult = &result.probes[0]
	}
	failureReportedAt := d.applyHealthResultLocked(result, canonicalResult != nil && canonicalResult.err == nil)
	if canonicalResult != nil {
		d.recordLatencyLocked(canonicalResult.latency, canonicalResult.err == nil)
	}
	forceSelection := d.takePendingForceLocked()
	currentHealthy := d.health.usable()
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
	if d.ctx.Err() != nil || event.Seq <= d.observedSessionSeq {
		d.mu.Unlock()
		return false
	}
	d.observedSessionSeq = event.Seq
	d.statusRevision++
	resourceFailure := false
	if event.Cause != nil {
		failure := primaryNodeFailure(event.Cause)
		if failure.Scope == netproxy.ScopeUnknown && event.State == netproxy.SessionDisconnected && (d.health.usable() || event.EpisodeID != 0) {
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
		if resourceFailure || !shared && d.lastFailure == nil {
			d.lastFailure = failureSnapshot(failure, event.EpisodeID)
		}
	} else {
		d.observeResourceFailureLocked(event, false)
	}
	if event.Accepting {
		unchecked := !d.checksConnectivity
		if unchecked {
			d.health = healthHealthy
			d.healthSeq = event.ReadinessVersion
			if event.Cause == nil && !event.RecoveryRequired {
				d.lastFailure = nil
			}
		} else if d.health.usable() && d.healthSeq == event.ReadinessVersion && event.Cause == nil && !event.RecoveryRequired {
			d.lastFailure = nil
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
	wasHealthy := d.health.usable()
	if wasHealthy {
		d.recovery.Attempt = 0
	}
	readinessChanged := d.healthSeq != event.ReadinessVersion
	failureReportedAt := d.failureReportedAt
	d.health = healthUnhealthy
	d.healthSeq = event.ReadinessVersion
	d.failureReportedAt = time.Time{}
	d.pendingCheck &^= checkRequestDataPlane
	diagnostic := d.lastFailure
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
	healthy := d.health.usable() && d.healthSeq == seq
	d.mu.RUnlock()
	return healthy
}
