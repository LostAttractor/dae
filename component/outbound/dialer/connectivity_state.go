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

// networkState records mode capability; transient reachability has a separate lifecycle.
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

type modeHealth struct {
	phase       healthPhase
	readiness   uint64
	lastLatency time.Duration
	measuredAt  time.Time
	failures    pathFailures
}

// pathHealth holds per-mode reachability and the shared session/authentication gate.
// phase is an aggregate observation for node status, never a mode admission rule.
// It is protected by pathRuntime.mu; it carries no group monitoring policy.
type pathHealth struct {
	phase              healthPhase
	blocked            bool
	modes              [common.NetworkTypeCount]modeHealth
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
	return d.ctx.Err() == nil && !d.health.blocked && d.health.phase.usable() && (d.session == nil || session.Accepting && d.health.readiness == session.ReadinessVersion)
}

func (d *pathRuntime) modeUsableLocked(index common.NetworkIndex, session netproxy.StateEvent) bool {
	return index.Valid() && d.healthyLocked(session) && d.health.networks[index] == networkSupported && d.health.modes[index].phase.usable() && d.health.modes[index].readiness == d.health.readiness
}

func (d *pathRuntime) aggregateHealthLocked() {
	d.health.phase = healthUnhealthy
	if d.health.blocked {
		return
	}
	for i, mode := range d.health.modes {
		if d.health.networks[i] != networkSupported || mode.readiness != d.health.readiness {
			continue
		}
		if mode.phase == healthConfirming {
			d.health.phase = healthConfirming
			return
		}
		if mode.phase == healthHealthy {
			d.health.phase = healthHealthy
		}
	}
}

func (d *pathRuntime) modeGenerationsLocked() (generations [common.NetworkTypeCount]uint64) {
	for i := range generations {
		generations[i] = d.health.modes[i].failures.generation
	}
	return
}

func (d *Dialer) Usable(networkType *common.NetworkType) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return !d.closed && d.modeUsableLocked(networkType.Index(), d.sessionSnapshot())
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

func (d *pathRuntime) reportDataPlaneFailure(failure netproxy.Failure, network common.NetworkIndex) {
	d.mu.Lock()
	if d.ctx.Err() != nil {
		d.mu.Unlock()
		return
	}
	started := false
	if d.checksConnectivity && d.healthyLocked(d.sessionSnapshot()) {
		for i := range d.health.modes {
			if network.Valid() && common.NetworkIndex(i) != network {
				continue
			}
			mode := &d.health.modes[i]
			if mode.phase != healthHealthy {
				continue
			}
			mode.phase = healthConfirming
			mode.failures.generation++
			mode.failures.reportedAt = time.Now()
			started = true
		}
		if started {
			if !network.Valid() {
				d.failures.generation++
				d.failures.reportedAt = time.Now()
			}
			d.failures.last = failureSnapshot(failure, d.failures.generation)
			d.aggregateHealthLocked()
			d.statusRevision++
			d.checks.pending |= checkRequestDataPlane
		}
	}
	d.mu.Unlock()
	d.recordConnectionFailure()
	if started {
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
	force := SelectionForceNone
	for i := range d.health.modes {
		index := common.NetworkIndex(i)
		if d.health.pendingForce.Contains(index) && d.modeUsableLocked(index, d.sessionSnapshot()) {
			force |= SelectionForceFor(index)
		}
	}
	d.health.pendingForce &^= force
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
			d.failures.last = failureSnapshot(primaryNodeFailure(result.failure()), d.failures.generation)
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
		d.health.blocked = false
		d.health.phase = healthHealthy
		for i := range d.health.modes {
			d.health.modes[i].phase = healthHealthy
			d.health.modes[i].readiness = observedReadiness
		}
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
	if result.kind != checkSupport || recoveryBlockedReason(result.failure()) != "" {
		d.confirmFailureLocked()
		d.health.blocked = true
		d.health.phase = healthUnhealthy
		for i := range d.health.modes {
			d.health.modes[i].phase = healthUnhealthy
		}
		d.health.readiness = result.readiness
		d.failures.reportedAt = time.Time{}
		d.checks.pending &^= checkRequestDataPlane
		d.statusRevision++
		if d.failures.last == nil {
			d.failures.last = failureSnapshot(primaryNodeFailure(result.failure()), d.failures.generation)
		}
	}
	d.mu.Unlock()
	if result.kind != checkSupport || recoveryBlockedReason(result.failure()) != "" {
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

func (d *pathRuntime) applyCapabilityCheckLocked(result checkResult) appliedCheck {
	transitions := d.applyCapabilityResultsLocked(result)
	for _, transition := range transitions {
		if firstSupportConfirmed(transition) {
			d.health.pendingForce |= SelectionForceFor(transition.probe.network)
		}
	}
	return d.applyModeResultsLocked(result, transitions)
}

func (d *pathRuntime) applyHealthCheckLocked(result checkResult) appliedCheck {
	return d.applyModeResultsLocked(result, nil)
}

func (d *pathRuntime) applyModeResultsLocked(result checkResult, transitions []probeTransition) appliedCheck {
	previousHealthy := d.healthyLocked(d.sessionSnapshot())
	failureReportedAt := d.failures.reportedAt
	fresh := result.generation == d.failures.generation
	if fresh {
		d.health.blocked = false
		d.health.readiness = result.readiness
	}
	applied := false
	appliedSuccess := false
	allSuccess := len(result.probes) > 0
	var representative *probeResult
	for i := range result.probes {
		probe := &result.probes[i]
		mode := &d.health.modes[probe.network]
		if probe.err == nil && (representative == nil || representative.err != nil) {
			representative = probe
		}
		if representative == nil {
			representative = probe
		}
		d.recordModeLatencyLocked(probe.network, probe.latency, probe.err == nil)
		allSuccess = allSuccess && probe.err == nil
		if !fresh || result.modeGenerations[probe.network] != mode.failures.generation {
			continue
		}
		applied = true
		if failureReportedAt.IsZero() {
			failureReportedAt = mode.failures.reportedAt
		}
		if probe.err != nil {
			mode.phase = healthUnhealthy
			if !errors.Is(probe.err, netproxy.UnsupportedTunnelTypeError) {
				d.confirmModeFailureLocked(probe.network)
				d.failures.last = failureSnapshot(primaryNodeFailure(probe.err), mode.failures.generation)
			}
		} else if d.health.networks[probe.network] == networkSupported {
			mode.phase = healthHealthy
			mode.readiness = result.readiness
			d.recordModeRecoverySuccessLocked(probe.network)
			appliedSuccess = true
		}
		mode.failures.reportedAt = time.Time{}
	}
	d.aggregateHealthLocked()
	if d.health.phase != healthConfirming {
		d.checks.pending &^= checkRequestDataPlane
	}
	currentHealthy := d.healthyLocked(d.sessionSnapshot())
	if appliedSuccess && currentHealthy && d.health.phase == healthHealthy {
		d.recordRecoverySuccessLocked()
		d.failures.reportedAt = time.Time{}
		if allSuccess && d.sessionSnapshot().Cause == nil && !d.sessionSnapshot().RecoveryRequired {
			d.failures.last = nil
		}
	}
	for _, network := range canonicalNetworkOrder {
		if probe := resultProbe(result, network); probe != nil && probe.err == nil {
			representative = probe
			break
		}
	}
	if representative != nil {
		d.recordLatencyLocked(representative.latency, representative.err == nil)
	}
	d.recordHealthProofsLocked(result)
	force := d.takePendingForceLocked()
	d.statusRevision++
	d.mu.Unlock()
	d.logCheckOutcome(previousHealthy, currentHealthy, representative, transitions, result)
	if applied {
		d.recordAvailability(currentHealthy, true, failureReportedAt)
	}
	d.notifyGroups(force)
	// Partial failures still schedule retries, without revoking healthy modes.
	success := allSuccess && fresh
	if result.kind == checkInitial || result.kind == checkSupport {
		success = currentHealthy
	}
	return appliedCheck{success: success, healthApplied: applied}
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
			d.health.blocked = false
			d.health.phase = healthHealthy
			for i := range d.health.modes {
				d.health.modes[i].phase = healthHealthy
				d.health.modes[i].readiness = event.ReadinessVersion
			}
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
	d.health.blocked = true
	d.health.phase = healthUnhealthy
	for i := range d.health.modes {
		d.health.modes[i].phase = healthUnhealthy
	}
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
