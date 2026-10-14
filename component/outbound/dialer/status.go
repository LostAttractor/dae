/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/outbound/netproxy"
)

type SelectionSnapshot struct {
	Usable          bool
	Dormant         bool
	ObservedHealthy bool
	Support         api.NetworkSupportState
	HasLatency      bool
	Latency         api.LatencyStats
	Degraded        bool
	RecoveryElapsed time.Duration
	FailureRecovery time.Duration
	MeasuredAt      time.Time
	Monitoring      bool // Shared worker demand, including other groups.
	Proof           HealthProof
}

// ConnectivitySnapshot is the state needed to aggregate a dialer into its
// group. It deliberately excludes process-lifetime statistics.
type ConnectivitySnapshot struct {
	Usable            [common.NetworkTypeCount]bool
	InitialCheckDone  bool
	ConfirmingFailure bool
	Confirming        [common.NetworkTypeCount]bool
}

func supportState(state networkState) api.NetworkSupportState {
	switch state {
	case networkSupported:
		return api.NetworkSupportConfirmed
	case networkUnsupported:
		return api.NetworkSupportUnsupported
	default:
		return api.NetworkSupportUnknown
	}
}

// RuntimeSnapshot is a coherent view of a dialer's current connectivity state.
// Process-lifetime availability statistics are sampled after releasing its lock.
type RuntimeSnapshot struct {
	ObservedHealthy    bool
	Revision           uint64
	ObservedSessionSeq uint64
	Recovery           RecoverySnapshot
	Failure            *FailureSnapshot
	Healthy            bool
	Dormant            bool // Physical transport released, not a group's probe policy.
	InitialCheckDone   bool
	CheckEnabled       bool
	Checking           bool
	CheckedAt          time.Time
	ConfirmingFailure  bool
	SupportState       [common.NetworkTypeCount]api.NetworkSupportState
	Usable             [common.NetworkTypeCount]bool
	Session            netproxy.StateEvent
	HasSession         bool
	HasLatency         bool
	Latency            api.LatencyStats
	Availability       api.Availability
	Degraded           bool
	RecoveryElapsed    time.Duration
	FailureRecovery    time.Duration
	MeasuredAt         time.Time
}

func (d *Dialer) SelectionSnapshot(networkType *common.NetworkType) SelectionSnapshot {
	d.mu.RLock()
	session := d.sessionSnapshot()
	dormant := false
	if d.dormant != nil {
		session, dormant = d.dormant.status()
	}
	state := d.health.networks[networkType.Index()]
	snapshot := SelectionSnapshot{
		Usable:          !d.closed && d.modeUsableLocked(networkType.Index(), session),
		Dormant:         dormant,
		ObservedHealthy: !d.closed && !d.health.blocked && d.health.modes[networkType.Index()].phase == healthHealthy,
		Support:         supportState(state),
	}
	if d.group != nil {
		snapshot.Latency, snapshot.HasLatency = d.group.modeLatency[networkType.Index()].snapshot()
	}
	snapshot.Degraded, snapshot.RecoveryElapsed, snapshot.FailureRecovery = d.modeDegradationLocked(networkType.Index())
	snapshot.MeasuredAt = d.health.modes[networkType.Index()].measuredAt
	snapshot.Monitoring = !d.checks.paused
	snapshot.Proof = d.health.proofs[networkType.Index()]
	d.mu.RUnlock()
	return snapshot
}

func (d *Dialer) ConnectivitySnapshot() ConnectivitySnapshot {
	d.mu.RLock()
	session := d.sessionSnapshot()
	healthy := !d.closed && d.healthyLocked(session)
	snapshot := ConnectivitySnapshot{
		InitialCheckDone:  d.initialCheckCompletedLocked(),
		ConfirmingFailure: healthy && d.health.phase == healthConfirming,
	}
	for i := range d.health.networks {
		snapshot.Usable[i] = !d.closed && d.modeUsableLocked(common.NetworkIndex(i), session)
		snapshot.Confirming[i] = snapshot.Usable[i] && d.health.modes[i].phase == healthConfirming
	}
	d.mu.RUnlock()
	return snapshot
}

func (d *Dialer) RuntimeStatus() RuntimeSnapshot {
	d.mu.RLock()
	snapshot := d.runtimeStatusLocked()
	snapshot.Healthy = snapshot.Healthy && !d.closed
	snapshot.CheckEnabled = d.checkEnabled && !d.closed
	snapshot.Latency, snapshot.HasLatency = d.latencyStatsLocked()
	snapshot.Degraded, snapshot.RecoveryElapsed, snapshot.FailureRecovery = d.degradationLocked()
	snapshot.MeasuredAt = d.health.measuredAt
	d.mu.RUnlock()
	snapshot.Availability = stats.DefaultStore.GetNode(d.StatsKey())
	return snapshot
}

func (d *pathRuntime) runtimeStatus() RuntimeSnapshot {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.runtimeStatusLocked()
}

func (d *pathRuntime) runtimeStatusLocked() RuntimeSnapshot {
	session := d.sessionSnapshot()
	dormant := false
	if d.dormant != nil {
		// Sample readiness and physical sleep together while connections may
		// independently release the last transport reference.
		session, dormant = d.dormant.status()
	}
	healthy := d.healthyLocked(session)
	snapshot := RuntimeSnapshot{
		ObservedHealthy:    d.health.phase.usable(),
		Revision:           d.statusRevision,
		ObservedSessionSeq: d.health.observedSessionSeq,
		Recovery:           d.recoverySnapshotLocked(session, healthy),
		Failure:            d.failures.last,
		Healthy:            healthy,
		Dormant:            dormant,
		InitialCheckDone:   d.initialCheckCompletedLocked(),
		CheckEnabled:       !d.checks.paused,
		Checking:           d.checks.operation != checkIdle || d.checks.pending != 0 || (!d.checks.paused && d.checks.checkedAt.IsZero()),
		CheckedAt:          d.checks.checkedAt,
		ConfirmingFailure:  healthy && d.health.phase == healthConfirming,
		Session:            session,
		HasSession:         d.session != nil,
	}
	for i, state := range d.health.networks {
		snapshot.SupportState[i] = supportState(state)
		snapshot.Usable[i] = d.modeUsableLocked(common.NetworkIndex(i), session)
	}
	return snapshot
}
