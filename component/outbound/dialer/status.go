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
	Monitoring      bool // Shared worker demand, including other groups.
	RecoveryElapsed time.Duration
	FailureRecovery time.Duration
	MeasuredAt      time.Time
	Proof           HealthProof
}

// ConnectivitySnapshot is the state needed to aggregate a dialer into its
// group. It deliberately excludes process-lifetime statistics.
type ConnectivitySnapshot struct {
	Usable            [common.NetworkTypeCount]bool
	InitialCheckDone  bool
	ConfirmingFailure bool
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
		Usable:          !d.closed && d.healthyLocked(session) && state == networkSupported,
		Dormant:         dormant,
		ObservedHealthy: !d.closed && d.health.phase == healthHealthy,
		Support:         supportState(state),
	}
	snapshot.Latency, snapshot.HasLatency = d.latencyStatsLocked()
	snapshot.Degraded, snapshot.RecoveryElapsed, snapshot.FailureRecovery = d.degradationLocked()
	snapshot.Monitoring = !d.checks.paused
	snapshot.MeasuredAt = d.health.measuredAt
	snapshot.Proof = d.healthProofLocked(networkType.Index())
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
	for i, state := range d.health.networks {
		snapshot.Usable[i] = healthy && state == networkSupported
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
		Checking:           d.checks.running || d.checks.pending != 0 || (!d.checks.paused && d.checks.checkedAt.IsZero()),
		CheckedAt:          d.checks.checkedAt,
		ConfirmingFailure:  healthy && d.health.phase == healthConfirming,
		Session:            session,
		HasSession:         d.session != nil,
	}
	for i, state := range d.health.networks {
		snapshot.SupportState[i] = supportState(state)
	}
	return snapshot
}
