/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Package stats keeps process-lifetime availability statistics of nodes and
// outbound groups. Single-value state (current aliveness and event timestamps)
// lives in the prometheus gauges declared in package common, which survive
// control-plane reloads. Uptime and duration accounting plus rolling-window
// history live here because the prometheus client registry retains current
// samples, not a queryable time series.
package stats

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

var ProcessStart = time.Now()

// registryMu serializes identity reconciliation with records and snapshots.
// Availability itself has a finer-grained lock for normal concurrent updates.
var registryMu sync.RWMutex

func RecordReload() {
	common.LastReloadTime.Set(float64(time.Now().Unix()))
}

// LastReload returns when the last control-plane reload finished, or the
// zero time if no reload has happened since process start.
func LastReload() time.Time {
	return gaugeTime(common.LastReloadTime)
}

// Availability is a point-in-time view of the uptime of a node or group.
type Availability struct {
	Seen                 bool          // false until the first record
	Alive                bool          // current state
	AliveSince           time.Time     // start of the current up-streak; zero while down
	LastFailureStartedAt time.Time     // start of the current or most recently completed failure
	LastFailureDuration  time.Duration // current failure duration while down; final duration while alive
	LastCheckAt          time.Time     // last connectivity check; zero if none (groups, unchecked nodes)
	LastConnFailAt       time.Time     // last connection failure reported by the data plane; zero if none
	UpRatio              float64       // up time / total time since first seen
	UpDuration           time.Duration // length of the current up-streak

	// Check counters are zero for groups (which run no checks); each check
	// appends one latency sample, so
	// ChecksSinceAlive also tells how many fresh samples the avg10 window
	// and the moving average have absorbed.
	ChecksTotal      int64 // total connectivity checks
	ChecksFailed     int64 // failed checks
	ChecksSinceAlive int64 // checks since the current up-streak began, inclusive; stale while down
	ChecksSinceFail  int64 // checks since the latest failed sample, inclusive; counts all checks if none failed

	Recent24h AvailabilityWindow // statistics observed during the trailing 24 hours
}

// GroupAvailability adds current and recent aggregate connectivity states to
// the time-weighted availability statistics of an outbound group.
type GroupAvailability struct {
	Availability
	Recent GroupStateWindow
}

type gauge interface {
	Set(float64)
	Inc()
	Write(*dto.Metric) error
}

func metricValue(m interface{ Write(*dto.Metric) error }) float64 {
	var d dto.Metric
	if err := m.Write(&d); err != nil {
		return 0
	}
	if g := d.GetGauge(); g != nil {
		return g.GetValue()
	}
	return d.GetCounter().GetValue()
}

func gaugeValue(g gauge) float64              { return metricValue(g) }
func counterValue(c prometheus.Counter) int64 { return int64(metricValue(c)) }
func gaugeBool(g gauge) bool                  { return metricValue(g) != 0 }

func gaugeTime(g gauge) time.Time {
	if sec := metricValue(g); sec > 0 {
		return time.Unix(int64(sec), 0)
	}
	return time.Time{}
}

func setGaugeTime(g gauge, t time.Time) {
	g.Set(float64(t.Unix()))
}

func boolFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// availability keeps uptime and duration accounting for one identity. Its
// wall-clock state is mirrored to the prometheus handles below.
type availability struct {
	mu                       sync.Mutex
	labels                   prometheus.Labels
	firstSeen                time.Time // zero until the first record
	totalUp                  time.Duration
	lastAcc                  time.Time // last time totalUp was brought up to date
	failureStartedAt         time.Time // retains monotonic time for duration accounting
	completedFailureDuration time.Duration
	alive                    gauge
	aliveSince               gauge       // set on transitions to alive; stale while down
	failureStart             gauge       // wall-clock start retained after recovery
	checks                   *nodeChecks // nil for groups, which run no connectivity checks
	recent                   recentAvailability
}

// nodeChecks holds the check-related series of a node. Each connectivity
// check appends one latency sample, so the counters double as
// latency-sample counts.
type nodeChecks struct {
	lastCheck    gauge
	lastConnFail gauge
	total        prometheus.Counter
	failed       prometheus.Counter
	sinceAlive   gauge // reset at the check that starts an up-streak
	sinceFailure gauge // reset at every failed check
}

// record updates the check counters for one connectivity check; transition
// is true when the check flipped the aliveness state.
func (c *nodeChecks) record(alive, transition bool, now time.Time) {
	setGaugeTime(c.lastCheck, now)
	c.total.Inc()
	if !alive {
		c.failed.Inc()
		c.sinceFailure.Set(1)
		return
	}
	if transition {
		c.sinceAlive.Set(1)
	} else {
		c.sinceAlive.Inc()
	}
	c.sinceFailure.Inc()
}

func (a *availability) record(alive, checked bool, now time.Time, failureStartedAt ...time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	prevAlive := gaugeBool(a.alive)
	firstObservation := a.firstSeen.IsZero()
	transitionAt := now
	if !alive && len(failureStartedAt) != 0 && !failureStartedAt[0].IsZero() {
		transitionAt = failureStartedAt[0]
	}
	if firstObservation {
		a.firstSeen = transitionAt
	} else if prevAlive {
		a.totalUp += transitionAt.Sub(a.lastAcc)
	}
	a.lastAcc = now
	if alive != prevAlive {
		a.alive.Set(boolFloat(alive))
		if alive {
			setGaugeTime(a.aliveSince, now)
			if !a.failureStartedAt.IsZero() {
				a.completedFailureDuration = max(now.Sub(a.failureStartedAt), 0)
			}
		}
	}
	if !alive && (firstObservation || prevAlive) {
		a.failureStartedAt = transitionAt
		a.completedFailureDuration = 0
		setGaugeTime(a.failureStart, transitionAt)
	}
	isCheck := checked && a.checks != nil
	if isCheck {
		a.checks.record(alive, alive != prevAlive, now)
	}
	a.recent.record(now, alive, isCheck, transitionAt)
}

func (a *availability) recordConnFail(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	setGaugeTime(a.checks.lastConnFail, now)
}

func (a *availability) snapshot() Availability {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.snapshotLocked(time.Now())
}

func (a *availability) snapshotAt(now time.Time) Availability {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.snapshotLocked(now)
}

func (a *availability) snapshotLocked(now time.Time) Availability {
	if a.firstSeen.IsZero() {
		return Availability{}
	}
	snap := Availability{
		Seen:                 true,
		Alive:                gaugeBool(a.alive),
		LastFailureStartedAt: gaugeTime(a.failureStart),
		Recent24h:            a.recent.snapshot(a.firstSeen, now),
	}
	if c := a.checks; c != nil {
		snap.LastCheckAt = gaugeTime(c.lastCheck)
		snap.LastConnFailAt = gaugeTime(c.lastConnFail)
		snap.ChecksTotal = counterValue(c.total)
		snap.ChecksFailed = counterValue(c.failed)
		snap.ChecksSinceAlive = int64(metricValue(c.sinceAlive))
		snap.ChecksSinceFail = int64(metricValue(c.sinceFailure))
	}
	totalUp := a.totalUp
	if snap.Alive {
		snap.AliveSince = gaugeTime(a.aliveSince)
		snap.UpDuration = now.Sub(snap.AliveSince)
		totalUp += now.Sub(a.lastAcc)
	}
	if !snap.LastFailureStartedAt.IsZero() {
		snap.LastFailureDuration = a.completedFailureDuration
		if !snap.Alive && !a.failureStartedAt.IsZero() {
			snap.LastFailureDuration = max(now.Sub(a.failureStartedAt), 0)
		}
	}
	if total := now.Sub(a.firstSeen); total > 0 {
		snap.UpRatio = float64(totalUp) / float64(total)
	}
	return snap
}

// Node keys are node identities (see dialer.StatsKey) that stay stable across
// control-plane reloads.
var nodes sync.Map // key -> *availability

// NodeID is the value of the "id" label of node-level series. A 128-bit
// prefix keeps labels compact while making accidental identity collisions
// negligible.
func NodeID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16])
}

func nodeAvailability(key, subtag, name string) *availability {
	if v, ok := nodes.Load(key); ok {
		return v.(*availability)
	}
	labels := prometheus.Labels{"id": NodeID(key), "subtag": subtag, "dialer": name}
	a := &availability{
		labels:       labels,
		alive:        common.NodeAlive.With(labels),
		aliveSince:   common.NodeAliveSince.With(labels),
		failureStart: common.NodeLastFailureStart.With(labels),
		checks: &nodeChecks{
			lastCheck:    common.NodeLastCheck.With(labels),
			lastConnFail: common.NodeLastConnFailure.With(labels),
			total:        common.NodeChecksTotal.With(labels),
			failed:       common.NodeCheckFailures.With(labels),
			sinceAlive:   common.NodeChecksSinceAlive.With(labels),
			sinceFailure: common.NodeChecksSinceFailure.With(labels),
		},
	}
	v, _ := nodes.LoadOrStore(key, a)
	return v.(*availability)
}

// RecordNode records the state of a node. checked should be true when the
// state comes from a connectivity check (as opposed to registration).
func RecordNode(key, subtag, name string, alive, checked bool, failureStartedAt ...time.Time) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	nodeAvailability(key, subtag, name).record(alive, checked, time.Now(), failureStartedAt...)
}

// RecordNodeConnFail records that traffic through the node failed outside of
// scheduled connectivity checks. It is a no-op for nodes never recorded,
// which cannot carry traffic anyway.
func RecordNodeConnFail(key string) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	v, ok := nodes.Load(key)
	if !ok {
		return
	}
	v.(*availability).recordConnFail(time.Now())
}

func GetNode(key string) Availability {
	registryMu.RLock()
	defer registryMu.RUnlock()
	v, ok := nodes.Load(key)
	if !ok {
		return Availability{}
	}
	return v.(*availability).snapshot()
}

type groupStats struct {
	mu           sync.Mutex
	availability *availability
	states       recentGroupStates
}

var groups sync.Map // group name -> *groupStats

func newGroupStats(name string) *groupStats {
	labels := prometheus.Labels{"outbound": name}
	return &groupStats{
		availability: &availability{
			labels:       labels,
			alive:        common.GroupAvailable.With(labels),
			aliveSince:   common.GroupAvailableSince.With(labels),
			failureStart: common.GroupLastFailureStart.With(labels),
		},
	}
}

func groupStatistics(name string) *groupStats {
	if v, ok := groups.Load(name); ok {
		return v.(*groupStats)
	}
	g := newGroupStats(name)
	v, _ := groups.LoadOrStore(name, g)
	return v.(*groupStats)
}

func RecordGroup(name string, available bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	g := groupStatistics(name)
	now := time.Now()
	g.availability.record(available, false, now)
	g.mu.Lock()
	g.states.record(now, available)
	g.mu.Unlock()
}

func GetGroup(name string) GroupAvailability {
	registryMu.RLock()
	defer registryMu.RUnlock()
	v, ok := groups.Load(name)
	if !ok {
		return GroupAvailability{
			Recent: emptyGroupStateWindow(),
		}
	}
	g := v.(*groupStats)
	now := time.Now()
	g.mu.Lock()
	recent := g.states.snapshot(now)
	g.mu.Unlock()
	return GroupAvailability{
		Availability: g.availability.snapshotAt(now),
		Recent:       recent,
	}
}

// NodeIdentity describes an availability identity retained by the currently
// committed control plane.
type NodeIdentity struct {
	Key    string
	Subtag string
	Name   string
}

func sameLabels(a, b prometheus.Labels) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func deleteNodeMetrics(labels prometheus.Labels) {
	common.NodeAlive.Delete(labels)
	common.NodeAliveSince.Delete(labels)
	common.NodeLastFailureStart.Delete(labels)
	common.NodeLastCheck.Delete(labels)
	common.NodeLastConnFailure.Delete(labels)
	common.NodeChecksTotal.Delete(labels)
	common.NodeCheckFailures.Delete(labels)
	common.NodeChecksSinceAlive.Delete(labels)
	common.NodeChecksSinceFailure.Delete(labels)
}

func deleteGroupMetrics(group *groupStats) {
	common.GroupAvailable.Delete(group.availability.labels)
	common.GroupAvailableSince.Delete(group.availability.labels)
	common.GroupLastFailureStart.Delete(group.availability.labels)
}

// Reconcile removes availability state and prometheus series that do not
// belong to the newly committed control plane. Retained identities preserve
// their process-lifetime history across reloads; identities removed and later
// re-added start a fresh history rather than counting their absence as uptime.
// Call it only after the retired plane's health-check goroutines have stopped.
func Reconcile(activeNodes []NodeIdentity, activeGroups []string) {
	registryMu.Lock()
	defer registryMu.Unlock()

	nodeLabels := make(map[string]prometheus.Labels, len(activeNodes))
	for _, node := range activeNodes {
		nodeLabels[node.Key] = prometheus.Labels{
			"id":     NodeID(node.Key),
			"subtag": node.Subtag,
			"dialer": node.Name,
		}
	}
	nodes.Range(func(key, value any) bool {
		labels, keep := nodeLabels[key.(string)]
		a := value.(*availability)
		if !keep || !sameLabels(a.labels, labels) {
			deleteNodeMetrics(a.labels)
			nodes.Delete(key)
		}
		return true
	})

	groupNames := make(map[string]struct{}, len(activeGroups))
	for _, name := range activeGroups {
		groupNames[name] = struct{}{}
	}
	groups.Range(func(key, value any) bool {
		if _, keep := groupNames[key.(string)]; !keep {
			deleteGroupMetrics(value.(*groupStats))
			groups.Delete(key)
		}
		return true
	})
}
