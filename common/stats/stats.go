/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Package stats keeps process-lifetime availability statistics of nodes and
// outbound groups. Single-value state (current aliveness and event
// timestamps) lives solely in the prometheus gauges declared in package
// common, which survive control-plane reloads; this package only keeps the
// uptime accounting that gauges cannot represent (cumulative up time since
// first seen) together with the per-identity gauge handles, so there is a
// single source of truth and every recorded value is also exposed to
// prometheus.
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

func RecordReload() {
	common.LastReloadTime.Set(float64(time.Now().Unix()))
}

// LastReload returns when the last control-plane reload finished, or the
// zero time if no reload has happened since process start.
func LastReload() time.Time {
	return gaugeTime(common.LastReloadTime)
}

// Availability is a point-in-time view of the uptime of a node, or of a
// group on one network type.
type Availability struct {
	Seen           bool          // false until the first record
	Alive          bool          // current state
	AliveSince     time.Time     // start of the current up-streak; zero while down
	LastFailAt     time.Time     // last recorded check failure; zero if none
	LastCheckAt    time.Time     // last connectivity check; zero if none (groups, unchecked nodes)
	LastConnFailAt time.Time     // last connection failure reported by the data plane; zero if none
	UpRatio        float64       // up time / total time since first seen
	UpDuration     time.Duration // length of the current up-streak

	// Check counters are node-only (groups run no checks) and count
	// per-network-type checks; each check appends one latency sample, so
	// ChecksSinceAlive also tells how many fresh samples the avg10 window
	// and the moving average have absorbed.
	ChecksTotal      int64 // total connectivity checks
	ChecksFailed     int64 // failed checks
	ChecksSinceAlive int64 // checks since the current up-streak began, inclusive; stale while down
	ChecksSinceFail  int64 // checks since the last failure, inclusive; counts all checks if none failed
}

func gaugeValue(g prometheus.Gauge) float64 {
	if g == nil {
		return 0
	}
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		return 0
	}
	return m.GetGauge().GetValue()
}

func gaugeBool(g prometheus.Gauge) bool {
	return gaugeValue(g) != 0
}

func gaugeTime(g prometheus.Gauge) time.Time {
	if sec := gaugeValue(g); sec > 0 {
		return time.Unix(int64(sec), 0)
	}
	return time.Time{}
}

func counterValue(c prometheus.Counter) int64 {
	if c == nil {
		return 0
	}
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		return 0
	}
	return int64(m.GetCounter().GetValue())
}

func setGaugeTime(g prometheus.Gauge, t time.Time) {
	g.Set(float64(t.Unix()))
}

// availability keeps the uptime accounting of one identity; all
// single-value state is stored in the gauge handles below.
type availability struct {
	mu           sync.Mutex
	firstSeen    time.Time // zero until the first record
	totalUp      time.Duration
	lastAcc      time.Time // last time totalUp was brought up to date
	alive        prometheus.Gauge
	aliveSince   prometheus.Gauge // set on transitions to alive; stale while down
	lastFail     prometheus.Gauge
	lastCheck    prometheus.Gauge // nil for groups
	lastConnFail prometheus.Gauge // nil for groups

	// Check counters; nil for groups.
	checksTotal        prometheus.Counter
	checksFailed       prometheus.Counter
	checksSinceAlive   prometheus.Gauge // reset at the check that starts an up-streak
	checksSinceFailure prometheus.Gauge // reset at every failed check
}

func (a *availability) setAlive(alive bool, now time.Time) {
	if alive {
		a.alive.Set(1)
		setGaugeTime(a.aliveSince, now)
	} else {
		a.alive.Set(0)
		setGaugeTime(a.lastFail, now)
	}
}

func (a *availability) record(alive, checked bool, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if checked {
		setGaugeTime(a.lastCheck, now)
	}
	if a.firstSeen.IsZero() {
		a.firstSeen, a.lastAcc = now, now
		a.setAlive(alive, now)
		if checked {
			a.recordCheck(alive, true)
		}
		return
	}
	prevAlive := gaugeBool(a.alive)
	if prevAlive {
		a.totalUp += now.Sub(a.lastAcc)
	}
	a.lastAcc = now
	if !alive {
		setGaugeTime(a.lastFail, now)
	}
	if checked {
		a.recordCheck(alive, alive != prevAlive)
	}
	if alive == prevAlive {
		return
	}
	a.setAlive(alive, now)
}

// recordCheck updates the check counters for one connectivity check.
// transition is true when this check flipped the aliveness state (or is the
// first record).
func (a *availability) recordCheck(alive, transition bool) {
	if a.checksTotal == nil {
		return
	}
	a.checksTotal.Inc()
	if alive {
		if transition {
			a.checksSinceAlive.Set(1)
		} else {
			a.checksSinceAlive.Inc()
		}
		a.checksSinceFailure.Inc()
		return
	}
	a.checksFailed.Inc()
	a.checksSinceFailure.Set(1)
}

func (a *availability) snapshot(now time.Time) Availability {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.firstSeen.IsZero() {
		return Availability{}
	}
	snap := Availability{
		Seen:           true,
		Alive:          gaugeBool(a.alive),
		LastFailAt:     gaugeTime(a.lastFail),
		LastCheckAt:    gaugeTime(a.lastCheck),
		LastConnFailAt: gaugeTime(a.lastConnFail),
		ChecksTotal:    counterValue(a.checksTotal),
		ChecksFailed:   counterValue(a.checksFailed),
	}
	if snap.ChecksTotal > 0 {
		snap.ChecksSinceAlive = int64(gaugeValue(a.checksSinceAlive))
		snap.ChecksSinceFail = int64(gaugeValue(a.checksSinceFailure))
	}
	totalUp := a.totalUp
	if snap.Alive {
		snap.AliveSince = gaugeTime(a.aliveSince)
		snap.UpDuration = now.Sub(snap.AliveSince)
		totalUp += now.Sub(a.lastAcc)
	}
	if total := now.Sub(a.firstSeen); total > 0 {
		snap.UpRatio = float64(totalUp) / float64(total)
	}
	return snap
}

// Node keys are node identities (see dialer.StatsKey) that stay stable across
// control-plane reloads.
var nodes sync.Map // key -> *availability

// nodeID is the value of the "id" label of node-level series: a short hash
// of the node identity, keeping series of same-named nodes apart.
func nodeID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:4])
}

func nodeAvailability(key, subtag, name string) *availability {
	if v, ok := nodes.Load(key); ok {
		return v.(*availability)
	}
	labels := prometheus.Labels{"id": nodeID(key), "subtag": subtag, "dialer": name}
	a := &availability{
		alive:              common.NodeAlive.With(labels),
		aliveSince:         common.NodeAliveSince.With(labels),
		lastFail:           common.NodeLastFailure.With(labels),
		lastCheck:          common.NodeLastCheck.With(labels),
		lastConnFail:       common.NodeLastConnFailure.With(labels),
		checksTotal:        common.NodeChecksTotal.With(labels),
		checksFailed:       common.NodeCheckFailures.With(labels),
		checksSinceAlive:   common.NodeChecksSinceAlive.With(labels),
		checksSinceFailure: common.NodeChecksSinceFailure.With(labels),
	}
	v, _ := nodes.LoadOrStore(key, a)
	return v.(*availability)
}

// RecordNode records the state of a node. checked should be true when the
// state comes from a connectivity check (as opposed to registration).
func RecordNode(key, subtag, name string, alive, checked bool) {
	nodeAvailability(key, subtag, name).record(alive, checked, time.Now())
}

// RecordNodeConnFail records that traffic through the node failed outside of
// scheduled connectivity checks. It is a no-op for nodes never recorded,
// which cannot carry traffic anyway.
func RecordNodeConnFail(key string) {
	v, ok := nodes.Load(key)
	if !ok {
		return
	}
	a := v.(*availability)
	a.mu.Lock()
	setGaugeTime(a.lastConnFail, time.Now())
	a.mu.Unlock()
}

func GetNode(key string) Availability {
	v, ok := nodes.Load(key)
	if !ok {
		return Availability{}
	}
	return v.(*availability).snapshot(time.Now())
}

var groups sync.Map // group name -> *[4]availability

func newGroupAvailability(name string) *[4]availability {
	var arr [4]availability
	for i := 0; i < 4; i++ {
		labels := prometheus.Labels{
			"outbound": name,
			"network":  common.IndexToNetworkType(i).String(),
		}
		arr[i].alive = common.GroupAlive.With(labels)
		arr[i].aliveSince = common.GroupAliveSince.With(labels)
		arr[i].lastFail = common.GroupLastFailure.With(labels)
	}
	return &arr
}

func RecordGroup(name string, networkIndex int, alive bool) {
	v, _ := groups.LoadOrStore(name, newGroupAvailability(name))
	v.(*[4]availability)[networkIndex].record(alive, false, time.Now())
}

func GetGroup(name string, networkIndex int) Availability {
	v, ok := groups.Load(name)
	if !ok {
		return Availability{}
	}
	return v.(*[4]availability)[networkIndex].snapshot(time.Now())
}
