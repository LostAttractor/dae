// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
)

type availabilityObservation struct {
	alive          bool
	failureStarted time.Time
}

// Candidate checks must not modify the running plane's statistics. Retain the
// latest check and any subsequent state change, rather than a startup history.
type dialerStats struct {
	key, id string // Immutable group-local identity.
	sync.Mutex
	deferred         bool
	check, state     *availabilityObservation
	connectionFailed bool
}

// DeferStats must be called before candidate connectivity checks start.
func (d *Dialer) DeferStats() {
	d.stats.Lock()
	d.stats.deferred = true
	d.stats.Unlock()
}

// PublishStats records the validated candidate state once its identity has been
// reconciled into the process store, then enables normal check accounting.
func (d *Dialer) PublishStats() {
	d.stats.Lock()
	defer d.stats.Unlock()
	if !d.stats.deferred {
		return
	}
	key := d.StatsKey()
	if check := d.stats.check; check != nil {
		stats.DefaultStore.RecordNodeCheck(key, check.alive, check.failureStarted)
	}
	if state := d.stats.state; state != nil {
		stats.DefaultStore.RecordNodeState(key, state.alive, state.failureStarted)
	}
	if d.stats.connectionFailed {
		stats.DefaultStore.RecordNodeConnFail(key)
	}
	d.stats.check, d.stats.state = nil, nil
	d.stats.connectionFailed = false
	d.stats.deferred = false
}

func (d *pathRuntime) recordAvailability(alive, checked bool, failureStarted time.Time) {
	for _, member := range d.membersSnapshot() {
		member.recordMemberAvailability(alive, checked, failureStarted)
	}
}

func (d *Dialer) recordMemberAvailability(alive, checked bool, failureStarted time.Time) {
	d.stats.Lock()
	defer d.stats.Unlock()
	if d.stats.deferred {
		observation := &availabilityObservation{alive: alive, failureStarted: failureStarted}
		if checked {
			d.stats.check = observation
			d.stats.state = nil
		} else {
			d.stats.state = observation
		}
		return
	}
	if checked {
		stats.DefaultStore.RecordNodeCheck(d.StatsKey(), alive, failureStarted)
	} else {
		stats.DefaultStore.RecordNodeState(d.StatsKey(), alive, failureStarted)
	}
}

func (d *pathRuntime) recordConnectionFailure() {
	for _, member := range d.membersSnapshot() {
		member.recordMemberConnectionFailure()
	}
}

func (d *Dialer) recordMemberConnectionFailure() {
	d.stats.Lock()
	defer d.stats.Unlock()
	if d.stats.deferred {
		d.stats.connectionFailed = true
		return
	}
	stats.DefaultStore.RecordNodeConnFail(d.StatsKey())
}

func (d *pathRuntime) recordResourceFailure() {
	for _, member := range d.membersSnapshot() {
		stats.DefaultStore.RecordResourceFailure(member.StatsKey())
	}
}

func composeStatsIdentity(parts ...string) string {
	var builder strings.Builder
	for _, part := range parts {
		builder.WriteString(strconv.Itoa(len(part)))
		builder.WriteByte(':')
		builder.WriteString(part)
	}
	return builder.String()
}

func makeStatsKey(property *Property, scope string) string {
	id := property.Link
	if id == "" {
		id = property.Protocol + "://" + property.Address
	}
	return composeStatsIdentity(property.SubscriptionTag, id, scope)
}

func (d *Dialer) StatsKey() string { return d.stats.key }

func (d *Dialer) StatsID() string { return d.stats.id }

func (d *Dialer) StatsPath(outbound string, networkType *common.NetworkType) stats.Path {
	return stats.Path{
		NodeID:   d.StatsID(),
		Outbound: outbound,
		Subtag:   d.Property.SubscriptionTag,
		Dialer:   d.Name,
		Network:  networkType.Index(),
	}
}
