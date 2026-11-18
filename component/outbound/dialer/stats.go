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

// Members with the same key on one path share accounting. For a new key, keep
// the latest check and subsequent state change until the plane publishes it.
type dialerStats struct {
	key, id string // Immutable group-local identity.
	sync.Mutex
	published        bool
	deferred         bool
	check, state     *availabilityObservation
	connectionFailed bool
}

// DeferStats buffers new statistics before candidate connectivity checks start.
func (d *Dialer) DeferStats() {
	d.stats.Lock()
	if !d.stats.published {
		d.stats.deferred = true
	}
	d.stats.Unlock()
}

// PublishStats records the validated candidate state once its identity has been
// reconciled into the process store, then enables normal check accounting.
func (d *Dialer) PublishStats() {
	s := d.stats
	s.Lock()
	defer s.Unlock()
	s.published = true
	if !s.deferred {
		return
	}
	if check := s.check; check != nil {
		stats.DefaultStore.RecordNodeCheck(s.key, check.alive, check.failureStarted)
	}
	if state := s.state; state != nil {
		stats.DefaultStore.RecordNodeState(s.key, state.alive, state.failureStarted)
	}
	if s.connectionFailed {
		stats.DefaultStore.RecordNodeConnFail(s.key)
	}
	s.check, s.state = nil, nil
	s.connectionFailed = false
	s.deferred = false
}

// Count path events once per stats key, even while old and new groups coexist.
func (d *pathRuntime) activeStats() map[*dialerStats]struct{} {
	d.mu.RLock()
	defer d.mu.RUnlock()
	active := make(map[*dialerStats]struct{}, len(d.members))
	for member := range d.members {
		if member.active {
			active[member.stats] = struct{}{}
		}
	}
	return active
}

func (d *pathRuntime) recordAvailability(alive, checked bool, failureStarted time.Time) {
	for s := range d.activeStats() {
		s.recordAvailability(alive, checked, failureStarted)
	}
}

func (s *dialerStats) recordAvailability(alive, checked bool, failureStarted time.Time) {
	s.Lock()
	defer s.Unlock()
	if s.deferred {
		observation := &availabilityObservation{alive: alive, failureStarted: failureStarted}
		if checked {
			s.check = observation
			s.state = nil
		} else {
			s.state = observation
		}
		return
	}
	if checked {
		stats.DefaultStore.RecordNodeCheck(s.key, alive, failureStarted)
	} else {
		stats.DefaultStore.RecordNodeState(s.key, alive, failureStarted)
	}
}

func (d *pathRuntime) recordConnectionFailure() {
	for s := range d.activeStats() {
		s.recordConnectionFailure()
	}
}

func (s *dialerStats) recordConnectionFailure() {
	s.Lock()
	defer s.Unlock()
	if s.deferred {
		s.connectionFailed = true
		return
	}
	stats.DefaultStore.RecordNodeConnFail(s.key)
}

func (d *pathRuntime) recordResourceFailure() {
	for s := range d.activeStats() {
		stats.DefaultStore.RecordResourceFailure(s.key)
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
