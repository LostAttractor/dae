// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/stats"
)

type availabilityObservation struct {
	alive          bool
	failureStarted time.Time
}

// Candidate checks must not modify the running plane's statistics. Retain the
// latest check and any subsequent state change, rather than a startup history.
type dialerStats struct {
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

func (d *Dialer) recordAvailability(alive, checked bool, failureStarted time.Time) {
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

func (d *Dialer) recordConnectionFailure() {
	d.stats.Lock()
	defer d.stats.Unlock()
	if d.stats.deferred {
		d.stats.connectionFailed = true
		return
	}
	stats.DefaultStore.RecordNodeConnFail(d.StatsKey())
}
