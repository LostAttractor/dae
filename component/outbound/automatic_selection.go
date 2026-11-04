// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/outbound/internal/checktime"
)

// automaticSelection owns discovery and the selected paths under mu. An alive
// node is its own proof: it takes over without a new probe. Group publications
// happen after releasing mu, except decisions made by observe, which runs under
// the group lock. Lock order is group, then selection, then path.
type automaticSelection struct {
	mu              sync.Mutex
	selected        [common.NetworkTypeCount]*dialer.Dialer
	tolerance       time.Duration
	toleranceActive bool
	g               *DialerGroup
	ctx             context.Context
	cancel          context.CancelFunc
	wake            chan struct{}
	wg              sync.WaitGroup
	started         bool
	ready           bool      // The start gate opened; decisions may be made.
	armed           time.Time // The worker's next deadline; zero when none.
	networks        [common.NetworkTypeCount]selectionNetwork
}

type selectionNetwork struct {
	visited      map[*dialer.Dialer]bool
	standby      map[*dialer.Dialer]bool
	measuredAt   time.Time // Last observed measurement of the selected path.
	reconsider   bool
	disabled     bool
	job          *selectionJob
	retryAt      time.Time
	upgradeAt    time.Time
	retryDelay   time.Duration
	upgradeDelay time.Duration
	changed      chan struct{}
	force        bool // A new capability: the next decision ignores the tolerance.
}

// selectionJob probes candidates when no alive node can serve, or tests a
// sleeping better candidate. An alive node may take over while a replacement
// job runs; the job then commits only a strictly better candidate.
type selectionJob struct {
	ctx       context.Context
	cancel    context.CancelFunc
	replacing bool // Started without a usable path.
	force     bool // A forced decision or a replacement: the tolerance does not apply.
	committed bool
}

// commits marks networks whose selection changed and must be published.
type commits [common.NetworkTypeCount]bool

func newAutomaticSelection(g *DialerGroup, tolerance time.Duration) *automaticSelection {
	ctx, cancel := context.WithCancel(context.Background())
	s := &automaticSelection{g: g, tolerance: tolerance, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1)}
	for i := range s.networks {
		s.networks[i].changed = make(chan struct{})
		s.networks[i].visited = make(map[*dialer.Dialer]bool)
		s.networks[i].standby = make(map[*dialer.Dialer]bool)
	}
	return s
}

func (s *automaticSelection) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *automaticSelection) start(start <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.ctx.Err() != nil {
		return
	}
	s.started = true
	s.wg.Go(func() {
		select {
		case <-start:
		case <-s.ctx.Done():
			return
		}
		s.mu.Lock()
		s.ready = true
		s.mu.Unlock()
		timer := time.NewTimer(0)
		defer timer.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-s.wake:
			case <-timer.C:
			}
			timer.Stop()
			s.mu.Lock()
			changed, next := s.scheduleLocked(nil)
			s.armed = next
			s.mu.Unlock()
			s.g.automaticChanged(changed)
			if !next.IsZero() {
				timer.Reset(max(time.Until(next), 0))
			}
		}
	})
}

func (s *automaticSelection) failover() bool {
	return s.g.selectionPolicy.Policy == consts.DialerSelectionPolicy_Failover
}

// current is the selected path while it can still serve, including while a
// reported failure is being confirmed.
func (s *automaticSelection) current(network common.NetworkIndex) (selectorCandidate, bool) {
	return s.g.candidate(s.selected[network], network.NetworkType())
}

func betterTier(a, b selectorCandidate) bool {
	return !a.degraded && b.degraded || a.degraded == b.degraded && a.priority > b.priority
}

func (s *automaticSelection) prefer(a, b selectorCandidate, force bool) bool {
	if betterTier(a, b) {
		return true
	}
	// Failover suppresses periodic demand, not selection from real samples.
	if s.g.selectionPolicy.Policy == consts.DialerSelectionPolicy_Random ||
		a.degraded != b.degraded || a.priority != b.priority {
		return false
	}
	tolerance := time.Duration(0)
	if s.toleranceActive && !force {
		tolerance = s.tolerance
	}
	return saturatingDurationAdd(a.sortingLatency, tolerance) < b.sortingLatency
}

func (s *automaticSelection) hasUpgrade(network common.NetworkIndex, current selectorCandidate) bool {
	for _, d := range s.g.Dialers {
		if d == current.dialer {
			continue
		}
		// A monitored candidate with a confirmed capability needs no test: it
		// becomes alive by itself, as does a failed one recovering on its own.
		snapshot := d.SelectionSnapshot(network.NetworkType())
		if snapshot.Support == api.NetworkSupportUnsupported || snapshot.Recovering() ||
			snapshot.Monitoring && snapshot.Support == api.NetworkSupportConfirmed {
			continue
		}
		upper := s.g.dialerToAnnotation[d].MaxPriority()
		if current.degraded || upper > current.priority ||
			!s.failover() && upper == current.priority && (!snapshot.Usable || snapshot.Degraded ||
				s.g.dialerToAnnotation[d].PriorityAt(candidateLatency(s.g.selectionPolicy.Policy, snapshot.Latency)) < current.priority) {
			return true
		}
	}
	return false
}

// hasBetterTier reports an unmonitored candidate that could outrank the path
// in a strictly better tier. Monitored candidates report by themselves.
func (s *automaticSelection) hasBetterTier(network common.NetworkIndex, current selectorCandidate) bool {
	for _, d := range s.g.Dialers {
		if d == current.dialer || !d.CanProbe(network) {
			continue
		}
		snapshot := d.SelectionSnapshot(network.NetworkType())
		if !snapshot.Monitoring && snapshot.Support != api.NetworkSupportUnsupported &&
			betterTier(selectorCandidate{priority: s.g.dialerToAnnotation[d].MaxPriority(), degraded: snapshot.Degraded}, current) {
			return true
		}
	}
	return false
}

// lowersTier reports whether replacing the failed path with next serves the
// network in a worse tier. A confirmed failure marks the failed path degraded,
// so its tier is scored without that mark.
func (s *automaticSelection) lowersTier(failed *dialer.Dialer, network common.NetworkIndex, next selectorCandidate) bool {
	if failed == nil {
		return true
	}
	snapshot := failed.SelectionSnapshot(network.NetworkType())
	return betterTier(s.g.scoreCandidate(failed, snapshot.Latency, false), next)
}

// bestAlive returns the best alive candidate other than the excluded path.
func (s *automaticSelection) bestAlive(network common.NetworkIndex, exclude *dialer.Dialer) (best selectorCandidate, monitored, ok bool) {
	for _, d := range s.g.Dialers {
		if d == exclude {
			continue
		}
		snapshot := d.SelectionSnapshot(network.NetworkType())
		if !snapshot.Alive {
			continue
		}
		candidate := s.g.scoreCandidate(d, snapshot.Latency, snapshot.Degraded)
		if !ok || compareCandidates(candidate, best) < 0 {
			best, monitored, ok = candidate, snapshot.Monitoring, true
		}
	}
	return best, monitored, ok
}

// scheduleLocked switches to the best alive candidate when the current path
// cannot serve or is outranked, and starts a job only when testing is needed.
// cause is the node whose report triggered the pass; it has just been checked.
func (s *automaticSelection) scheduleLocked(cause *dialer.Dialer) (changed commits, next time.Time) {
	if s.ctx.Err() != nil {
		return changed, next
	}
	defer s.refreshDemandLocked()
	if !s.ready {
		return changed, next
	}
	now := time.Now()
	for index := range common.NetworkIndex(common.NetworkTypeCount) {
		state := &s.networks[index]
		current, usable := s.current(index)
		if job := state.job; job != nil {
			if usable {
				continue
			}
			// The serving path failed. A canceled job cannot commit; its slot
			// stays occupied until it exits. A replacement job that has not
			// committed keeps running, but an alive node takes over now in
			// either case.
			if !job.replacing || job.committed {
				job.cancel()
			}
		}
		if best, monitored, ok := s.bestAlive(index, current.dialer); ok && (!usable || s.prefer(best, current, state.force)) {
			failed := s.selected[index]
			s.commitLocked(index, best.dialer)
			changed[index] = true
			// Verify a node switched to on an earlier observation: a takeover
			// from a failed path, or a switch to an unmonitored node. The path
			// coalesces requests from every network it took over.
			if best.dialer != cause && (usable && !monitored || !usable && failed != nil) {
				best.dialer.RequestVerification()
			}
			// A takeover by a worse tier tests better unmonitored candidates
			// at once instead of after the upgrade interval.
			if !usable && s.lowersTier(failed, index, best) && s.hasBetterTier(index, best) {
				state.upgradeAt = now
			}
			current, usable = best, true
		}
		if state.job != nil {
			continue
		}
		// Only a job started by this decision carries a forced refresh further.
		force := state.force
		state.force = false
		var target *dialer.Dialer
		upgrade := false
		when := state.retryAt
		if usable {
			// A served network elects at once when its path fails again.
			state.disabled, state.retryAt, state.retryDelay = false, time.Time{}, 0
			when = time.Time{}
			var best selectorCandidate
			for _, d := range s.g.Dialers {
				snapshot := d.SelectionSnapshot(index.NetworkType())
				candidate := s.g.scoreCandidate(d, snapshot.Latency, snapshot.Degraded)
				if d == current.dialer || !s.prefer(candidate, current, force) {
					delete(state.standby, d)
					continue
				}
				// A new current-path measurement can justify one bounded wake-up
				// of a promising sleeping peer. Timer/status wakes cannot do so.
				if state.reconsider && !snapshot.Alive && snapshot.ObservedHealthy && snapshot.HasLatency &&
					snapshot.Support == api.NetworkSupportConfirmed {
					state.standby[d] = true
				}
				if state.standby[d] && (target == nil || compareCandidates(candidate, best) < 0) {
					target, best = d, candidate
				}
			}
			state.reconsider = false
			if target == nil {
				if !s.hasUpgrade(index, current) {
					continue
				}
				if state.upgradeAt.IsZero() {
					state.upgradeAt = now.Add(checktime.Jitter(s.g.selectionPolicy.UpgradeInterval, s.g.selectionPolicy.UpgradeIntervalMax))
				}
				when, upgrade = state.upgradeAt, true
			}
		} else {
			clear(state.standby)
			state.reconsider = false
			if disabled := !s.canDiscover(index); disabled != state.disabled {
				state.disabled = disabled
				s.changedLocked(index)
			}
			if state.disabled {
				continue
			}
		}
		if when.After(now) {
			if next.IsZero() || when.Before(next) {
				next = when
			}
			continue
		}
		ctx, cancel := context.WithTimeout(s.ctx, s.g.selectionPolicy.SelectionTimeout)
		delete(state.standby, target)
		job := &selectionJob{ctx: ctx, cancel: cancel, replacing: !usable, force: force || !usable}
		state.job = job
		s.wg.Go(func() { s.selectNetwork(index, job, target, upgrade) })
	}
	return changed, next
}

// canDiscover reports a candidate an election could test. Recovering paths
// take over when they recover, so an election cannot hasten them.
func (s *automaticSelection) canDiscover(network common.NetworkIndex) bool {
	for _, d := range s.g.Dialers {
		snapshot := d.SelectionSnapshot(network.NetworkType())
		if d.CanProbe(network) && snapshot.Support != api.NetworkSupportUnsupported && !snapshot.Recovering() {
			return true
		}
	}
	return false
}

func (s *automaticSelection) selectNetwork(network common.NetworkIndex, job *selectionJob, target *dialer.Dialer, upgrade bool) {
	ctx := job.ctx
	defer job.cancel()
	if target != nil {
		if release, err := target.Check(ctx, network, s.g.selectionPolicy.ProbeTimeout); err == nil {
			s.commit(network, job, target)
			release()
		}
	} else {
		s.elect(network, job, upgrade)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := &s.networks[network]
	// The slot stays occupied until this goroutine completes, including after
	// cancellation. A replacement cannot overlap this job's commit or cleanup.
	state.job = nil
	// The worker decides next and publishes, so no gap between this job and
	// its successor is published as unavailable.
	defer s.signal()
	if errors.Is(ctx.Err(), context.Canceled) {
		// A serving path failed during discovery. Restart selection immediately;
		// canceling that job is not evidence that all replacements failed.
		clear(state.visited)
		state.retryAt = time.Time{}
		s.changedLocked(network)
		return
	}
	now := time.Now()
	if _, usable := s.current(network); !usable {
		state.retryDelay = min(max(time.Second, saturatingDurationAdd(state.retryDelay, state.retryDelay)), s.g.selectionPolicy.UpgradeIntervalMax)
		state.retryAt = now.Add(checktime.Jitter(state.retryDelay, s.g.selectionPolicy.UpgradeIntervalMax))
	}
	if job.committed {
		clear(state.visited)
		state.upgradeDelay = s.g.selectionPolicy.UpgradeInterval
	} else {
		state.upgradeDelay = min(max(s.g.selectionPolicy.UpgradeInterval, saturatingDurationAdd(state.upgradeDelay, state.upgradeDelay)), s.g.selectionPolicy.UpgradeIntervalMax)
	}
	state.upgradeAt = now.Add(checktime.Jitter(state.upgradeDelay, s.g.selectionPolicy.UpgradeIntervalMax))
	s.changedLocked(network)
}

func (s *automaticSelection) changedLocked(network common.NetworkIndex) {
	state := &s.networks[network]
	close(state.changed)
	state.changed = make(chan struct{})
}

// commitLocked selects an alive path. The caller refreshes demand, which keeps
// the selected transport awake, and publishes the change.
func (s *automaticSelection) commitLocked(network common.NetworkIndex, d *dialer.Dialer) {
	previous := s.selected[network]
	s.selected[network] = d
	s.networks[network].measuredAt = d.SelectionSnapshot(network.NetworkType()).MeasuredAt
	if previous != d {
		s.logSelection(previous, d, network.NetworkType())
	}
	s.changedLocked(network)
}

// commit concludes a job with a node it has just checked.
func (s *automaticSelection) commit(network common.NetworkIndex, job *selectionJob, d *dialer.Dialer) bool {
	s.mu.Lock()
	candidate, alive := s.g.aliveCandidate(d, network.NetworkType())
	if s.ctx.Err() != nil || errors.Is(job.ctx.Err(), context.Canceled) || !alive {
		s.mu.Unlock()
		return false
	}
	if current, ok := s.current(network); ok && current.dialer != d && !s.prefer(candidate, current, job.force) {
		s.mu.Unlock()
		return false
	}
	s.commitLocked(network, d)
	job.committed = true
	s.refreshDemandLocked()
	s.mu.Unlock()
	var changed commits
	changed[network] = true
	s.g.automaticChanged(changed)
	return true
}

type discoveryCandidate struct {
	d          *dialer.Dialer
	upper      int
	degraded   bool
	annotation *dialer.Annotation
}

type discoveryResult struct {
	d       *dialer.Dialer
	release func()
	err     error
}

func (s *automaticSelection) discoveryCandidates(network common.NetworkIndex, upgrade bool) []discoveryCandidate {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, usable := s.current(network)
	var candidates []discoveryCandidate
	for _, d := range s.g.Dialers {
		if !d.CanProbe(network) {
			continue
		}
		snapshot := d.SelectionSnapshot(network.NetworkType())
		if snapshot.Support == api.NetworkSupportUnsupported || snapshot.Recovering() {
			continue
		}
		if upgrade && snapshot.Monitoring && snapshot.Support == api.NetworkSupportConfirmed {
			continue
		}
		annotation := s.g.dialerToAnnotation[d]
		upper := annotation.MaxPriority()
		if upgrade && usable && !current.degraded && (upper < current.priority ||
			s.failover() && upper == current.priority) {
			continue
		}
		if upgrade && usable && d == current.dialer && !current.degraded {
			continue
		}
		candidates = append(candidates, discoveryCandidate{d, upper, snapshot.Degraded, annotation})
	}
	slices.SortStableFunc(candidates, func(a, b discoveryCandidate) int {
		return compareCandidates(selectorCandidate{priority: a.upper, degraded: a.degraded}, selectorCandidate{priority: b.upper, degraded: b.degraded})
	})
	// Continue an incomplete discovery sweep across bounded rounds. Otherwise
	// repeatedly timing out in the first tiers can starve every lower fallback.
	visited := s.networks[network].visited
	if slices.ContainsFunc(candidates, func(candidate discoveryCandidate) bool { return !visited[candidate.d] }) {
		candidates = slices.DeleteFunc(candidates, func(candidate discoveryCandidate) bool { return visited[candidate.d] })
	} else {
		clear(visited)
	}
	return candidates
}

// Each tier is a bounded parallel test. Plain equal-priority candidates can
// commit on the first response. Offsets and conditional priorities wait only
// while another candidate could still overturn the result.
func (s *automaticSelection) elect(network common.NetworkIndex, job *selectionJob, upgrade bool) {
	ctx := job.ctx
	pending := s.discoveryCandidates(network, upgrade)
	var verified []discoveryResult
	// Ranking and validity can change while another probe is in flight. Keep
	// successful results in arrival order so an expired winner cannot hide a
	// still-valid runner-up, and equal candidates retain first-response order.
	bestResult := func() (best discoveryResult, bestCandidate selectorCandidate) {
		for _, result := range verified {
			candidate, alive := s.g.aliveCandidate(result.d, network.NetworkType())
			if alive && (best.d == nil || compareCandidates(candidate, bestCandidate) < 0) {
				best, bestCandidate = result, candidate
			}
		}
		return
	}
	for len(pending) > 0 && ctx.Err() == nil {
		if job.replacing {
			// A node that took over meanwhile ends the replacement once no
			// remaining tier can outrank it.
			s.mu.Lock()
			current, usable := s.current(network)
			s.mu.Unlock()
			if usable && !betterTier(selectorCandidate{priority: pending[0].upper, degraded: pending[0].degraded}, current) {
				break
			}
		}
		end := 1
		for end < len(pending) && pending[end].upper == pending[0].upper && pending[end].degraded == pending[0].degraded {
			end++
		}
		batch := pending[:end]
		pending = pending[end:]
		s.mu.Lock()
		for _, candidate := range batch {
			s.networks[network].visited[candidate.d] = true
		}
		s.mu.Unlock()
		results := make(chan discoveryResult, len(batch))
		outstanding := make(map[*dialer.Dialer]discoveryCandidate, len(batch))
		for _, candidate := range batch {
			outstanding[candidate.d] = candidate
			go func() {
				release, err := candidate.d.Check(ctx, network, s.g.selectionPolicy.ProbeTimeout)
				results <- discoveryResult{candidate.d, release, err}
			}()
		}
		for range batch {
			result := <-results
			delete(outstanding, result.d)
			if result.err == nil {
				// Keep the transport awake until this election ends.
				defer result.release()
				verified = append(verified, result)
			}
			if job.committed || ctx.Err() != nil {
				continue
			}
			best, bestCandidate := bestResult()
			if best.d == nil {
				continue
			}
			canBeat := func(candidate discoveryCandidate, running bool) bool {
				if candidate.degraded != bestCandidate.degraded {
					return !candidate.degraded
				}
				if candidate.upper != bestCandidate.priority {
					return candidate.upper > bestCandidate.priority
				}
				// Successful durations are nonnegative. Even a zero-latency
				// response cannot win when its offset already exceeds the score.
				if candidate.annotation.AddLatency >= bestCandidate.sortingLatency {
					return false
				}
				// Equal, static annotations preserve first-success semantics. An
				// unstarted peer or a differently weighted peer still needs a test.
				return !running || hasConditionalPriority(candidate.annotation) ||
					candidate.annotation.AddLatency != s.g.dialerToAnnotation[best.d].AddLatency
			}
			blocked := false
			for _, candidate := range outstanding {
				blocked = blocked || canBeat(candidate, true)
			}
			for _, candidate := range pending {
				blocked = blocked || canBeat(candidate, false)
			}
			if !blocked {
				s.commit(network, job, best.d)
			}
		}
		if job.committed {
			return
		}
		best, bestCandidate := bestResult()
		if best.d != nil && (len(pending) == 0 || betterTier(bestCandidate,
			selectorCandidate{priority: pending[0].upper, degraded: pending[0].degraded})) {
			if s.commit(network, job, best.d) {
				return
			}
		}
	}
	if best, _ := bestResult(); best.d != nil && !errors.Is(ctx.Err(), context.Canceled) {
		s.commit(network, job, best.d)
	}
}

func hasConditionalPriority(annotation *dialer.Annotation) bool {
	if len(annotation.ConditionalPriority) != 0 {
		return true
	}
	for _, term := range annotation.PriorityTerms {
		if len(term.Conditional) != 0 {
			return true
		}
	}
	return false
}

func (s *automaticSelection) refreshDemandLocked() {
	var current [common.NetworkTypeCount]selectorCandidate
	var usable [common.NetworkTypeCount]bool
	var hasPeer [common.NetworkTypeCount]bool
	for network, d := range s.selected {
		current[network], usable[network] = s.current(common.NetworkIndex(network))
		if s.failover() || !usable[network] {
			continue
		}
		for _, peer := range s.g.Dialers {
			if peer.SharesRuntime(d) {
				continue
			}
			candidate, alive := s.g.aliveCandidate(peer, common.NetworkIndex(network).NetworkType())
			if alive && candidate.degraded == current[network].degraded && candidate.priority == current[network].priority {
				hasPeer[network] = true
				break
			}
		}
	}
	for _, d := range s.g.Dialers {
		enabled := false
		d.SetSelected(slices.Contains(s.selected[:], d))
		for network, selected := range current {
			snapshot := d.SelectionSnapshot(common.NetworkIndex(network).NetworkType())
			// Any candidate may be needed again. A failed one stays monitored to
			// recover on its path's schedule, which bounds probes by its downtime.
			if snapshot.Failed {
				enabled = true
				break
			}
			candidate, ok := s.g.candidate(d, common.NetworkIndex(network).NetworkType())
			// A continuous policy may sleep lower tiers only with a usable peer
			// in the serving tier. An election that already serves finishes its
			// parallel tests before waking untested backups; already warm
			// backups stay monitored meanwhile.
			job := s.networks[network].job
			if !s.failover() && usable[network] && !hasPeer[network] && (ok || job == nil || !job.committed && !job.replacing) &&
				d.CanProbe(common.NetworkIndex(network)) && snapshot.Support != api.NetworkSupportUnsupported {
				enabled = true
				break
			}
			if !ok {
				continue
			}
			// A useful recovered candidate is monitored only for its observation
			// window. The shared checker stops once it passes or loses demand.
			recovering := candidate.degraded && (!usable[network] || selected.dialer == d || selected.degraded ||
				s.g.dialerToAnnotation[d].MaxPriority() >= selected.priority)
			if recovering || !s.failover() && (!usable[network] || selected.degraded == candidate.degraded && selected.priority == candidate.priority) {
				enabled = true
				break
			}
		}
		d.SetMonitoring(enabled)
	}
}

// available reports whether the network's selected path can serve; only
// otherwise does a request need a selection budget to wait.
func (s *automaticSelection) available(network common.NetworkIndex) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.availableLocked(network)
}

func (s *automaticSelection) availableLocked(network common.NetworkIndex) bool {
	selected := s.selected[network]
	return selected != nil && selected.Usable(network.NetworkType())
}

// wait blocks while an election may still select a node for the network. One
// request context spans job replacements and both IP families. Backoff after a
// failed election is never a request queue.
func (s *automaticSelection) wait(ctx context.Context, network common.NetworkIndex) bool {
	for {
		s.mu.Lock()
		available := s.availableLocked(network)
		if !s.started || s.ctx.Err() != nil || available {
			s.mu.Unlock()
			return available
		}
		state := &s.networks[network]
		if state.disabled || state.job == nil && state.retryAt.After(time.Now()) {
			s.mu.Unlock()
			return false
		}
		changed := state.changed
		s.signal()
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return false
		case <-s.ctx.Done():
			return false
		}
	}
}
