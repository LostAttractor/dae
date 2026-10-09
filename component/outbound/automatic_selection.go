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
	"github.com/daeuniverse/outbound/pkg/fastrand"
)

// automaticSelection owns discovery demand. Its state and selection commits are
// protected by the group mutex; network operations never hold that mutex.
type automaticSelection struct {
	g        *DialerGroup
	ctx      context.Context
	cancel   context.CancelFunc
	wake     chan struct{}
	wg       sync.WaitGroup
	started  bool
	networks [common.NetworkTypeCount]selectionNetwork
}

type selectionNetwork struct {
	fresh        map[*dialer.Dialer]dialer.HealthProof
	observed     map[*dialer.Dialer]dialer.HealthProof
	visited      map[*dialer.Dialer]bool
	standby      map[*dialer.Dialer]bool
	reconsider   bool
	disabled     bool
	job          *selectionJob
	retryAt      time.Time
	upgradeAt    time.Time
	retryDelay   time.Duration
	upgradeDelay time.Duration
	changed      chan struct{}
	force        bool
}

type selectionJob struct {
	ctx       context.Context
	cancel    context.CancelFunc
	serving   bool
	committed bool
	proofs    map[*dialer.Dialer]dialer.HealthProof
}

func (s *automaticSelection) check(job *selectionJob, network common.NetworkIndex, d *dialer.Dialer) (dialer.HealthProof, error) {
	if proof := job.proofs[d]; proof.Network == network && d.ProofValid(proof) {
		return proof, nil
	}
	return d.Check(job.ctx, network, s.g.selectionPolicy.ProbeTimeout)
}

func newAutomaticSelection(g *DialerGroup) *automaticSelection {
	ctx, cancel := context.WithCancel(context.Background())
	s := &automaticSelection{g: g, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1)}
	for i := range s.networks {
		s.networks[i].changed = make(chan struct{})
		s.networks[i].fresh = make(map[*dialer.Dialer]dialer.HealthProof)
		s.networks[i].observed = make(map[*dialer.Dialer]dialer.HealthProof)
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
	s.g.mu.Lock()
	defer s.g.mu.Unlock()
	if s.started || s.g.closed.Load() {
		return
	}
	s.started = true
	s.wg.Go(func() {
		select {
		case <-start:
		case <-s.ctx.Done():
			return
		}
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
			s.g.mu.Lock()
			next := s.scheduleLocked()
			s.g.mu.Unlock()
			if !next.IsZero() {
				timer.Reset(max(time.Until(next), 0))
			}
		}
	})
}

func (s *automaticSelection) failover() bool {
	return s.g.selectionPolicy.Policy == consts.DialerSelectionPolicy_Failover
}

func (s *automaticSelection) current(network common.NetworkIndex) (selectorCandidate, bool) {
	d := s.g.selector.selected[network]
	if d == nil || !d.VerifiedUsable(network.NetworkType()) {
		return selectorCandidate{}, false
	}
	return s.g.candidate(d, network.NetworkType())
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
	if s.g.selector.toleranceActive && !force {
		tolerance = s.g.selector.tolerance
	}
	return saturatingDurationAdd(a.sortingLatency, tolerance) < b.sortingLatency
}

func (s *automaticSelection) hasUpgrade(network common.NetworkIndex, current selectorCandidate) bool {
	for _, d := range s.g.Dialers {
		if d == current.dialer {
			continue
		}
		snapshot := d.SelectionSnapshot(network.NetworkType())
		if snapshot.Support == api.NetworkSupportUnsupported || snapshot.Monitoring && snapshot.Support == api.NetworkSupportConfirmed {
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

// A continuously monitored peer can recover on its canonical network before
// another known capability is reverified. Fill that proof before sleeping the
// lower tiers; a canonical success alone cannot certify an independent backup.
func (s *automaticSelection) unverifiedPeer(network common.NetworkIndex, current selectorCandidate) *dialer.Dialer {
	var target *dialer.Dialer
	for _, d := range s.g.Dialers {
		if d.SharesRuntime(current.dialer) {
			continue
		}
		candidate, ok := s.g.candidate(d, network.NetworkType())
		if !ok || candidate.degraded != current.degraded || candidate.priority != current.priority {
			continue
		}
		if d.VerifiedUsable(network.NetworkType()) {
			return nil
		}
		if target == nil {
			target = d
		}
	}
	return target
}

func (s *automaticSelection) scheduleLocked() time.Time {
	if s.g.closed.Load() {
		return time.Time{}
	}
	now := time.Now()
	var next time.Time
	for index := range common.NetworkIndex(common.NetworkTypeCount) {
		state := &s.networks[index]
		if state.disabled {
			continue
		}
		current, usable := s.current(index)
		if state.job != nil {
			if state.job.serving && !usable {
				state.job.cancel()
			}
			continue
		}
		if !usable && !s.canDiscover(index) {
			state.disabled = true
			s.changedLocked(index)
			continue
		}
		var target *dialer.Dialer
		upgrade := false
		when := state.retryAt
		if usable {
			when = time.Time{}
			var best selectorCandidate
			for _, d := range s.g.Dialers {
				snapshot := d.SelectionSnapshot(index.NetworkType())
				candidate := s.g.scoreCandidate(d, snapshot)
				if d == current.dialer || !s.prefer(candidate, current, state.force) {
					delete(state.standby, d)
					continue
				}
				// A new current-path measurement can justify one bounded wake-up
				// of a promising sleeping peer. Timer/status wakes cannot do so.
				if state.reconsider && snapshot.Dormant && snapshot.ObservedHealthy && snapshot.HasLatency &&
					snapshot.Support == api.NetworkSupportConfirmed {
					state.standby[d] = true
				}
				if (snapshot.Usable || state.standby[d]) && (target == nil || compareCandidates(candidate, best) < 0) {
					target, best = d, candidate
				}
			}
			state.reconsider = false
			if target == nil && !s.failover() {
				target = s.unverifiedPeer(index, current)
			}
			if target == nil {
				releaseProofs(state.fresh)
				if !s.hasUpgrade(index, current) {
					continue
				}
				if state.upgradeAt.IsZero() {
					state.upgradeAt = now.Add(selectionJitter(s.g.selectionPolicy.UpgradeInterval, s.g.selectionPolicy.UpgradeIntervalMax))
				}
				when, upgrade = state.upgradeAt, true
			}
		} else {
			clear(state.standby)
			state.reconsider = false
		}
		if when.After(now) {
			if next.IsZero() || when.Before(next) {
				next = when
			}
			continue
		}
		ctx, cancel := context.WithTimeout(s.ctx, s.g.selectionPolicy.SelectionTimeout)
		delete(state.standby, target)
		for d, proof := range state.fresh {
			if d.ProofValid(proof) {
				delete(state.visited, d)
			}
		}
		job := &selectionJob{ctx: ctx, cancel: cancel, serving: usable, proofs: state.fresh}
		state.fresh = make(map[*dialer.Dialer]dialer.HealthProof)
		state.job = job
		s.wg.Go(func() { s.selectNetwork(index, job, target, upgrade) })
	}
	s.refreshDemandLocked()
	_ = s.g.updateConnectivity()
	return next
}

func (s *automaticSelection) canDiscover(network common.NetworkIndex) bool {
	for _, d := range s.g.Dialers {
		if d.CanProbe(network) && d.SelectionSnapshot(network.NetworkType()).Support != api.NetworkSupportUnsupported {
			return true
		}
	}
	return false
}

func (s *automaticSelection) selectNetwork(network common.NetworkIndex, job *selectionJob, target *dialer.Dialer, upgrade bool) {
	ctx := job.ctx
	defer job.cancel()
	defer releaseProofs(job.proofs)
	if target != nil {
		proof, err := s.check(job, network, target)
		defer proof.Release()
		if err == nil {
			s.commit(network, job, target, proof)
		}
	} else {
		s.elect(network, job, upgrade)
	}
	s.g.mu.Lock()
	defer s.g.mu.Unlock()
	state := &s.networks[network]
	// The slot stays occupied until this goroutine completes, including after
	// cancellation. A replacement cannot overlap this job's commit or cleanup.
	state.job = nil
	if errors.Is(ctx.Err(), context.Canceled) {
		// A serving path failed during discovery. Restart selection immediately;
		// canceling that job is not evidence that all replacements failed.
		clear(state.visited)
		state.retryAt = time.Time{}
		s.changedLocked(network)
		s.signal()
		return
	}
	state.force = false
	now := time.Now()
	if _, usable := s.current(network); !usable {
		state.retryDelay = min(max(time.Second, saturatingDurationAdd(state.retryDelay, state.retryDelay)), s.g.selectionPolicy.UpgradeIntervalMax)
		state.retryAt = now.Add(selectionJitter(state.retryDelay, s.g.selectionPolicy.UpgradeIntervalMax))
	} else {
		state.retryDelay = 0
		state.retryAt = time.Time{}
	}
	if job.committed {
		clear(state.visited)
		state.upgradeDelay = s.g.selectionPolicy.UpgradeInterval
	} else {
		state.upgradeDelay = min(max(s.g.selectionPolicy.UpgradeInterval, saturatingDurationAdd(state.upgradeDelay, state.upgradeDelay)), s.g.selectionPolicy.UpgradeIntervalMax)
	}
	state.upgradeAt = now.Add(selectionJitter(state.upgradeDelay, s.g.selectionPolicy.UpgradeIntervalMax))
	s.changedLocked(network)
	s.refreshDemandLocked()
	_ = s.g.updateConnectivity()
	s.g.closeRecoveredConnections()
	s.signal()
}

func releaseProofs(proofs map[*dialer.Dialer]dialer.HealthProof) {
	for _, proof := range proofs {
		proof.Release()
	}
	clear(proofs)
}

func selectionJitter(interval, maximum time.Duration) time.Duration {
	spread := interval / 5
	if spread == 0 {
		return interval
	}
	low, high := interval-spread, min(saturatingDurationAdd(interval, spread), maximum)
	if high <= low {
		return min(interval, maximum)
	}
	return low + time.Duration(fastrand.Int63n(int64(high-low+1)))
}

func (s *automaticSelection) changedLocked(network common.NetworkIndex) {
	state := &s.networks[network]
	close(state.changed)
	state.changed = make(chan struct{})
}

func (s *automaticSelection) commit(network common.NetworkIndex, job *selectionJob, d *dialer.Dialer, proof dialer.HealthProof) bool {
	s.g.mu.Lock()
	defer s.g.mu.Unlock()
	state := &s.networks[network]
	if s.g.closed.Load() || errors.Is(job.ctx.Err(), context.Canceled) || proof.Network != network || !d.ProofValid(proof) {
		return false
	}
	candidate, ok := s.g.candidate(d, network.NetworkType())
	if !ok {
		return false
	}
	previous := s.g.selector.selected[network]
	if current, ok := s.current(network); ok && previous != d && !s.prefer(candidate, current, state.force) {
		return false
	}
	if previous != d {
		s.g.selector.selected[network] = d
		s.g.selector.logSelection(previous, d, network.NetworkType())
	}
	job.committed, job.serving = true, true
	s.g.updateConnectionSelection(network.NetworkType(), d)
	s.changedLocked(network)
	s.refreshDemandLocked()
	_ = s.g.updateConnectivity()
	s.g.closeRecoveredConnections()
	return true
}

type discoveryCandidate struct {
	d          *dialer.Dialer
	upper      int
	degraded   bool
	annotation *dialer.Annotation
}

type discoveryResult struct {
	d     *dialer.Dialer
	proof dialer.HealthProof
	err   error
}

func (s *automaticSelection) discoveryCandidates(network common.NetworkIndex, upgrade bool) []discoveryCandidate {
	s.g.mu.Lock()
	defer s.g.mu.Unlock()
	current, usable := s.current(network)
	var candidates []discoveryCandidate
	for _, d := range s.g.Dialers {
		if !d.CanProbe(network) {
			continue
		}
		snapshot := d.SelectionSnapshot(network.NetworkType())
		if snapshot.Support == api.NetworkSupportUnsupported {
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
			if !result.d.ProofValid(result.proof) {
				continue
			}
			candidate, ok := s.g.candidate(result.d, network.NetworkType())
			if ok && (best.d == nil || compareCandidates(candidate, bestCandidate) < 0) {
				best, bestCandidate = result, candidate
			}
		}
		return
	}
	for len(pending) > 0 && ctx.Err() == nil {
		end := 1
		for end < len(pending) && pending[end].upper == pending[0].upper && pending[end].degraded == pending[0].degraded {
			end++
		}
		batch := pending[:end]
		pending = pending[end:]
		s.g.mu.Lock()
		for _, candidate := range batch {
			s.networks[network].visited[candidate.d] = true
		}
		s.g.mu.Unlock()
		results := make(chan discoveryResult, len(batch))
		outstanding := make(map[*dialer.Dialer]discoveryCandidate, len(batch))
		for _, candidate := range batch {
			outstanding[candidate.d] = candidate
			go func() {
				proof, err := s.check(job, network, candidate.d)
				results <- discoveryResult{candidate.d, proof, err}
			}()
		}
		for range batch {
			result := <-results
			defer result.proof.Release()
			delete(outstanding, result.d)
			if result.err == nil {
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
				s.commit(network, job, best.d, best.proof)
			}
		}
		if job.committed {
			return
		}
		best, bestCandidate := bestResult()
		if best.d != nil && (len(pending) == 0 || betterTier(bestCandidate,
			selectorCandidate{priority: pending[0].upper, degraded: pending[0].degraded})) {
			if s.commit(network, job, best.d, best.proof) {
				return
			}
		}
	}
	if best, _ := bestResult(); best.d != nil && !errors.Is(ctx.Err(), context.Canceled) {
		s.commit(network, job, best.d, best.proof)
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
	for network, d := range s.g.selector.selected {
		current[network], usable[network] = s.current(common.NetworkIndex(network))
		if s.failover() || !usable[network] {
			continue
		}
		for _, peer := range s.g.Dialers {
			if peer.SharesRuntime(d) {
				continue
			}
			candidate, ok := s.g.candidate(peer, common.NetworkIndex(network).NetworkType())
			if ok && peer.VerifiedUsable(common.NetworkIndex(network).NetworkType()) &&
				candidate.degraded == current[network].degraded && candidate.priority == current[network].priority {
				hasPeer[network] = true
				break
			}
		}
	}
	for _, d := range s.g.Dialers {
		enabled := false
		d.SetSelected(slices.Contains(s.g.selector.selected[:], d))
		for network, selected := range current {
			candidate, ok := s.g.candidate(d, common.NetworkIndex(network).NetworkType())
			// A continuous policy may sleep lower tiers only with a usable peer
			// in the serving tier. Finish its initial parallel tests before waking
			// untested backups; already warm backups stay monitored meanwhile.
			job := s.networks[network].job
			if !s.failover() && usable[network] && !hasPeer[network] && (ok || job == nil || !job.committed) &&
				d.CanProbe(common.NetworkIndex(network)) && d.SelectionSnapshot(common.NetworkIndex(network).NetworkType()).Support != api.NetworkSupportUnsupported {
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

// A request's budget spans job replacements and both IP families. Allocate a
// timer only when it actually waits; backoff is never a request queue.
func (s *automaticSelection) wait(network common.NetworkIndex, deadline time.Time) bool {
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		s.g.mu.Lock()
		selected := s.g.selector.selected[network]
		available := selected != nil && selected.VerifiedUsable(network.NetworkType())
		if !s.started || s.g.closed.Load() || available {
			s.g.mu.Unlock()
			return available
		}
		state := &s.networks[network]
		if state.disabled {
			s.g.mu.Unlock()
			return false
		}
		if state.job == nil && state.retryAt.After(time.Now()) {
			s.g.mu.Unlock()
			return false
		}
		changed := state.changed
		s.signal()
		s.g.mu.Unlock()
		if timer == nil {
			timer = time.NewTimer(max(time.Until(deadline), 0))
		}
		select {
		case <-changed:
		case <-timer.C:
			return false
		case <-s.ctx.Done():
			return false
		}
	}
}
