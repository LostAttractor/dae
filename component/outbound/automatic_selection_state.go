// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"slices"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

// observe decides synchronously on a node's report, before its checker can let
// the just-checked transport sleep. The caller holds the group lock and
// publishes the returned changes once the start gate has opened.
func (s *automaticSelection) observe(d *dialer.Dialer, forceSelection dialer.SelectionForceMask) (changed commits, ready bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return changed, false
	}
	for network := range common.NetworkIndex(common.NetworkTypeCount) {
		state := &s.networks[network]
		if forceSelection.Contains(network) {
			state.force = true
		}
		// A new measurement of the selected path can justify testing a
		// promising sleeping peer.
		if s.selected[network] == d {
			if measured := d.SelectionSnapshot(network.NetworkType()).MeasuredAt; measured.After(state.measuredAt) {
				state.measuredAt, state.reconsider = measured, true
			}
		}
	}
	changed, next := s.scheduleLocked(d)
	// Wake the worker only to arm an earlier deadline.
	if !next.IsZero() && (s.armed.IsZero() || next.Before(s.armed)) {
		s.signal()
	}
	return changed, s.ready
}

func (s *automaticSelection) close() {
	s.mu.Lock()
	s.cancel()
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *automaticSelection) connectivity() (groupConnectivity, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	aggregate := groupConnectivity{initialDone: true}
	for network := range common.NetworkIndex(common.NetworkTypeCount) {
		available := s.availableLocked(network)
		aggregate.networks[network] = available
		aggregate.stable = aggregate.stable || available
		state := &s.networks[network]
		// No election has failed since the network was last served.
		electing := !state.disabled && state.retryAt.IsZero() && !available
		pending := electing || state.job != nil
		aggregate.electing[network] = electing
		aggregate.pending = aggregate.pending || pending
		aggregate.initialDone = aggregate.initialDone && !pending
		aggregate.retain[network] = state.job != nil
	}
	return aggregate, s.started
}

func (s *automaticSelection) selectedDialer(network common.NetworkIndex) *dialer.Dialer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.selected[network]
}

func (s *automaticSelection) isSelected(d *dialer.Dialer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Contains(s.selected[:], d)
}

func (s *automaticSelection) enableTolerance() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.toleranceActive = true
}

func (s *automaticSelection) refreshDemand() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshDemandLocked()
}
