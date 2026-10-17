// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"slices"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func (s *automaticSelection) observe(dialer *dialer.Dialer, forceSelection dialer.SelectionForceMask) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return
	}
	newObservation := false
	for network := range common.NetworkIndex(common.NetworkTypeCount) {
		snapshot := dialer.SelectionSnapshot(network.NetworkType())
		state := &s.networks[network]
		if !snapshot.Proof.SameObservation(state.observed[dialer]) {
			state.observed[dialer] = snapshot.Proof
			if proof, ok := dialer.RetainProof(snapshot.Proof); ok {
				state.fresh[dialer].Release()
				state.fresh[dialer] = proof
				state.retryAt = time.Time{}
				newObservation = true
			}
		}
		if forceSelection.Contains(network) {
			s.networks[network].force = true
		}
	}
	if newObservation {
		for network, selected := range s.selected {
			if selected == dialer {
				s.networks[network].reconsider = true
			}
		}
	}
	s.refreshDemandLocked()
	s.signal()
}

func (s *automaticSelection) close() {
	s.mu.Lock()
	s.cancel()
	s.mu.Unlock()
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, state := range s.networks {
		releaseProofs(state.fresh)
	}
}

func (s *automaticSelection) connectivity() (groupConnectivity, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	aggregate := groupConnectivity{initialDone: true}
	for network := range common.NetworkIndex(common.NetworkTypeCount) {
		selected := s.selected[network]
		available := selected != nil && selected.VerifiedUsable(network.NetworkType())
		aggregate.networks[network] = available
		aggregate.stable = aggregate.stable || available
		state := &s.networks[network]
		pending := !state.disabled && (state.job != nil || state.retryAt.IsZero() && !available)
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
