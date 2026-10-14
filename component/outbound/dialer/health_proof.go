// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
)

// HealthProof is invalidated by a new failure or a changed transport generation.
// It is evidence for one destination capability, not a promise about the target.
type HealthProof struct {
	path        *pathRuntime
	failure     uint64
	modeFailure uint64
	readiness   uint64
	sequence    uint64
	Network     common.NetworkIndex
	CheckedAt   time.Time
	release     func()
}

func (p HealthProof) Release() {
	if p.release != nil {
		p.release()
	}
}

// SameObservation distinguishes a new successful test from unrelated status
// notifications, including notifications for another destination network.
func (p HealthProof) SameObservation(other HealthProof) bool {
	return p.path == other.path && p.sequence == other.sequence && p.Network == other.Network
}

func (d *pathRuntime) recordHealthProofsLocked(result checkResult) {
	if d.health.blocked || result.generation != d.failures.generation {
		return
	}
	for _, probe := range result.probes {
		if probe.err != nil || d.health.networks[probe.network] != networkSupported || d.health.modes[probe.network].phase != healthHealthy || result.modeGenerations[probe.network] != d.health.modes[probe.network].failures.generation {
			continue
		}
		d.health.proofSequence++
		d.health.proofs[probe.network] = HealthProof{
			path: d, failure: result.generation, modeFailure: result.modeGenerations[probe.network], readiness: result.readiness,
			sequence: d.health.proofSequence, Network: probe.network, CheckedAt: time.Now(),
		}
	}
}

func (d *Dialer) ProofValid(proof HealthProof) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.proofValidLocked(proof)
}

// VerifiedUsable keeps an admitted path available during failure confirmation,
// but a confirmed failure requires a new proof for this network before reuse.
func (d *Dialer) VerifiedUsable(network *common.NetworkType) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || !d.modeUsableLocked(network.Index(), d.sessionSnapshot()) {
		return false
	}
	proof := d.health.proofs[network.Index()]
	mode := d.health.modes[network.Index()]
	return !proof.CheckedAt.IsZero() && proof.readiness == d.health.readiness &&
		(proof.failure == d.failures.generation || mode.phase == healthConfirming && proof.failure+1 == d.failures.generation) &&
		(proof.modeFailure == mode.failures.generation || mode.phase == healthConfirming && proof.modeFailure+1 == mode.failures.generation)
}

func (d *Dialer) proofValidLocked(proof HealthProof) bool {
	return !d.closed && d.pathRuntime.proofCurrentLocked(proof)
}

func (d *pathRuntime) proofCurrentLocked(proof HealthProof) bool {
	return proof.path == d && !proof.CheckedAt.IsZero() && proof.Network.Valid() &&
		proof.failure == d.failures.generation && proof.readiness == d.health.readiness &&
		proof.modeFailure == d.health.modes[proof.Network].failures.generation &&
		d.health.modes[proof.Network].phase == healthHealthy && d.modeUsableLocked(proof.Network, d.sessionSnapshot())
}

// RetainProof keeps a completed background test's Session alive until the
// selector has consumed its result, just as Check does for a waiting caller.
func (d *Dialer) RetainProof(proof HealthProof) (HealthProof, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.proofValidLocked(proof) {
		return HealthProof{}, false
	}
	proof.release = d.holdProofLocked()
	d.updateTransportDemandLocked()
	return proof, true
}

func (d *pathRuntime) holdProofLocked() func() {
	d.proofHolds++
	return sync.OnceFunc(func() {
		d.mu.Lock()
		d.proofHolds--
		d.updateTransportDemandLocked()
		d.mu.Unlock()
	})
}
