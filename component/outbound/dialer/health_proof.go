// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
)

// HealthProof is invalidated by a new failure or a changed transport generation.
// One representative probe establishes path health for all confirmed capabilities.
type HealthProof struct {
	path      *pathRuntime
	failure   uint64
	readiness uint64
	sequence  uint64
	Network   common.NetworkIndex // Requested capability; not the probe's network.
	CheckedAt time.Time
	release   func()
}

func (p HealthProof) Release() {
	if p.release != nil {
		p.release()
	}
}

// SameObservation identifies the shared path observation across capabilities.
func (p HealthProof) SameObservation(other HealthProof) bool {
	return p.path == other.path && p.sequence == other.sequence
}

func (d *pathRuntime) recordHealthProofLocked(result checkResult, probe *probeResult) {
	if d.health.phase != healthHealthy || result.generation != d.failures.generation || probe == nil || probe.err != nil {
		return
	}
	d.health.proofSequence++
	d.health.proof = HealthProof{
		path: d, failure: result.generation, readiness: result.readiness,
		sequence: d.health.proofSequence, CheckedAt: time.Now(),
	}
}

func (d *pathRuntime) healthProofLocked(network common.NetworkIndex) HealthProof {
	if !network.Valid() || d.health.networks[network] != networkSupported {
		return HealthProof{}
	}
	proof := d.health.proof
	proof.Network = network
	return proof
}

func (d *Dialer) ProofValid(proof HealthProof) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.proofValidLocked(proof)
}

// VerifiedUsable keeps an admitted path available during failure confirmation,
// but a confirmed failure requires a new shared path proof before reuse.
func (d *Dialer) VerifiedUsable(network *common.NetworkType) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || !d.healthyLocked(d.sessionSnapshot()) || d.health.networks[network.Index()] != networkSupported {
		return false
	}
	proof := d.health.proof
	return !proof.CheckedAt.IsZero() && proof.readiness == d.health.readiness &&
		(proof.failure == d.failures.generation || d.health.phase == healthConfirming && proof.failure+1 == d.failures.generation)
}

func (d *Dialer) proofValidLocked(proof HealthProof) bool {
	return !d.closed && d.health.phase == healthHealthy && proof.path == d.pathRuntime && !proof.CheckedAt.IsZero() &&
		proof.failure == d.failures.generation &&
		proof.readiness == d.health.readiness && proof.Network.Valid() &&
		d.health.networks[proof.Network] == networkSupported && d.healthyLocked(d.sessionSnapshot())
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
