// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/netproxy"
)

// HealthProof is invalidated by a new failure or a changed transport generation.
// It is evidence for one destination capability, not a promise about the target.
type HealthProof struct {
	path      *pathRuntime
	failure   uint64
	readiness uint64
	sequence  uint64
	Network   common.NetworkIndex
	CheckedAt time.Time
	release   func()
}

func (p HealthProof) Release() {
	if p.release != nil {
		p.release()
	}
}

func (d *pathRuntime) healthProofLocked(network common.NetworkIndex) HealthProof {
	return d.healthProofs[network]
}

// SameObservation distinguishes a new successful test from unrelated status
// notifications, including notifications for another destination network.
func (p HealthProof) SameObservation(other HealthProof) bool {
	return p.path == other.path && p.sequence == other.sequence && p.Network == other.Network
}

func (d *pathRuntime) recordHealthProofsLocked(result checkResult) {
	if d.health != healthHealthy || result.generation != d.failureGeneration {
		return
	}
	for _, probe := range result.probes {
		if probe.err != nil || d.networks[probe.network] != networkSupported {
			continue
		}
		d.proofSequence++
		d.healthProofs[probe.network] = HealthProof{
			path: d, failure: result.generation, readiness: result.readiness,
			sequence: d.proofSequence, Network: probe.network, CheckedAt: time.Now(),
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
	if d.closed || !d.healthyLocked(d.sessionSnapshot()) || d.networks[network.Index()] != networkSupported {
		return false
	}
	proof := d.healthProofLocked(network.Index())
	return !proof.CheckedAt.IsZero() && proof.readiness == d.healthSeq &&
		(proof.failure == d.failureGeneration || d.health == healthConfirming && proof.failure+1 == d.failureGeneration)
}

func (d *Dialer) proofValidLocked(proof HealthProof) bool {
	return !d.closed && d.health == healthHealthy && proof.path == d.pathRuntime && !proof.CheckedAt.IsZero() &&
		proof.failure == d.failureGeneration &&
		proof.readiness == d.healthSeq && proof.Network.Valid() &&
		d.networks[proof.Network] == networkSupported && d.healthyLocked(d.sessionSnapshot())
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

func (d *Dialer) degradationLocked() (bool, time.Duration, time.Duration) {
	required := DefaultFailureRecovery
	if d.group != nil {
		required = d.group.failureRecovery
		if d.group.recovered {
			return false, required, required
		}
	}
	return d.failedBefore, min(d.recoveryVerifiedAt.Sub(d.recoverySince), required), required
}

func (d *pathRuntime) confirmFailureLocked() {
	d.failedBefore = true
	d.resetRecoveryObservationLocked()
	for member := range d.members {
		if member.group != nil {
			member.group.recovered = false
		}
	}
	d.failureGeneration++
}

type selectionCheck struct {
	requestedAt time.Time
	ctx         context.Context
	cancel      context.CancelFunc
	network     common.NetworkIndex
	done        chan struct{}
	waiters     int
	proof       HealthProof
	err         error
}

var ErrCheckSuperseded = errors.New("connectivity proof superseded")

var errSharedCheckTimeout = errors.New("shared connectivity check exhausted another caller's budget")

// A pinned check resolver with no address for this family cannot produce a
// proof. Do not wake proxy sessions just to rediscover this local fact.
func (d *Dialer) CanProbe(network common.NetworkIndex) bool {
	raw := d.CheckDnsOptionRaw.Raw
	if len(raw) <= 1 {
		return true
	}
	want4 := network.NetworkType().IpVersion == "4"
	for _, text := range raw[1:] {
		address, err := netip.ParseAddr(text)
		if err != nil {
			return true
		}
		if address.Unmap().Is4() == want4 {
			return true
		}
	}
	return false
}

// Check joins a bounded, one-shot check of this physical path and network.
// Queueing, connection establishment and verification share the same deadline.
// A caller can stop waiting without canceling checks needed by other groups.
func (d *Dialer) Check(ctx context.Context, network common.NetworkIndex, timeout time.Duration) (HealthProof, error) {
	if !network.Valid() {
		return HealthProof{}, errors.New("invalid check network")
	}
	if err := ctx.Err(); err != nil {
		return HealthProof{}, err
	}
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	ctx, cancelWait := context.WithTimeout(ctx, timeout)
	defer cancelWait()
	d.mu.Lock()
	if d.closed || d.ctx.Err() != nil {
		d.mu.Unlock()
		return HealthProof{}, context.Canceled
	}
	release := d.holdProofLocked()
	d.updateTransportDemandLocked()
	d.mu.Unlock()
	transferred := false
	defer func() {
		if !transferred {
			release()
		}
	}()
	for {
		proof, err := d.checkOnce(ctx, network)
		// A shared operation may have been created by a shorter-budget caller.
		// Retry within this caller's original deadline, never restarting its budget.
		if !errors.Is(err, errSharedCheckTimeout) {
			if err == nil {
				proof.release = release
				transferred = true
			}
			return proof, err
		}
		if err := ctx.Err(); err != nil {
			return HealthProof{}, err
		}
	}
}

func (d *Dialer) checkOnce(ctx context.Context, network common.NetworkIndex) (HealthProof, error) {
	if err := ctx.Err(); err != nil {
		return HealthProof{}, err
	}
	deadline, _ := ctx.Deadline()
	d.mu.Lock()
	if d.closed || d.ctx.Err() != nil {
		d.mu.Unlock()
		return HealthProof{}, context.Canceled
	}
	flight := d.queueSelectionCheckLocked(network, deadline)
	flight.waiters++
	d.updateTransportDemandLocked()
	d.mu.Unlock()
	d.signalConnectivityCheck()
	checkError := func(err error) error {
		end, _ := flight.ctx.Deadline()
		if errors.Is(flight.ctx.Err(), context.DeadlineExceeded) && end.Before(deadline) {
			return errSharedCheckTimeout
		}
		return err
	}
	defer func() {
		d.mu.Lock()
		flight.waiters--
		if flight.waiters == 0 {
			// Let an elapsed probe deadline report a timeout. Turning it into
			// caller cancellation here would discard actual failure evidence.
			if end, ok := flight.ctx.Deadline(); !ok || time.Now().Before(end) {
				flight.cancel()
			}
		}
		d.mu.Unlock()
		d.signalConnectivityCheck()
	}()
	select {
	case <-ctx.Done():
		return HealthProof{}, ctx.Err()
	case <-d.ctx.Done():
		return HealthProof{}, d.ctx.Err()
	case <-flight.ctx.Done():
		select {
		case <-flight.done:
		default:
			return HealthProof{}, checkError(flight.ctx.Err())
		}
	case <-flight.done:
	}
	if flight.err != nil {
		return HealthProof{}, checkError(flight.err)
	}
	return flight.proof, nil
}

func (d *pathRuntime) queueSelectionCheckLocked(network common.NetworkIndex, deadline time.Time) *selectionCheck {
	flight := d.selectionChecks[network]
	if flight == nil || flight.ctx.Err() != nil {
		ctx, cancel := context.WithDeadline(d.ctx, deadline)
		flight = &selectionCheck{ctx: ctx, cancel: cancel, network: network, done: make(chan struct{}), requestedAt: time.Now()}
		d.selectionChecks[network] = flight
	}
	return flight
}

// The worker's operation gate (c.cancel) serializes dispatch and completion.
func (c *connectivityChecker) startSelectionCheck() bool {
	c.d.mu.Lock()
	var flight *selectionCheck
	for i, queued := range c.d.selectionChecks {
		if queued == nil {
			continue
		}
		if err := queued.ctx.Err(); err != nil {
			queued.err = err
			close(queued.done)
			c.d.selectionChecks[i] = nil
			continue
		}
		proof := c.d.healthProofLocked(queued.network)
		if !proof.CheckedAt.Before(queued.requestedAt) && proof.failure == c.d.failureGeneration &&
			proof.readiness == c.d.healthSeq && c.d.networks[queued.network] == networkSupported &&
			c.d.health == healthHealthy && c.d.healthyLocked(c.d.sessionSnapshot()) {
			queued.proof = proof
			close(queued.done)
			c.d.selectionChecks[i] = nil
			continue
		}
		flight = queued
		break
	}
	if flight == nil {
		c.d.mu.Unlock()
		return false
	}
	generation := c.d.failureGeneration
	c.d.checkRunning, c.d.checkProbing = true, true
	c.d.updateTransportDemandLocked()
	c.d.mu.Unlock()
	c.flight = flight
	c.blockedBy = ""
	c.libraryRequested = false
	c.runningKind = checkSelection
	c.cancel = flight.cancel
	go func() {
		c.results <- c.performSelectionCheck(flight, generation)
	}()
	return true
}

func (c *connectivityChecker) performSelectionCheck(flight *selectionCheck, generation uint64) checkResult {
	result := checkResult{kind: checkSelection, generation: generation}
	ctx := flight.ctx
	c.d.setRecovery(RecoveryQueued, time.Time{}, "connectivity_slot")
	if err := acquireConnectivityCheckSlot(ctx); err != nil {
		result.connectErr = err
		return result
	}
	defer releaseConnectivityCheckSlot()
	result.attempted = true
	if c.d.session != nil {
		snapshot := c.d.session.Snapshot()
		if !snapshot.Accepting {
			c.d.startConnection(snapshot, "connect")
			result.connectErr = c.d.session.Connect(ctx)
		}
		snapshot = c.d.session.Snapshot()
		result.seq, result.readiness = snapshot.Seq, snapshot.ReadinessVersion
		if result.connectErr != nil {
			return result
		}
		if !snapshot.Accepting {
			result.connectErr = netproxy.ErrNotConnected
			return result
		}
	}
	c.d.probeQueued()
	c.d.probeStarted()
	defer c.d.probeFinished()
	start := time.Now()
	ok, err := c.probe(ctx, flight.network.NetworkType())
	if !ok && err == nil {
		err = errors.New("connectivity probe produced no response")
	}
	result.probes = []probeResult{{network: flight.network, latency: time.Since(start), err: err}}
	return result
}

func (c *connectivityChecker) finishSelectionCheck(result checkResult) {
	flight := c.flight
	c.flight = nil
	err := result.failure()
	if err == nil && flight.ctx.Err() != nil {
		err = flight.ctx.Err()
		if len(result.probes) != 0 {
			result.probes[0].err = err
		} else {
			result.connectErr = err
		}
	}
	if !result.attempted || errors.Is(flight.ctx.Err(), context.Canceled) {
		if err == nil {
			err = flight.ctx.Err()
		}
	} else {
		applied, ok := c.d.applyCheck(result)
		if !ok || !applied.success {
			if err == nil {
				err = ErrCheckSuperseded
			}
		}
	}
	c.d.mu.Lock()
	if !result.attempted || errors.Is(flight.ctx.Err(), context.Canceled) {
		c.d.resetRecoveryObservationLocked()
	}
	c.healthAt = time.Now().Add(c.d.recoveryCheckInterval())
	if err == nil && (c.d.failureGeneration != result.generation ||
		c.d.healthSeq != result.readiness || !c.d.healthyLocked(c.d.sessionSnapshot())) {
		err = ErrCheckSuperseded
	}
	if err == nil {
		flight.proof = c.d.healthProofLocked(flight.network)
	}
	flight.err = err
	if c.d.selectionChecks[flight.network] == flight {
		c.d.selectionChecks[flight.network] = nil
	}
	close(flight.done)
	c.d.mu.Unlock()
}

func (d *pathRuntime) applySelectionCheckLocked(result checkResult) appliedCheck {
	probe := result.probes[0]
	previous := d.networks[probe.network]
	d.applyCapabilityResultsLocked(result)
	if previous != networkSupported && probe.err == nil {
		d.pendingForce |= SelectionForceFor(probe.network)
	}
	if probe.err != nil && (errors.Is(probe.err, netproxy.UnsupportedTunnelTypeError) ||
		previous != networkSupported && d.health.usable()) {
		d.statusRevision++
		d.mu.Unlock()
		d.notifyGroups(SelectionForceNone)
		return appliedCheck{}
	}
	return d.applyHealthCheckLocked(result)
}
