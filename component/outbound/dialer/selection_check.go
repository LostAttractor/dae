// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

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
	d.mu.RLock()
	state := d.health.networks[network]
	network = d.selectionProbeNetworkLocked(network)
	d.mu.RUnlock()
	if state == networkUnsupported {
		return false
	}
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

// Check joins a bounded, one-shot check of this physical path. Known capabilities
// share the representative probe; unknown capabilities require discovery first.
// Queueing, connection establishment and verification share the same deadline.
// A caller can stop waiting without canceling checks needed by other groups.
func (d *Dialer) Check(ctx context.Context, network common.NetworkIndex, timeout time.Duration) (HealthProof, error) {
	if !network.Valid() {
		return HealthProof{}, errors.New("invalid check network")
	}
	ctx, cancelWait := context.WithTimeout(ctx, timeout)
	defer cancelWait()
	if err := ctx.Err(); err != nil {
		return HealthProof{}, err
	}
	d.mu.Lock()
	if d.closed {
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
	}
}

func (d *Dialer) checkOnce(ctx context.Context, network common.NetworkIndex) (HealthProof, error) {
	if err := ctx.Err(); err != nil {
		return HealthProof{}, err
	}
	deadline, _ := ctx.Deadline()
	d.mu.Lock()
	if d.closed {
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
			end, _ := flight.ctx.Deadline()
			if time.Now().Before(end) {
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
	proof := flight.proof
	proof.Network = network
	return proof, nil
}

func (d *pathRuntime) selectionProbeNetworkLocked(network common.NetworkIndex) common.NetworkIndex {
	if d.health.networks[network] == networkSupported {
		return firstSupportedNetwork(d.health.networks)
	}
	return network
}

func (d *pathRuntime) queueSelectionCheckLocked(network common.NetworkIndex, deadline time.Time) *selectionCheck {
	network = d.selectionProbeNetworkLocked(network)
	flight := d.checks.selection[network]
	if flight == nil || flight.ctx.Err() != nil {
		ctx, cancel := context.WithDeadline(d.ctx, deadline)
		flight = &selectionCheck{ctx: ctx, cancel: cancel, network: network, done: make(chan struct{}), requestedAt: time.Now()}
		d.checks.selection[network] = flight
	}
	return flight
}

// The worker's operation gate (c.cancel) serializes dispatch and completion.
func (c *connectivityChecker) startSelectionCheck() bool {
	c.d.mu.Lock()
	var flight *selectionCheck
	for i, queued := range c.d.checks.selection {
		if queued == nil {
			continue
		}
		if err := queued.ctx.Err(); err != nil {
			queued.err = err
			close(queued.done)
			c.d.checks.selection[i] = nil
			continue
		}
		proof := c.d.healthProofLocked(queued.network)
		if !proof.CheckedAt.Before(queued.requestedAt) && proof.failure == c.d.failures.generation &&
			proof.readiness == c.d.health.readiness && c.d.health.networks[queued.network] == networkSupported &&
			c.d.health.phase == healthHealthy && c.d.healthyLocked(c.d.sessionSnapshot()) {
			queued.proof = proof
			close(queued.done)
			c.d.checks.selection[i] = nil
			continue
		}
		flight = queued
		break
	}
	if flight == nil {
		c.d.mu.Unlock()
		return false
	}
	generation := c.d.failures.generation
	c.d.checks.operation = checkProbing
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
	c.d.mu.RLock()
	network := c.d.selectionProbeNetworkLocked(flight.network)
	states := c.d.health.networks
	c.d.mu.RUnlock()
	probe := func(network common.NetworkIndex) probeResult {
		c.d.probeQueued()
		c.d.probeStarted()
		defer c.d.probeFinished()
		return c.measureProbe(ctx, network)
	}
	result.probes = []probeResult{probe(network)}
	states[network] = networkSupported
	canonical := firstSupportedNetwork(states)
	// Discovering another capability cannot replace a fresh representative check.
	if result.probes[0].err == nil && canonical.Valid() && canonical != network {
		c.d.mu.RLock()
		proof := c.d.healthProofLocked(canonical)
		fresh := !proof.CheckedAt.Before(flight.requestedAt) && proof.failure == generation &&
			proof.readiness == result.readiness && c.d.health.phase == healthHealthy && c.d.healthyLocked(c.d.sessionSnapshot())
		c.d.mu.RUnlock()
		if !fresh {
			result.probes = append(result.probes, probe(canonical))
		}
	}
	return result
}

func (c *connectivityChecker) finishSelectionCheck(result checkResult) {
	flight := c.flight
	c.flight = nil
	err := result.failure()
	blocked := ""
	rediscover := false
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
		rediscover = ok && applied.rediscover
		if ok && !applied.success {
			blocked = recoveryBlockedReason(result.failure())
		}
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
	if rediscover {
		c.scheduleRediscovery()
	}
	if blocked != "" {
		c.blockedBy = blocked
		c.stopRetries()
	}
	if err == nil && (c.d.failures.generation != result.generation ||
		c.d.health.readiness != result.readiness || !c.d.healthyLocked(c.d.sessionSnapshot())) {
		err = ErrCheckSuperseded
	}
	if err == nil {
		flight.proof = c.d.healthProofLocked(flight.network)
	}
	flight.err = err
	if c.d.checks.selection[flight.network] == flight {
		c.d.checks.selection[flight.network] = nil
	}
	close(flight.done)
	c.d.mu.Unlock()
}

func (d *pathRuntime) applySelectionCheckLocked(result checkResult) appliedCheck {
	probe := result.probes[0]
	previous := d.health.networks[probe.network]
	d.applyCapabilityResultsLocked(result)
	if previous != networkSupported && probe.err == nil {
		d.health.pendingForce |= SelectionForceFor(probe.network)
	}
	if probe.err != nil && recoveryBlockedReason(probe.err) == "" && previous != networkSupported &&
		(errors.Is(probe.err, netproxy.UnsupportedTunnelTypeError) || d.health.phase.usable()) {
		d.statusRevision++
		d.mu.Unlock()
		d.notifyGroups(SelectionForceNone)
		return appliedCheck{}
	}
	if probe.err == nil {
		canonical := resultProbe(result, firstSupportedNetwork(d.health.networks))
		if canonical == nil {
			// This request discovered a capability and reused a shared proof.
			// Keep that observation's timestamp and latency unchanged.
			force := d.takePendingForceLocked()
			success := d.health.phase == healthHealthy && d.healthyLocked(d.sessionSnapshot())
			d.statusRevision++
			d.mu.Unlock()
			d.notifyGroups(force)
			return appliedCheck{success: success}
		}
		result.probes = []probeResult{*canonical}
	}
	return d.applyHealthCheckLocked(result)
}
