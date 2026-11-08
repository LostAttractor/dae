// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/daeuniverse/dae/api"
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
	err         error
}

var ErrCheckSuperseded = errors.New("connectivity check superseded")

var errSharedCheckTimeout = errors.New("shared connectivity check exhausted another caller's budget")

var errPathProven = errors.New("path proven before discovery")

// A pinned check resolver with no address for this family cannot check the
// path. Do not wake proxy sessions just to rediscover this local fact.
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

// Check makes the path alive for the network, probing only if it is not
// already: an alive path is its own proof. Known capabilities share the
// representative probe; unknown capabilities require discovery, after the
// representative probe proves a path that is not alive.
// Queueing, connection establishment and verification share the same deadline.
// A caller can stop waiting without canceling checks needed by other groups.
// On success, release keeps the transport awake until the caller has acted
// on the result.
func (d *Dialer) Check(ctx context.Context, network common.NetworkIndex, timeout time.Duration) (release func(), err error) {
	if !network.Valid() {
		return nil, errors.New("invalid check network")
	}
	ctx, cancelWait := context.WithTimeout(ctx, timeout)
	defer cancelWait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, context.Canceled
	}
	release = d.holdLocked()
	d.mu.Unlock()
	for {
		err = d.checkOnce(ctx, network)
		// A shared operation may have been created by a shorter-budget caller.
		// Retry within this caller's original deadline, never restarting its budget.
		if !errors.Is(err, errSharedCheckTimeout) && !errors.Is(err, errPathProven) {
			break
		}
	}
	if err != nil {
		release()
		return nil, err
	}
	return release, nil
}

// holdLocked keeps the transport awake while a caller acts on a check.
func (d *pathRuntime) holdLocked() func() {
	d.checkHolds++
	d.updateTransportDemandLocked()
	return sync.OnceFunc(func() {
		d.mu.Lock()
		d.checkHolds--
		d.updateTransportDemandLocked()
		d.mu.Unlock()
	})
}

func (d *Dialer) checkOnce(ctx context.Context, network common.NetworkIndex) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return context.Canceled
	}
	if d.aliveLocked(network) {
		d.mu.Unlock()
		return nil
	}
	probe := d.selectionProbeNetworkLocked(network)
	// Connecting and the representative probe belong to the path: a discovery
	// must not delay, or be blamed for, proving a path that is not alive.
	proving := false
	if canonical := d.representativeLocked(); canonical.Valid() && probe != canonical && !d.aliveLocked(canonical) {
		probe, proving = canonical, true
	}
	flight := d.queueSelectionCheckLocked(probe, deadline)
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
		return ctx.Err()
	case <-d.ctx.Done():
		return d.ctx.Err()
	case <-flight.ctx.Done():
		select {
		case <-flight.done:
		default:
			return checkError(flight.ctx.Err())
		}
	case <-flight.done:
	}
	if err := checkError(flight.err); err != nil || !proving {
		return err
	}
	// Discover only on the path the proof left alive, so retries stay bounded.
	d.mu.RLock()
	alive := d.aliveLocked(probe)
	d.mu.RUnlock()
	if !alive {
		return ErrCheckSuperseded
	}
	return errPathProven
}

// A serving mode is proven by the representative probe. Unknown and failing
// modes are probed themselves.
func (d *pathRuntime) selectionProbeNetworkLocked(network common.NetworkIndex) common.NetworkIndex {
	if d.servesLocked(network) {
		return d.representativeLocked()
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

// startSelectionChecks starts waiting requests. Connecting and the
// representative probe belong to the whole path, so until the path is alive,
// or accepting before any capability is known, one check runs at a time,
// preferring the representative one. Afterwards requests for different
// networks run concurrently; a network's checks run one after another. The
// worker dispatches and completes each of them.
func (c *connectivityChecker) startSelectionChecks() bool {
	c.d.mu.Lock()
	canonical := c.d.representativeLocked()
	ready := c.d.session == nil || c.d.sessionSnapshot().Accepting
	if firstSupportedNetwork(c.d.health.networks).Valid() {
		ready = canonical.Valid() && c.d.aliveLocked(canonical)
	}
	var flights []*selectionCheck
	for network, queued := range c.d.checks.selection {
		if queued == nil || c.selections[network] != nil {
			continue
		}
		if err := queued.ctx.Err(); err != nil {
			queued.err = err
			close(queued.done)
			c.d.checks.selection[network] = nil
			continue
		}
		// A representative success after the request satisfies it.
		if c.d.aliveLocked(queued.network) && !c.d.health.measuredAt.Before(queued.requestedAt) {
			close(queued.done)
			c.d.checks.selection[network] = nil
			continue
		}
		flights = append(flights, queued)
	}
	if !ready && len(flights) != 0 {
		if c.selecting() {
			flights = nil
		} else {
			lead := slices.IndexFunc(flights, func(flight *selectionCheck) bool { return flight.network == canonical })
			flights = flights[max(lead, 0):][:1]
		}
	}
	if len(flights) == 0 {
		c.d.mu.Unlock()
		return false
	}
	generation := c.d.failures.generation
	c.d.checks.operation = checkProbing
	c.d.updateTransportDemandLocked()
	c.d.mu.Unlock()
	c.blockedBy = ""
	c.libraryRequested = false
	for _, flight := range flights {
		c.selections[flight.network] = flight
		go func() {
			c.results <- c.performSelectionCheck(flight, generation)
		}()
	}
	return true
}

func (c *connectivityChecker) selecting() bool {
	return slices.ContainsFunc(c.selections[:], func(flight *selectionCheck) bool { return flight != nil })
}

func (c *connectivityChecker) performSelectionCheck(flight *selectionCheck, generation uint64) checkResult {
	result := checkResult{kind: checkSelection, generation: generation, request: flight}
	ctx := flight.ctx
	c.d.setRecovery(api.RecoveryQueued, time.Time{}, "connectivity_slot")
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
	states, failing := c.d.health.networks, c.d.health.failing
	c.d.mu.RUnlock()
	probe := func(network common.NetworkIndex) probeResult {
		c.d.probeQueued()
		c.d.probeStarted()
		defer c.d.probeFinished()
		return c.measureProbe(ctx, network)
	}
	result.probes = []probeResult{probe(network)}
	states[network] = networkSupported
	failing.set(network, false)
	canonical := representative(states, failing)
	// Discovering another capability cannot replace a representative check of
	// a path that is not alive for this session.
	if result.probes[0].err == nil && canonical.Valid() && canonical != network {
		c.d.mu.RLock()
		alive := c.d.failures.generation == generation && c.d.health.readiness == result.readiness && c.d.aliveLocked(canonical)
		c.d.mu.RUnlock()
		if !alive {
			result.probes = append(result.probes, probe(canonical))
		}
	}
	return result
}

func (c *connectivityChecker) finishSelectionCheck(result checkResult) {
	flight := result.request
	c.selections[flight.network] = nil
	err := result.failure()
	blocked := ""
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
	now := time.Now()
	if c.d.awaitingRecoveryLocked() {
		// One recovery deadline: without a confirmed mode it starts discovery.
		c.healthAt = now.Add(c.recoveryRetryDelayLocked(now))
		c.supportAt = time.Time{}
	} else {
		c.healthAt = now.Add(c.d.recoveryCheckInterval())
	}
	if blocked != "" {
		c.blockedBy = blocked
		c.stopRetries()
	}
	// A mode the protocol rejected leaves the path serving, but not for it.
	if err == nil && (c.d.failures.generation != result.generation ||
		c.d.health.readiness != result.readiness || !c.d.healthyLocked(c.d.sessionSnapshot()) ||
		!c.d.servesLocked(flight.network)) {
		err = ErrCheckSuperseded
	}
	flight.err = err
	if c.d.checks.selection[flight.network] == flight {
		c.d.checks.selection[flight.network] = nil
	}
	close(flight.done)
	c.d.mu.Unlock()
}

func (d *pathRuntime) applySelectionCheckLocked(result checkResult, before pathView) appliedCheck {
	probe := result.probes[0]
	previous := d.health.networks[probe.network]
	d.applyCapabilityResultsLocked(result)
	if previous != networkSupported && probe.err == nil {
		d.health.pendingForce |= SelectionForceFor(probe.network)
	}
	if probe.err != nil && recoveryBlockedReason(probe.err) == "" && previous != networkSupported &&
		(errors.Is(probe.err, netproxy.UnsupportedTunnelTypeError) || d.health.phase.usable()) {
		d.statusRevision++
		after := d.viewLocked()
		d.mu.Unlock()
		d.publish(result.kind, before, after, SelectionForceNone, true)
		return appliedCheck{}
	}
	return d.applyHealthCheckLocked(result, before)
}
