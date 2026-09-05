package dialer

import (
	"errors"
	"net"
	"time"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

type RecoveryPhase string

const (
	RecoveryCleanup           RecoveryPhase = "cleanup"
	RecoveryWaitingDependency RecoveryPhase = "waiting_dependency"
	RecoveryQueued            RecoveryPhase = "queued"
	RecoveryBackoff           RecoveryPhase = "backoff"
	RecoveryConnecting        RecoveryPhase = "connecting"
	RecoveryVerifying         RecoveryPhase = "verifying"
	RecoveryReady             RecoveryPhase = "ready"
	RecoveryBlocked           RecoveryPhase = "blocked"
	RecoveryStopped           RecoveryPhase = "stopped"
)

func ownerRecovery(snapshot netproxy.StateEvent, recovery RecoverySnapshot) RecoverySnapshot {
	if recovery.Phase == RecoveryStopped || recovery.Phase == RecoveryBlocked {
		return recovery
	}
	switch RecoveryPhase(snapshot.RecoveryPhase) {
	case RecoveryCleanup, RecoveryWaitingDependency:
		recovery.Phase = RecoveryPhase(snapshot.RecoveryPhase)
		recovery.Action = "connect"
		recovery.BlockedBy = snapshot.BlockedBy
		recovery.RetryAt = time.Time{}
		recovery.RetryTimeKnown = false
	}
	return recovery
}

// RecoverySnapshot describes the actual background worker, never a queue for
// application dials. RetryAt is populated only by the owner of the timer.
type RecoverySnapshot struct {
	Executor       netproxy.RecoveryExecutor `json:"executor,omitempty"`
	Action         string                    `json:"action,omitempty"`
	Phase          RecoveryPhase             `json:"phase"`
	Verification   string                    `json:"verification"`
	Attempt        uint64                    `json:"attempt"`
	RetryAt        time.Time                 `json:"retry_at,omitzero"`
	RetryTimeKnown bool                      `json:"retry_time_known"`
	BlockedBy      string                    `json:"blocked_by,omitempty"`
}

// FailureSnapshot contains stable metadata, without serializing concrete Go
// errors or permitting diagnostic text to become metric labels.
type FailureSnapshot struct {
	EpisodeID  uint64                 `json:"episode_id"`
	Resource   netproxy.ResourceRef   `json:"resource"`
	Scope      netproxy.FailureScope  `json:"scope"`
	Layer      netproxy.FailureLayer  `json:"layer"`
	Phase      netproxy.Operation     `json:"phase"`
	Origin     netproxy.FailureOrigin `json:"origin"`
	Reason     netproxy.FailureReason `json:"reason"`
	Code       string                 `json:"code,omitempty"`
	OccurredAt time.Time              `json:"occurred_at"`
	Message    string                 `json:"message"`
}

// The publisher is a configured lifecycle controller, not a replaceable pool
// member. Keeping one watermark per publisher bounds memory across reconnects.
type resourceFailureProgress struct {
	Generation uint64
	Episode    uint64
	Consumed   bool
}

// observeResourceFailureLocked consumes a publisher's monotonically ordered
// facts. A newer aggregate Seq can revisit an older child accident, so Seq alone
// cannot deduplicate it. Resource generations are only compared within the same
// publisher; pool member identities in Cause must never become map keys.
func (d *Dialer) observeResourceFailureLocked(event netproxy.StateEvent, failed bool) bool {
	owner := event.PublisherID
	if d.resourceFailures == nil {
		d.resourceFailures = make(map[uint64]resourceFailureProgress)
	}
	progress := d.resourceFailures[owner]
	if event.Resource.Generation < progress.Generation || event.EpisodeID < progress.Episode {
		return false
	}
	if event.Resource.Generation > progress.Generation {
		progress.Generation = event.Resource.Generation
	}
	if event.EpisodeID > progress.Episode {
		progress.Episode = event.EpisodeID
		progress.Consumed = false
	}
	fresh := failed && !progress.Consumed
	if fresh || event.EpisodeID != 0 && event.Cause == nil && event.Accepting && !event.RecoveryRequired {
		// An already resolved episode must not reappear after another controller
		// becomes the aggregate's selected diagnostic source.
		progress.Consumed = true
	}
	d.resourceFailures[owner] = progress
	return fresh
}

func failureTimeout(failure netproxy.Failure) bool {
	var timeout net.Error
	return failure.Reason == netproxy.ReasonDeadline || errors.As(failure.Cause, &timeout) && timeout.Timeout()
}

func failureSnapshot(failure netproxy.Failure, episode uint64) *FailureSnapshot {
	message := ""
	if failure.Cause != nil {
		message = failure.Cause.Error()
	}
	return &FailureSnapshot{
		EpisodeID:  episode,
		Resource:   failure.Resource,
		Scope:      failure.Scope,
		Layer:      failure.Layer,
		Phase:      failure.Phase,
		Origin:     failure.Origin,
		Reason:     failure.Reason,
		Code:       failure.Code,
		OccurredAt: time.Now(),
		Message:    message,
	}
}

func primaryNodeFailure(err error) netproxy.Failure {
	var primary netproxy.Failure
	priority := -1
	for _, failure := range netproxy.Failures(err) {
		rank := 0
		switch {
		case failure.Reason == netproxy.ReasonAuth && failure.Origin != netproxy.OriginTarget:
			rank = 3
		case failure.Scope == netproxy.ScopeSharedResource:
			rank = 2
		case failure.Scope == netproxy.ScopeUnknown:
			rank = 1
		}
		if rank > priority {
			priority, primary = rank, failure
		}
	}
	return primary
}

// ReportDataPlaneError consumes every independent cause. The protocol owner
// invalidates shared resources; observing an error never closes a Session.
func (d *Dialer) ReportDataPlaneError(err error) {
	if err == nil {
		return
	}
	var confirmation *netproxy.Failure
	for _, failure := range netproxy.Failures(err) {
		if failure.Origin == netproxy.OriginLocalCleanup {
			continue
		}
		stats.DefaultStore.RecordRelayFailure(d.StatsKey(), string(failure.Scope), string(failure.Layer), string(failure.Reason))
		if failure.Origin == netproxy.OriginCaller || failure.Origin == netproxy.OriginTarget {
			continue
		}
		// Shared failures come from the Session watch; stream and operation
		// failures concern one relay. Only unknown upstream failures need a probe.
		if failure.Scope == netproxy.ScopeUnknown && !failureTimeout(failure) && confirmation == nil {
			confirmation = &failure
		}
	}
	if confirmation != nil {
		d.reportDataPlaneFailure(*confirmation)
	}
}

func (d *Dialer) setRecovery(phase RecoveryPhase, retryAt time.Time, blockedBy string) {
	d.updateRecovery(phase, retryAt, blockedBy, "")
}

func (d *Dialer) updateRecovery(phase RecoveryPhase, retryAt time.Time, blockedBy, action string) {
	d.mu.Lock()
	if d.ctx.Err() != nil {
		d.mu.Unlock()
		return
	}
	next := d.recovery
	next.Phase = phase
	next.RetryAt = retryAt
	next.RetryTimeKnown = !retryAt.IsZero()
	next.BlockedBy = blockedBy
	switch phase {
	case RecoveryQueued, RecoveryBackoff:
		next.Action = "verify"
		if d.session != nil && !d.session.Snapshot().Accepting {
			next.Action = "connect"
		}
	case RecoveryConnecting:
		next.Action = "connect"
	case RecoveryVerifying:
		next.Action = "verify"
		next.Verification = "pending"
	case RecoveryReady:
		next.Action = ""
		if d.ChecksConnectivity() {
			next.Verification = "verified"
			if d.health == healthConfirming {
				next.Phase = RecoveryQueued
				next.Action = "verify"
				next.Verification = "pending"
				next.BlockedBy = "failure_confirmation"
			}
		}
	case RecoveryStopped:
		next.Action = ""
	}
	if action != "" {
		next.Action = action
	}
	if next == d.recovery {
		d.mu.Unlock()
		return
	}
	d.recovery = next
	d.statusRevision++
	revision := d.statusRevision
	d.mu.Unlock()
	fields := log.Fields{"node": d.Name, "phase": next.Phase, "executor": next.Executor, "attempt": next.Attempt, "revision": revision}
	if next.RetryTimeKnown {
		fields["retry_at"] = retryAt
		fields["retry_in"] = max(time.Until(retryAt), 0).Round(time.Millisecond)
	}
	if blockedBy != "" {
		fields["blocked_by"] = blockedBy
	}
	if phase == RecoveryBlocked {
		log.WithFields(fields).Warn("Outbound recovery paused; check configuration")
	} else {
		log.WithFields(fields).Debug("Outbound recovery state changed")
	}
}

func (d *Dialer) startConnection(event netproxy.StateEvent, action string) {
	d.mu.Lock()
	if d.ctx.Err() != nil {
		d.mu.Unlock()
		return
	}
	d.recovery.Executor = event.RecoveryExecutor
	d.recovery.Attempt++
	d.recovery.Phase = RecoveryConnecting
	d.recovery.Action = action
	d.recovery.RetryAt = time.Time{}
	d.recovery.RetryTimeKnown = false
	d.recovery.BlockedBy = ""
	d.statusRevision++
	executor := d.recovery.Executor
	d.mu.Unlock()
	stats.DefaultStore.RecordReconnectAttempt(d.StatsKey(), string(executor))
}

func (d *Dialer) probeQueued() {
	d.mu.Lock()
	if d.ctx.Err() == nil && d.activeProbes == 0 {
		d.recovery.Phase = RecoveryQueued
		d.recovery.Action = "verify"
		d.recovery.RetryAt = time.Time{}
		d.recovery.RetryTimeKnown = false
		d.recovery.BlockedBy = "connectivity_slot"
		d.statusRevision++
	}
	d.mu.Unlock()
}

func (d *Dialer) probeStarted() {
	d.mu.Lock()
	d.activeProbes++
	if d.ctx.Err() == nil {
		d.recovery.Phase = RecoveryVerifying
		d.recovery.Action = "verify"
		d.recovery.Verification = "pending"
		d.recovery.BlockedBy = ""
		d.statusRevision++
	}
	d.mu.Unlock()
}

func (d *Dialer) probeFinished() {
	d.mu.Lock()
	d.activeProbes--
	d.mu.Unlock()
}

func recoveryBlockedReason(err error) string {
	for _, failure := range netproxy.Failures(err) {
		if failure.Origin == netproxy.OriginTarget || failure.Scope == netproxy.ScopeStream {
			continue
		}
		if failure.Reason == netproxy.ReasonAuth {
			return string(failure.Reason)
		}
	}
	return ""
}
