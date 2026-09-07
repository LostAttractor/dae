// SPDX-License-Identifier: AGPL-3.0-only

package api

import "time"

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

// ResourceRef identifies a resource generation within its owner.
type ResourceRef struct {
	OwnerID    uint64 `json:"owner_id"`
	ResourceID uint64 `json:"resource_id"`
	Generation uint64 `json:"generation"`
}

// RecoverySnapshot describes worker progress. Only backoff has a retry deadline.
type RecoverySnapshot struct {
	Executor     string        `json:"executor,omitempty"`
	Action       string        `json:"action,omitempty"`
	Phase        RecoveryPhase `json:"phase"`
	Verification string        `json:"verification"`
	Attempt      uint64        `json:"attempt"`
	RetryAt      time.Time     `json:"retry_at,omitzero"`
	BlockedBy    string        `json:"blocked_by,omitempty"`
}

// FailureSnapshot carries classified diagnostics without concrete Go errors.
type FailureSnapshot struct {
	EpisodeID  uint64      `json:"episode_id"`
	Resource   ResourceRef `json:"resource"`
	Scope      string      `json:"scope"`
	Layer      string      `json:"layer"`
	Phase      string      `json:"phase"`
	Origin     string      `json:"origin"`
	Reason     string      `json:"reason"`
	Code       string      `json:"code,omitempty"`
	OccurredAt time.Time   `json:"occurred_at"`
	Message    string      `json:"message"`
}
