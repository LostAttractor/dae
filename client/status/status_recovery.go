package status

import (
	"fmt"
	"strings"
	"time"

	"github.com/daeuniverse/dae/api"
)

func formatRecovery(r api.RecoverySnapshot, now time.Time) string {
	switch r.Phase {
	case api.RecoveryCleanup:
		return "cleaning up previous connection"
	case api.RecoveryWaitingDependency:
		return "waiting for parent connection"
	case api.RecoveryBackoff:
		if r.RetryAt.IsZero() {
			return "retry time unknown"
		}
		action := fmt.Sprintf("retry #%d", r.Attempt+1)
		switch r.Action {
		case "replenish":
			action = "replenish capacity"
		case "verify":
			action = "recheck"
		}
		return fmt.Sprintf("%s in %.1fs", action, max(r.RetryAt.Sub(now).Seconds(), 0))
	case api.RecoveryConnecting:
		if r.Action == "replenish" {
			return fmt.Sprintf("replenishing capacity #%d", r.Attempt)
		}
		if r.Executor == "library_managed" {
			return "protocol reconnecting (time unknown)"
		}
		return fmt.Sprintf("connecting #%d", r.Attempt)
	case api.RecoveryQueued:
		if r.BlockedBy == "failure_confirmation" {
			return "recheck queued"
		}
		if r.BlockedBy == "connectivity_slot" {
			if r.Action == "verify" {
				return "queued for check slot"
			}
			return "queued for connection slot"
		}
		return "recovery queued"
	case api.RecoveryVerifying:
		return "verifying connectivity"
	case api.RecoveryBlocked:
		return "blocked: " + r.BlockedBy + "; check configuration"
	case api.RecoveryReady:
		if r.Verification == "disabled" {
			return "ready (verification disabled)"
		}
		return "ready"
	case api.RecoveryStopped:
		return "stopped"
	default:
		return "-"
	}
}

func formatRecoveryFailure(f *api.FailureSnapshot) string {
	if f == nil {
		return "-"
	}
	parts := []string{string(f.Layer), string(f.Scope), string(f.Reason)}
	if f.Code != "" {
		parts = append(parts, f.Code)
	}
	summary := strings.Join(parts, "/")
	if f.Message != "" {
		summary += ": " + truncateStatusCell(strings.Join(strings.Fields(f.Message), " "), 80)
	}
	return summary
}
