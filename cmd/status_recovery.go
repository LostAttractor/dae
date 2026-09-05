package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

func formatRecovery(r dialer.RecoverySnapshot, now time.Time) string {
	switch r.Phase {
	case dialer.RecoveryCleanup:
		return "cleaning up previous connection"
	case dialer.RecoveryWaitingDependency:
		return "waiting for parent connection"
	case dialer.RecoveryBackoff:
		if !r.RetryTimeKnown {
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
	case dialer.RecoveryConnecting:
		if r.Action == "replenish" {
			return fmt.Sprintf("replenishing capacity #%d", r.Attempt)
		}
		if r.Executor == netproxy.RecoveryLibraryManaged {
			return "protocol reconnecting (time unknown)"
		}
		return fmt.Sprintf("connecting #%d", r.Attempt)
	case dialer.RecoveryQueued:
		if r.BlockedBy == "connectivity_slot" {
			if r.Action == "connect" {
				return "queued for connection slot"
			}
			return "queued for check slot"
		}
		return "recovery queued"
	case dialer.RecoveryVerifying:
		return "verifying connectivity"
	case dialer.RecoveryBlocked:
		if r.Action == "replenish" {
			return "capacity blocked: " + r.BlockedBy + "; existing capacity ready"
		}
		return "blocked: " + r.BlockedBy + "; check configuration"
	case dialer.RecoveryReady:
		if r.Verification == "disabled" {
			return "ready (verification disabled)"
		}
		return "ready"
	case dialer.RecoveryStopped:
		return "stopped"
	default:
		return "-"
	}
}

func formatRecoveryFailure(f *dialer.FailureSnapshot) string {
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
