//go:build !linux

package direct

import (
	"syscall"
	"time"
)

// setMaxRTO is a no-op: TCP_RTO_MAX_MS is Linux-specific.
func setMaxRTO(syscall.RawConn, time.Duration) error { return nil }
