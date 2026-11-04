//go:build !linux

package direct

import (
	"syscall"
	"time"
)

// setUserTimeout is a no-op: TCP_USER_TIMEOUT is Linux-specific.
func setUserTimeout(syscall.RawConn, time.Duration) error { return nil }
