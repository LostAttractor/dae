//go:build !linux

package netproxy

import (
	"errors"
	"syscall"
)

func setUnsentLowat(syscall.RawConn, int) error { return errors.ErrUnsupported }

func sendBuffer(syscall.RawConn) int { return 0 }

func waitWritable(syscall.RawConn) (bool, error) { return false, nil }
