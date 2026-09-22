//go:build linux && dae_splice

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package splice

import (
	"fmt"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func tcpSocketError(conn TCPConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var socketErr int
	var controlErr error
	if err := raw.Control(func(rawFD uintptr) {
		socketErr, controlErr = unix.GetsockoptInt(int(rawFD), unix.SOL_SOCKET, unix.SO_ERROR)
	}); err != nil {
		return 0, err
	}
	return socketErr, controlErr
}

func spliceSocketEligible(conn TCPConn) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	protocol := 0
	var controlErr error
	if err := raw.Control(func(rawFD uintptr) {
		protocol, controlErr = unix.GetsockoptInt(int(rawFD), unix.SOL_SOCKET, unix.SO_PROTOCOL)
	}); err != nil {
		return false
	}
	return controlErr == nil && protocol != unix.IPPROTO_MPTCP
}

func (r *Runtime) endpoint(cookie uint64) (bpf_spliceSpliceEndpoint, error) {
	var endpoint bpf_spliceSpliceEndpoint
	err := r.objects.SpliceEndpoints.Lookup(&cookie, &endpoint)
	return endpoint, err
}

func (r *Runtime) stats(cookie uint64) (bpf_spliceSpliceStats, error) {
	var stats bpf_spliceSpliceStats
	err := r.objects.SpliceStats.Lookup(&cookie, &stats)
	return stats, err
}

func (r *Runtime) updateEndpoint(cookie uint64, endpoint *bpf_spliceSpliceEndpoint) error {
	return r.objects.SpliceEndpoints.Update(&cookie, endpoint, ebpf.UpdateExist)
}

func (r *Runtime) cleanupMetadata(cookies ...uint64) {
	for _, cookie := range cookies {
		_ = r.objects.SpliceSocks.Delete(&cookie)
		_ = r.objects.SpliceEndpoints.Delete(&cookie)
		_ = r.objects.SpliceStats.Delete(&cookie)
	}
}

// registerSocket installs metadata before exposing the socket to the verdict
// program. A new endpoint starts in pass mode until its queued bytes are drained.
func (r *Runtime) registerSocket(conn TCPConn) (uint64, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cookie uint64
	var controlErr error
	if err := raw.Control(func(rawFD uintptr) {
		fd := int(rawFD)
		cookie, controlErr = unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
		if controlErr != nil {
			return
		}
		endpoint := bpf_spliceSpliceEndpoint{}
		if updateErr := r.objects.SpliceEndpoints.Update(&cookie, &endpoint, ebpf.UpdateNoExist); updateErr != nil {
			controlErr = fmt.Errorf("store splice endpoint: %w", updateErr)
			return
		}
		stats := bpf_spliceSpliceStats{}
		if updateErr := r.objects.SpliceStats.Update(&cookie, &stats, ebpf.UpdateNoExist); updateErr != nil {
			_ = r.objects.SpliceEndpoints.Delete(&cookie)
			controlErr = fmt.Errorf("store splice stats: %w", updateErr)
			return
		}
		value := uint64(fd)
		if updateErr := r.objects.SpliceSocks.Update(&cookie, &value, ebpf.UpdateNoExist); updateErr != nil {
			_ = r.objects.SpliceStats.Delete(&cookie)
			_ = r.objects.SpliceEndpoints.Delete(&cookie)
			controlErr = fmt.Errorf("register socket in splice sockhash: %w", updateErr)
		}
	}); err != nil {
		return 0, err
	}
	return cookie, controlErr
}
