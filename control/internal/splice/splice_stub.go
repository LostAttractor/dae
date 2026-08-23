//go:build !linux || !dae_splice

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package splice

import (
	"net"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
)

type Runtime struct{}

type TCPConn interface {
	net.Conn
	syscall.Conn
	CloseWrite() error
}

func New(_ *ebpf.CollectionOptions, _ time.Duration) (*Runtime, error) {
	return nil, nil
}

func (r *Runtime) Relay(_, _ TCPConn) (bool, error) {
	return false, nil
}

func (r *Runtime) Close() error { return nil }
