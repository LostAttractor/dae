/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"sync"
	"time"
)

// LatenciesN keeps track of the most recent N latencies using a ring buffer.
// It is thread-safe.
type LatenciesN struct {
	mu    sync.Mutex
	buf   []time.Duration
	next  int // Ring buffer index of the next write.
	count int // Number of latencies currently stored.
	sum   time.Duration
}

func NewLatenciesN(n int) *LatenciesN {
	return &LatenciesN{
		buf: make([]time.Duration, n),
	}
}

// AppendLatency appends a new latency and keeps at most N entries in the
// buffer, dropping the oldest one when full. Appending a fixed duration for
// failed or timeout situation is recommended.
func (ln *LatenciesN) AppendLatency(l time.Duration) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.count == len(ln.buf) {
		ln.sum -= ln.buf[ln.next]
	} else {
		ln.count++
	}
	ln.buf[ln.next] = l
	ln.sum += l
	ln.next = (ln.next + 1) % len(ln.buf)
}

func (ln *LatenciesN) LastLatency() (time.Duration, bool) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.count == 0 {
		return 0, false
	}
	// The most recent entry is the one written just before ln.next.
	last := (ln.next - 1 + len(ln.buf)) % len(ln.buf)
	return ln.buf[last], true
}

func (ln *LatenciesN) AvgLatency() (time.Duration, bool) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.count == 0 {
		return 0, false
	}
	return ln.sum / time.Duration(ln.count), true
}
