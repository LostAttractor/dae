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
	mu           sync.Mutex
	buf          []time.Duration
	failed       []bool
	next         int // Ring buffer index of the next write.
	count        int // Number of latencies currently stored.
	failureCount int
	sum          time.Duration
}

func NewLatenciesN(n int) *LatenciesN {
	return &LatenciesN{
		buf:    make([]time.Duration, n),
		failed: make([]bool, n),
	}
}

// AppendLatency appends a successful latency sample.
func (ln *LatenciesN) AppendLatency(l time.Duration) {
	ln.AppendSample(l, false)
}

// AppendSample records a latency and whether it represents a failed check,
// keeping at most N entries and dropping the oldest one when full.
func (ln *LatenciesN) AppendSample(l time.Duration, failed bool) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.count == len(ln.buf) {
		ln.sum -= ln.buf[ln.next]
		if ln.failed[ln.next] {
			ln.failureCount--
		}
	} else {
		ln.count++
	}
	ln.buf[ln.next] = l
	ln.failed[ln.next] = failed
	if failed {
		ln.failureCount++
	}
	ln.sum += l
	ln.next = (ln.next + 1) % len(ln.buf)
}

func (ln *LatenciesN) HasFailure() bool {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	return ln.failureCount > 0
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
