/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"sync"
	"testing"
	"time"
)

func TestLatenciesN_Empty(t *testing.T) {
	ln := NewLatenciesN(10)
	if _, ok := ln.LastLatency(); ok {
		t.Errorf("LastLatency should report no latency on empty buffer")
	}
	if _, ok := ln.AvgLatency(); ok {
		t.Errorf("AvgLatency should report no latency on empty buffer")
	}
}

func TestLatenciesN_LastLatency(t *testing.T) {
	ln := NewLatenciesN(3)
	ln.AppendLatency(100 * time.Millisecond)
	if l, ok := ln.LastLatency(); !ok || l != 100*time.Millisecond {
		t.Errorf("LastLatency: got %v, %v", l, ok)
	}
	ln.AppendLatency(200 * time.Millisecond)
	if l, ok := ln.LastLatency(); !ok || l != 200*time.Millisecond {
		t.Errorf("LastLatency: got %v, %v", l, ok)
	}
}

func TestLatenciesN_AvgLatency(t *testing.T) {
	ln := NewLatenciesN(10)
	ln.AppendLatency(100 * time.Millisecond)
	ln.AppendLatency(200 * time.Millisecond)
	ln.AppendLatency(300 * time.Millisecond)
	if avg, ok := ln.AvgLatency(); !ok || avg != 200*time.Millisecond {
		t.Errorf("AvgLatency: got %v, %v", avg, ok)
	}
}

func TestLatenciesN_RingBufferWraps(t *testing.T) {
	ln := NewLatenciesN(3)
	for i := 1; i <= 5; i++ {
		ln.AppendLatency(time.Duration(i*100) * time.Millisecond)
	}
	// Only the most recent 3 latencies (300, 400, 500) are kept.
	if l, ok := ln.LastLatency(); !ok || l != 500*time.Millisecond {
		t.Errorf("LastLatency: got %v, %v", l, ok)
	}
	if avg, ok := ln.AvgLatency(); !ok || avg != 400*time.Millisecond {
		t.Errorf("AvgLatency after wrap: got %v, %v", avg, ok)
	}
	// Wrap around once more to verify sum accounting of overwritten slots.
	ln.AppendLatency(600 * time.Millisecond)
	if avg, ok := ln.AvgLatency(); !ok || avg != 500*time.Millisecond {
		t.Errorf("AvgLatency after second wrap: got %v, %v", avg, ok)
	}
	if l, ok := ln.LastLatency(); !ok || l != 600*time.Millisecond {
		t.Errorf("LastLatency after second wrap: got %v, %v", l, ok)
	}
}

func TestLatenciesN_TracksFailuresInWindow(t *testing.T) {
	ln := NewLatenciesN(3)
	ln.AppendSample(time.Second, true)
	ln.AppendLatency(100 * time.Millisecond)
	ln.AppendLatency(200 * time.Millisecond)
	if !ln.HasFailure() {
		t.Fatal("window should contain the failed sample")
	}
	ln.AppendLatency(300 * time.Millisecond)
	if ln.HasFailure() {
		t.Fatal("overwriting the failed sample should clear the failure marker")
	}
}

func TestLatenciesN_Concurrent(t *testing.T) {
	ln := NewLatenciesN(10)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				ln.AppendLatency(100 * time.Millisecond)
				ln.LastLatency()
				ln.AvgLatency()
				ln.HasFailure()
			}
		}()
	}
	wg.Wait()
	if avg, ok := ln.AvgLatency(); !ok || avg != 100*time.Millisecond {
		t.Errorf("AvgLatency: got %v, %v", avg, ok)
	}
}
