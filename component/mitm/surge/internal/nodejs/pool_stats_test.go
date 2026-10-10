//go:build linux && surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package nodejs

import (
	"path/filepath"
	"testing"
	"time"
)

func waitPoolStats(t *testing.T, p *Pool, ready func(Stats) bool) Stats {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticks := time.Tick(time.Millisecond)
	for {
		stats := p.Stats()
		if ready(stats) {
			return stats
		}
		select {
		case <-deadline.C:
			t.Fatalf("pool did not reach expected state: %+v", stats)
		case <-ticks:
		}
	}
}

func TestPoolReapsOnlyExcessIdleWorkers(t *testing.T) {
	p, err := NewPool(t.Context(), "", 64<<20, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	p.idleTimeout, p.sampleInterval = 30*time.Millisecond, 5*time.Millisecond
	if stats := p.Stats(); stats.Started != 0 || stats.Active != 0 || stats.Idle != 0 || p.monitorDone != nil {
		t.Fatalf("probe retained application state: %+v", stats)
	}
	first, second, active := acquire(t, p), acquire(t, p), acquire(t, p)
	retired, warm := first.worker, second.worker
	first.Close()
	second.Close()
	stats := waitPoolStats(t, p, func(s Stats) bool { return s.IdleReaped == 1 && s.MemorySampledWorkers == 2 })
	if stats.Active != 1 || stats.Idle != 1 || stats.Started != 3 || stats.Discarded != 0 || stats.RSSBytes == 0 || stats.PSSBytes == 0 || stats.PSSBytes > stats.RSSBytes {
		t.Fatalf("invalid pool/memory accounting: %+v", stats)
	}
	if retired.cmd.ProcessState == nil {
		t.Fatal("idle worker was not reaped")
	}
	if err := active.Eval("42"); err != nil {
		t.Fatalf("idle expiry killed an active lease: %v", err)
	}
	next := acquire(t, p)
	if next.worker != warm {
		t.Fatal("most recently used idle worker was not retained")
	}
	next.Close()
	active.Close()
	stats = waitPoolStats(t, p, func(s Stats) bool { return s.IdleReaped == 2 && s.MemorySampledWorkers == 1 })
	if stats.Active != 0 || stats.Idle != 1 || stats.Reused != 1 {
		t.Fatalf("pool did not shrink to one reusable worker: %+v", stats)
	}
	p.Close()
	select {
	case <-p.monitorDone:
	default:
		t.Fatal("pool shutdown did not join maintenance")
	}
	if stats := p.Stats(); stats.Active != 0 || stats.Idle != 0 || stats.RSSBytes != 0 || stats.PSSBytes != 0 || stats.Discarded != 0 {
		t.Fatalf("shutdown retained workers or counted a failure: %+v", stats)
	}
}

func TestPoolFailureCounters(t *testing.T) {
	p := testPool(t, 64<<20)
	path := p.path
	p.path = filepath.Join(t.TempDir(), "absent-node")
	if _, err := p.Acquire(t.Context()); err == nil {
		t.Fatal("missing runtime unexpectedly started")
	}
	p.path = path
	vm := acquire(t, p)
	if err := vm.Eval(`throw Error("fixture failure")`); err == nil {
		t.Fatal("expected script failure")
	}
	vm.Close()
	if stats := p.Stats(); stats.Started != 1 || stats.StartFailures != 1 || stats.Discarded != 1 || stats.Idle != 0 {
		t.Fatalf("incorrect failure counters: %+v", stats)
	}
	next := acquire(t, p)
	next.Close()
	if stats := p.Stats(); stats.Started != 2 || stats.Reused != 0 || stats.Idle != 1 {
		t.Fatalf("replacement was not a fresh worker: %+v", stats)
	}
}

func TestParseMemorySample(t *testing.T) {
	sample, err := parseMemorySample("Rss: 100 kB\nPss: 60 kB\nPrivate_Dirty: 40 kB\n")
	if err != nil || sample.rss != 100*1024 || sample.pss != 60*1024 || sample.at.IsZero() {
		t.Fatalf("sample=%+v err=%v", sample, err)
	}
	for _, data := range []string{"", "Rss: 100 kB\n", "Rss: bad kB\nPss: 60 kB\n", "Rss: 100 B\nPss: 60 kB\n"} {
		if _, err := parseMemorySample(data); err == nil {
			t.Fatalf("accepted incomplete or invalid memory data %q", data)
		}
	}
}
