//go:build linux && surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package nodejs

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/plugins/surge/internal/processgroup"
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
	t.Cleanup(func() { closePool(t, p) })
	p.idleTimeout, p.sampleInterval = 30*time.Millisecond, 5*time.Millisecond
	if stats := p.Stats(); stats.Started != 0 || stats.Active != 0 || stats.Idle != 0 || p.monitorDone != nil {
		t.Fatalf("preparation started application workers: %+v", stats)
	}
	first, second, active := acquire(t, p), acquire(t, p), acquire(t, p)
	retired, warm := first.worker, second.worker
	first.Close()
	second.Close()
	stats := waitPoolStats(t, p, func(s Stats) bool { return s.IdleReaped == 1 && s.MemorySampledWorkers == 2 })
	if stats.Active != 1 || stats.Idle != 1 || stats.Started != 3 || stats.Discarded != 0 || stats.RSSBytes == 0 || stats.PSSBytes == 0 || stats.PSSBytes > stats.RSSBytes {
		t.Fatalf("invalid pool/memory accounting: %+v", stats)
	}
	if retired.Cmd.ProcessState == nil {
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
	closePool(t, p)
	select {
	case <-p.monitorDone:
	default:
		t.Fatal("pool shutdown did not join maintenance")
	}
	if stats := p.Stats(); stats.Active != 0 || stats.Idle != 0 || stats.RSSBytes != 0 || stats.PSSBytes != 0 || stats.Discarded != 0 {
		t.Fatalf("shutdown retained workers or counted a failure: %+v", stats)
	}
}

func TestPoolIdleRetirementKeepsCapacity(t *testing.T) {
	p, err := NewPool(t.Context(), "", 64<<20, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePool(t, p) })
	p.idleTimeout, p.sampleInterval = time.Hour, time.Hour
	first, second, warm := acquire(t, p), acquire(t, p), acquire(t, p)
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	closeWorker := first.worker.Close
	first.worker.Close = sync.OnceValue(func() error {
		close(entered)
		<-release
		return closeWorker()
	})
	first.Close()
	second.Close()
	warm.Close()
	maintained := make(chan struct{})
	go func() {
		p.maintain(time.Now().Add(2 * time.Hour))
		close(maintained)
	}()
	waitDone(t, entered)
	if s := p.Stats(); s.Active != 0 || s.Idle != 1 || s.Started != 3 {
		t.Fatalf("retiring workers counted as active: %+v", s)
	}
	next := acquire(t, p)
	results := make(chan *VM, 2)
	errors := make(chan error, 2)
	for range 2 {
		go func() {
			vm, err := p.Acquire(t.Context())
			results <- vm
			errors <- err
		}()
	}
	waitPoolStats(t, p, func(s Stats) bool { return len(p.slots) == 3 })
	if s := p.Stats(); s.Started != 3 || s.Active != 1 {
		t.Fatalf("replacement started before retirement: %+v", s)
	}
	select {
	case vm := <-results:
		if vm != nil {
			vm.Close()
		}
		t.Fatal("Acquire did not wait for worker capacity")
	default:
	}
	unblock()
	waitDone(t, maintained)
	var acquired []*VM
	for range 2 {
		select {
		case vm := <-results:
			if err := <-errors; err != nil {
				t.Fatal(err)
			}
			acquired = append(acquired, vm)
		case <-time.After(3 * time.Second):
			t.Fatal("retirement did not wake all waiters")
		}
	}
	for _, vm := range acquired {
		vm.Close()
	}
	next.Close()
	if s := p.Stats(); s.Started != 5 || s.IdleReaped != 2 || s.Active != 0 || s.Idle != 3 {
		t.Fatalf("retirement accounting: %+v", s)
	}
}

func TestPoolFailureCounters(t *testing.T) {
	p := testPool(t, 64<<20)
	path := p.path
	p.path = filepath.Join(t.TempDir(), "absent-node")
	if _, err := p.Acquire(t.Context()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected missing runtime, got %v", err)
	}
	entries, err := os.ReadDir(p.group.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatal("failed spawn retained child group", entry.Name())
		}
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

func TestPoolCloseRetainsMemoryUntilGroupDeleted(t *testing.T) {
	p, err := NewPool(t.Context(), "", 64<<20, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "unfinished-group")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.events"), []byte("populated 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// An ordinary directory keeps deletion failing without a cgroup Manager.
	p.group = &processgroup.Group{Path: path}
	p.groupErr = errors.New("fixture group initialization failed")
	p.stats.CgroupMemoryBytes = 123
	if _, err := p.Acquire(t.Context()); !errors.Is(err, p.groupErr) {
		t.Fatalf("partially initialized group accepted work: %v", err)
	}
	err = p.Close()
	if !errors.Is(err, processgroup.ErrCleanup) || p.Close() != err {
		t.Fatalf("close did not retain its cleanup error: %v", err)
	}
	if p.group.Deleted() || p.Stats().CgroupMemoryBytes != 123 {
		t.Fatal("failed group deletion cleared current memory")
	}
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	waitPoolStats(t, p, func(s Stats) bool { return s.CgroupMemoryBytes == 0 })
	if !p.group.Deleted() {
		t.Fatal("current memory cleared before root deletion was confirmed")
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
