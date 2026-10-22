//go:build linux && surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package nodejs

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/plugins/surge/internal/processgroup"
)

func TestPoolWarmFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nwhile :; do :; done\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	pool, err := NewPool(t.Context(), path, 64<<20, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePool(t, pool) })
	err = pool.Warm(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("warmup ignored cancellation: %v", err)
	}
	if stats := pool.Stats(); stats.Active != 0 || stats.Idle != 0 {
		t.Fatalf("canceled warmup retained a worker: %+v", stats)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho 'startup fixture failed' >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := pool.Warm(t.Context()); err == nil || !strings.Contains(err.Error(), "startup fixture failed") {
		t.Fatalf("startup diagnostics lost: %v", err)
	}
}

func TestPoolCancellationDuringCleanup(t *testing.T) {
	p := testPool(t, 64<<20)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	vm, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer vm.Close()
	w := vm.worker
	closeWorker := w.Close
	w.Close = sync.OnceValue(func() error {
		cancel()
		err := closeWorker()
		w.OOMKilled = true
		return err
	})
	if err := vm.SetInputJSON([]byte("invalid JSON")); !errors.Is(err, context.Canceled) || errors.Is(err, processgroup.ErrOOMKilled) {
		t.Fatalf("cancellation during cleanup lost: %v", err)
	}
}

func TestPoolPrewarmsWithoutRunningBootstrap(t *testing.T) {
	// Kernel cgroup limits are page-rounded; the configured budget need not be.
	p, err := NewPool(t.Context(), "", (64<<20)+1, 3, `throw Error("bootstrap must only be compiled during warmup")`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePool(t, p) })
	if stats := p.Stats(); stats.Started != 0 || stats.Idle != 0 || p.monitorDone != nil {
		t.Fatalf("preparation started a worker: %+v", stats)
	}
	if err := p.Warm(t.Context()); err != nil {
		t.Fatal(err)
	}
	if stats := p.Stats(); stats.Started != 1 || stats.Idle != 1 || stats.Active != 0 || stats.Reused != 0 {
		t.Fatalf("warmup did not retain one worker: %+v", stats)
	}
	vm, err := p.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer vm.Close()
	if stats := p.Stats(); stats.Started != 1 || stats.Reused != 1 {
		t.Fatalf("first invocation did not reuse the warm worker: %+v", stats)
	}
}

func testPool(t *testing.T, memory int64) *Pool {
	t.Helper()
	p, err := NewPool(t.Context(), "", memory, 1, "delete globalThis.__daeHost; delete globalThis.__daeInput;")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePool(t, p) })
	return p
}

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("lifecycle operation did not complete")
	}
}

func closePool(t *testing.T, p *Pool) {
	t.Helper()
	if err := p.Close(); err != nil {
		t.Errorf("close pool: %v", err)
	}
}

func acquire(t *testing.T, p *Pool) *VM {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	vm, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vm.Close)
	if err := vm.SetInputJSON([]byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := vm.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	return vm
}

func TestPoolReuseIsolationAndClose(t *testing.T) {
	p := testPool(t, 64<<20)
	vm := acquire(t, p)
	w := vm.worker
	if err := vm.Eval(`
globalThis.secret = 1; Object.prototype.leaked = true; const local = 42;
Promise.reject(new Error("detached rejection"));
`); err != nil {
		t.Fatal(err)
	}
	vm.Close()
	next := acquire(t, p)
	if next.worker != w {
		t.Fatal("healthy process was not reused")
	}
	if err := next.Eval(`
if (typeof secret !== "undefined" || ({}).leaked || typeof local !== "undefined") throw Error("state leaked");
if (typeof process !== "undefined" || typeof require !== "undefined") throw Error("Node globals exposed");
if (globalThis.constructor.constructor("return typeof process")() !== "undefined") throw Error("outer realm exposed");
`); err != nil {
		t.Fatal(err)
	}
	next.Close()
	closePool(t, p)
	closePool(t, p)
	if w.Cmd.ProcessState == nil || !w.Cmd.ProcessState.Exited() && w.Cmd.ProcessState.String() != "signal: killed" {
		t.Fatalf("child not reaped: %v", w.Cmd.ProcessState)
	}
	if _, err := p.Acquire(t.Context()); err == nil {
		t.Fatal("closed pool accepted a lease")
	}
}

func TestPoolCancellationAndCrashRecovery(t *testing.T) {
	p := testPool(t, 64<<20)
	vm := acquire(t, p)
	w := vm.worker
	if err := w.Cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := vm.Eval("42"); err == nil {
		t.Fatal("dead worker accepted execution")
	}
	vm.Close()
	next := acquire(t, p)
	if next.worker == w {
		t.Fatal("dead worker was reused")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := p.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pool wait ignored deadline: %v", err)
	}
	finished := make(chan error, 1)
	go func() {
		_, err := p.Acquire(t.Context())
		finished <- err
	}()
	closePool(t, p)
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("pool wait succeeded after closure")
		}
	case <-time.After(time.Second):
		t.Fatal("pool close left a waiter blocked")
	}
	next.Close()
}

func TestPoolVMCloseKeepsSlotUntilCleanup(t *testing.T) {
	p := testPool(t, 64<<20)
	vm := acquire(t, p)
	w := vm.worker
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	closeWorker := w.Close
	w.Close = sync.OnceValue(func() error {
		close(entered)
		<-release
		return closeWorker()
	})
	vm.failed = true
	go func() {
		vm.Close()
		close(finished)
	}()
	t.Cleanup(func() {
		unblock()
		waitDone(t, finished)
	})
	waitDone(t, entered)
	if len(p.slots) != 1 {
		t.Fatal("VM released its slot before synchronous cleanup")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := p.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("acquired a slot before cleanup: %v", err)
	}
	if s := p.Stats(); s.Active != 0 || s.Started != 1 {
		t.Fatalf("retiring VM accounting: %+v", s)
	}
	unblock()
	waitDone(t, finished)
	next := acquire(t, p)
	if next.worker == w {
		t.Fatal("failed worker reused after cleanup")
	}
}

func TestPoolCleanupFailureRecovery(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "script"
		if canceled {
			name = "cancel"
		}
		t.Run(name, func(t *testing.T) {
			p, err := NewPool(t.Context(), "", 64<<20, 2, "")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := p.Close(); err != nil && !errors.Is(err, processgroup.ErrCleanup) {
					t.Errorf("close pool: %v", err)
				}
			})
			healthy := acquire(t, p)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			vm, err := p.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(vm.Close)
			if err := vm.SetInputJSON([]byte(`{}`)); err != nil {
				t.Fatal(err)
			}
			path := p.group.Path
			if err := os.Chmod(path, 0500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Chmod(path, 0700); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Error(err)
				}
			})
			if canceled {
				cancel()
			}
			err = vm.Eval(`throw Error("cleanup fixture")`)
			if canceled {
				if !errors.Is(err, context.Canceled) || errors.Is(err, processgroup.ErrCleanup) {
					t.Fatalf("cancellation did not take priority: %v", err)
				}
			} else if !errors.Is(err, processgroup.ErrCleanup) || !strings.Contains(err.Error(), "cleanup fixture") {
				t.Fatalf("script or cleanup error lost: %v", err)
			}
			vm.Close()
			if len(p.slots) != 1 {
				t.Fatal("failed cleanup did not hand off its lease")
			}
			if err := p.group.Check(); !errors.Is(err, processgroup.ErrCleanup) {
				t.Fatalf("cleanup did not pause admission: %v", err)
			}
			started := p.Stats().Started
			if _, err := p.Acquire(t.Context()); !errors.Is(err, processgroup.ErrCleanup) {
				t.Fatalf("pending cleanup allowed a replacement: %v", err)
			}
			if err := healthy.Eval("42"); err != nil {
				t.Fatalf("healthy lease interrupted by cleanup: %v", err)
			}
			worker := healthy.worker
			healthy.Close()
			if err := p.Warm(t.Context()); !errors.Is(err, processgroup.ErrCleanup) {
				t.Fatalf("pending cleanup allowed idle reuse: %v", err)
			}
			if p.Stats().Started != started {
				t.Fatal("paused pool started another worker")
			}
			if err := os.Chmod(path, 0700); err != nil {
				t.Fatal(err)
			}
			deadline := time.NewTimer(5 * time.Second)
			defer deadline.Stop()
			ticks := time.Tick(10 * time.Millisecond)
			for p.group.Check() != nil {
				select {
				case <-ticks:
				case <-deadline.C:
					t.Fatal("cleanup did not recover without external retries")
				}
			}
			next := acquire(t, p)
			if next.worker != worker {
				t.Fatal("recovered pool lost its healthy idle worker")
			}
			next.Close()
			if err := p.Warm(t.Context()); err != nil {
				t.Fatalf("historical cleanup error blocked recovery: %v", err)
			}
			if err := p.Close(); !errors.Is(err, processgroup.ErrCleanup) {
				t.Fatalf("final close lost historical cleanup error: %v", err)
			}
			if !p.group.Deleted() {
				t.Fatal("recovered pool retained its root group")
			}
		})
	}
}

func TestPoolCloseJoinsVMCancelAndMonitor(t *testing.T) {
	p, err := NewPool(t.Context(), "", 64<<20, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePool(t, p) })
	p.idleTimeout, p.sampleInterval = 0, 5*time.Millisecond
	first, warm := acquire(t, p), acquire(t, p)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	active, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(active.Close)
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
	warm.Close()
	waitDone(t, entered)
	closed := make(chan error, 2)
	for range 2 {
		go func() { closed <- p.Close() }()
	}
	waitDone(t, p.done)
	if _, err := p.Acquire(t.Context()); err == nil {
		t.Fatal("closing pool accepted a lease")
	}
	cancel()
	vmClosed := make(chan struct{})
	go func() {
		active.Close()
		close(vmClosed)
	}()
	waitDone(t, vmClosed)
	if len(p.slots) != 0 {
		t.Fatal("canceled VM retained its slot")
	}
	select {
	case err := <-closed:
		t.Fatalf("pool close did not join monitor cleanup: %v", err)
	default:
	}
	unblock()
	for range 2 {
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent pool close did not join")
		}
	}
	waitDone(t, p.monitorDone)
	if !p.group.Deleted() {
		t.Fatal("close returned before deleting the parent group")
	}
	if s := p.Stats(); s.Active != 0 || s.Idle != 0 || s.CgroupMemoryBytes != 0 || s.CgroupSampledAt.IsZero() {
		t.Fatalf("final pool sample: %+v", s)
	}
}

func TestPoolHeapFailureRecovery(t *testing.T) {
	p := testPool(t, 16<<20)
	vm := acquire(t, p)
	w := vm.worker
	if !slices.Contains(w.Cmd.Args, "--max-old-space-size=16") {
		t.Fatalf("unexpected V8 heap arguments: %v", w.Cmd.Args)
	}
	// Ordinary arrays consume V8 heap; ArrayBuffer backing stores do not.
	err := vm.Eval(`const retained = []; for (;;) retained.push(new Array(100000).fill(42));`)
	if err == nil || vm.ctx.Err() != nil || !strings.Contains(err.Error(), "JavaScript heap out of memory") {
		t.Fatalf("V8 heap exhaustion diagnostic missing: %v", err)
	}
	if w.OOMKilled || errors.Is(err, processgroup.ErrOOMKilled) {
		t.Fatalf("kernel OOM kill masked V8 heap exhaustion: %v", err)
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("V8 diagnostic lost the underlying I/O error: %v", err)
	}
	vm.Close()
	next := acquire(t, p)
	if next.worker == w {
		t.Fatal("OOM worker was reused")
	}
	if err := next.Eval("42"); err != nil {
		t.Fatal(err)
	}
}

func TestPoolRejectedPromisesReleaseContexts(t *testing.T) {
	p := testPool(t, 16<<20)
	var previous *worker
	for range 64 {
		vm := acquire(t, p)
		if previous != nil && vm.worker != previous {
			t.Fatal("rejected promises exhausted the persistent worker's heap")
		}
		previous = vm.worker
		// These reasons exceed the entire heap when retained across calls.
		if err := vm.Eval(`Promise.reject(new Array(100000).fill(42));`); err != nil {
			t.Fatal(err)
		}
		vm.Close()
	}
}

func TestPoolIgnoresNodeEnvironment(t *testing.T) {
	t.Setenv("NODE_OPTIONS", "--not-a-valid-node-option")
	t.Setenv("NODE_PATH", t.TempDir())
	t.Setenv("TZ", "Etc/GMT-8")
	p := testPool(t, 64<<20)
	vm := acquire(t, p)
	if err := vm.Eval(`if (new Date(0).getTimezoneOffset() !== -480) throw Error("timezone lost")`); err != nil {
		t.Fatal(err)
	}
}

func TestPoolCommandSizeLimit(t *testing.T) {
	p := testPool(t, 16<<20)
	vm := acquire(t, p)
	oversized := strings.Repeat("x", (16<<20)+1)
	for _, operation := range []struct {
		name string
		run  func() error
	}{
		{"input", func() error { return vm.SetInputJSON([]byte(oversized)) }},
		{"script", func() error { return vm.Eval(oversized) }},
		{"event", func() error { return vm.Dispatch(1, oversized) }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.run(); err == nil || !strings.Contains(err.Error(), "exceeds memory limit") {
				t.Fatalf("oversized %s: %v", operation.name, err)
			}
			if err := vm.Eval("42"); err != nil {
				t.Fatalf("rejected input corrupted the worker: %v", err)
			}
		})
	}
}

func TestPoolHostErrorsAndUnicode(t *testing.T) {
	p := testPool(t, 64<<20)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	vm, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer vm.Close()
	_ = vm.SetHostFunc(func(args []string) (any, error) {
		if args[0] != "\x00中文\ufffd" {
			t.Errorf("host text = %q", args[0])
		}
		return nil, errors.New("host failure")
	})
	if err := vm.SetInputJSON([]byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := vm.Eval(`
for (const args of [[null], [true], [1], [{}], Array(6).fill("x")]) {
  let caught = false;
  try { __daeHost(...args); } catch (error) { caught = error instanceof TypeError; }
  if (!caught) throw Error("invalid host arguments accepted");
}
let caught = false;
try { __daeHost("\x00中文\ud800"); }
catch (error) { caught = error instanceof TypeError && String(error).includes("host failure"); }
if (!caught) throw Error("host error is not realm local");
`); err != nil {
		t.Fatal(err)
	}
	if err := vm.Eval(`throw new Error("test error");`); err == nil || !strings.Contains(err.Error(), "test error") {
		t.Fatalf("lost JS error: %v", err)
	}
}
