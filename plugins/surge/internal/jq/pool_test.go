// SPDX-License-Identifier: AGPL-3.0-only

package jq

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/daeuniverse/dae/plugins/surge/internal/processgroup"
)

func init() {
	if slices.Equal(os.Args[1:], []string{"plugins", "surge", "__jq-worker"}) {
		if err := Run(os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
}

func testPool(tb testing.TB) *Pool {
	tb.Helper()
	pool, release, err := Acquire()
	if err != nil {
		tb.Fatalf("jq cgroup unavailable: %v", err)
	}
	if executable := os.Getenv("DAE_TEST_JQ_EXECUTABLE"); executable != "" {
		pool.executable = executable
	}
	tb.Cleanup(func() {
		if err := release(); err != nil {
			tb.Error(err)
		}
	})
	return pool
}

func workerGroups(t *testing.T, pool *Pool) int {
	t.Helper()
	entries, err := os.ReadDir(pool.group.Path)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			count++
		}
	}
	return count
}

func TestPoolIsolationAndRecovery(t *testing.T) {
	pool := testPool(t)
	budget := membuffer.NewBudget(1 << 20)
	for _, expression := range []string{".value += 1", "env", "empty"} {
		result, err := pool.Apply(t.Context(), expression, []byte(`{"value":2}`), 1024, budget)
		if err != nil {
			t.Fatal(err)
		}
		if expression == ".value += 1" && string(result.Bytes()) != `{"value":3}` {
			t.Fatal(string(result.Bytes()))
		}
		if expression == "env" && string(result.Bytes()) != `{}` {
			t.Fatal("inherited environment")
		}
		if expression == "empty" && result != nil {
			t.Fatal("empty filter replaced body")
		}
		result.Close()
	}
	if len(pool.idle) != 1 || workerGroups(t, pool) != 1 {
		t.Fatal("warm calls did not reuse one worker")
	}
	for _, expression := range []string{"def loop: loop; loop", `"x" * 1073741824`} {
		ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		result, err := pool.Apply(ctx, expression, []byte(`{}`), 1024, budget)
		cancel()
		result.Close()
		if err == nil {
			t.Fatal("unbounded expression succeeded")
		}
		if len(pool.idle) != 0 || workerGroups(t, pool) != 0 {
			t.Fatal("failed worker was not removed")
		}
		result, err = pool.Apply(t.Context(), ".", []byte(`{}`), 1024, budget)
		if err != nil {
			t.Fatal("worker did not recover", err)
		}
		result.Close()
	}
	if budget.Status().Used != 0 {
		t.Fatal(budget.Status())
	}
	events, err := os.ReadFile(filepath.Join(pool.group.Path, "memory.events"))
	if err != nil {
		t.Fatal(err)
	}
	var kills uint64
	for line := range strings.SplitSeq(string(events), "\n") {
		if value, ok := strings.CutPrefix(line, "oom_kill "); ok {
			kills, _ = strconv.ParseUint(value, 10, 64)
		}
	}
	if kills == 0 {
		t.Fatalf("large allocation did not hit the real memory limit: %s", events)
	}
	if err := pool.Validate(t.Context(), `.x =`); !errors.Is(err, ErrExpression) {
		t.Fatal(err)
	}
	if err := pool.Validate(t.Context(), `include "file"; .`); !errors.Is(err, ErrExpression) {
		t.Fatal(err)
	}
}

func TestPoolConcurrentCapacityAndClose(t *testing.T) {
	pool, release, err := Acquire()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := release(); err != nil {
			t.Error(err)
		}
	})
	var jobs sync.WaitGroup
	for range 32 {
		jobs.Go(func() {
			output, err := pool.Apply(t.Context(), "def loop: loop; loop", []byte(`{}`), 1024, membuffer.NewBudget(4096))
			output.Close()
			if err == nil {
				t.Error("canceled expression succeeded")
			}
		})
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		count := workerGroups(t, pool)
		if count > MaxWorkers {
			t.Fatal(count)
		}
		if count == MaxWorkers {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("workers did not start")
		}
		time.Sleep(time.Millisecond)
	}
	path := pool.group.Path
	if err := release(); err != nil {
		t.Fatal(err)
	}
	jobs.Wait()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cgroup was not removed", err)
	}
}

func blockPoolRemoval(t *testing.T, path string) func() {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission fault requires an unprivileged delegated service")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, info.Mode().Perm()&^0222); err != nil {
		t.Fatal(err)
	}
	restore := sync.OnceFunc(func() {
		if err := os.Chmod(path, info.Mode().Perm()); err != nil {
			t.Error(err)
		}
	})
	t.Cleanup(restore)
	return restore
}

func waitForPoolCleanup(t *testing.T, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatal("background cgroup cleanup did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPoolCleanupFailureRecovery(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(fmt.Sprintf("canceled=%t", canceled), func(t *testing.T) {
			pool, release, err := Acquire()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := release(); err != nil && !errors.Is(err, processgroup.ErrCleanup) {
					t.Error(err)
				}
				waitForPoolCleanup(t, pool.group.Deleted)
			})
			if err := pool.Validate(t.Context(), "."); err != nil {
				t.Fatal(err)
			}
			healthy := pool.idle[0]
			failed, err := pool.start()
			if err != nil {
				t.Fatal(err)
			}
			pool.idle = append(pool.idle, failed)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if canceled {
				closeWorker := failed.Close
				failed.Close = sync.OnceValue(func() error {
					err := closeWorker()
					cancel()
					return err
				})
			}
			restore := blockPoolRemoval(t, pool.group.Path)
			result, err := pool.Apply(ctx, `"x" * 1073741824`, []byte(`{}`), 1024, membuffer.NewBudget(4096))
			result.Close()
			if canceled {
				if !errors.Is(err, context.Canceled) || errors.Is(err, processgroup.ErrOOMKilled) || errors.Is(err, processgroup.ErrCleanup) {
					t.Fatalf("cancellation did not take precedence: %v", err)
				}
			} else if !errors.Is(err, processgroup.ErrOOMKilled) || !errors.Is(err, io.EOF) || !errors.Is(err, processgroup.ErrCleanup) {
				t.Fatalf("lost OOM, I/O or cleanup error identity: %v", err)
			}
			if !failed.OOMKilled || !errors.Is(pool.group.CleanupError(), processgroup.ErrCleanup) {
				t.Fatal("OOM or cleanup failure was not retained by its owner")
			}
			sequence := pool.sequence.Load()
			if _, unexpectedRelease, err := Acquire(); !errors.Is(err, processgroup.ErrCleanup) {
				if unexpectedRelease != nil {
					if err := unexpectedRelease(); err != nil {
						t.Error(err)
					}
				}
				t.Fatalf("Acquire admitted a pending cleanup: %v", err)
			}
			if err := pool.Validate(t.Context(), "."); !errors.Is(err, processgroup.ErrCleanup) {
				t.Fatalf("run admitted a pending cleanup: %v", err)
			}
			if pool.ctx.Err() != nil || shared.references != 1 || shared.pool != pool {
				t.Fatal("runtime cleanup failure canceled or released the shared pool")
			}
			if pool.sequence.Load() != sequence || workerGroups(t, pool) != 2 || len(pool.idle) != 1 || pool.idle[0] != healthy {
				t.Fatal("pending cleanup started a worker or consumed the healthy idle worker")
			}
			restore()
			waitForPoolCleanup(t, func() bool { return pool.group.Check() == nil })
			recovered, releaseRecovered, err := Acquire()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := releaseRecovered(); err != nil {
					t.Error(err)
				}
			})
			if recovered != pool || shared.references != 2 {
				t.Fatal("recovery replaced the pool while an old generation still held a reference")
			}
			if err := recovered.Validate(t.Context(), "."); err != nil {
				t.Fatal(err)
			}
			if workerGroups(t, pool) != 1 || len(pool.idle) != 1 || pool.idle[0] != healthy {
				t.Fatal("recovery did not reuse the healthy worker")
			}
			if err := releaseRecovered(); err != nil {
				t.Fatal(err)
			}
			closeErr := release()
			if !errors.Is(closeErr, processgroup.ErrCleanup) || !pool.group.Deleted() {
				t.Fatalf("final release lost history or did not delete the root: %v", closeErr)
			}
			if release() != closeErr || shared.references != 0 {
				t.Fatal("repeated release changed its cached error or reference count")
			}
		})
	}
}

func TestPoolFinalCleanupFailureReplacement(t *testing.T) {
	pool, release, err := Acquire()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := release(); err != nil && !errors.Is(err, processgroup.ErrCleanup) {
			t.Error(err)
		}
		waitForPoolCleanup(t, pool.group.Deleted)
	})
	if err := pool.Validate(t.Context(), "."); err != nil {
		t.Fatal(err)
	}
	restore := blockPoolRemoval(t, pool.group.Path)
	// Permission faults must not affect pools created by parallel test packages.
	sibling, err := processgroup.NewPool("jq-isolation-test", PoolMemory)
	if err != nil {
		t.Fatalf("permission fault escaped the test pool: %v", err)
	}
	t.Cleanup(func() {
		if err := sibling.Delete(); err != nil {
			t.Error(err)
		}
	})
	closing, resume := make(chan struct{}), make(chan struct{})
	resumeClose := sync.OnceFunc(func() { close(resume) })
	t.Cleanup(resumeClose)
	closeWorker := pool.idle[0].Close
	pool.idle[0].Close = sync.OnceValue(func() error {
		close(closing)
		<-resume
		return closeWorker()
	})
	released := make(chan error, 1)
	go func() { released <- release() }()
	select {
	case <-closing:
	case <-time.After(5 * time.Second):
		t.Fatal("final release did not begin closing the idle worker")
	}
	acquired := make(chan error, 1)
	go func() {
		_, unexpectedRelease, err := Acquire()
		if unexpectedRelease != nil {
			err = errors.Join(err, unexpectedRelease())
		}
		acquired <- err
	}()
	select {
	case err := <-acquired:
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Acquire admitted a closing pool: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("final release held the shared lock while closing a worker")
	}
	resumeClose()
	closeErr := <-released
	if !errors.Is(closeErr, processgroup.ErrCleanup) || pool.group.Deleted() {
		t.Fatalf("final deletion did not retain the failed root: %v", closeErr)
	}
	if _, unexpectedRelease, err := Acquire(); !errors.Is(err, ErrUnavailable) || !errors.Is(err, processgroup.ErrCleanup) {
		if unexpectedRelease != nil {
			if err := unexpectedRelease(); err != nil {
				t.Error(err)
			}
		}
		t.Fatalf("Acquire replaced the root before deletion: %v", err)
	}
	if shared.pool != pool || shared.references != 0 {
		t.Fatal("failed final cleanup lost the shared pool or changed its references")
	}
	restore()
	waitForPoolCleanup(t, pool.group.Deleted)
	replacement := testPool(t)
	if replacement == pool || replacement.group.Path == pool.group.Path {
		t.Fatal("Acquire reused the closed pool after background deletion")
	}
	if release() != closeErr || shared.references != 1 {
		t.Fatal("old release changed its cached error or released the new pool")
	}
	if err := replacement.Validate(t.Context(), "."); err != nil {
		t.Fatal(err)
	}
}

func reportMemory(b *testing.B, pool *Pool) {
	data, err := os.ReadFile(filepath.Join(pool.group.Path, "memory.peak"))
	if err != nil {
		b.Fatal(err)
	}
	peak, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(peak, "pool-peak-B")
}

func TestPoolQueueAndBodyBudget(t *testing.T) {
	pool := testPool(t)
	for range cap(pool.queue) {
		pool.queue <- struct{}{}
	}
	_, err := pool.Apply(t.Context(), ".", []byte(`{}`), 1024, membuffer.NewBudget(1024))
	if !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	for range cap(pool.queue) {
		<-pool.queue
	}
	budget := membuffer.NewBudget(1)
	result, err := pool.Apply(t.Context(), ".", []byte(`{}`), 1024, budget)
	result.Close()
	if !errors.Is(err, membuffer.ErrBudgetExhausted) || budget.Status().Used != 0 {
		t.Fatal(err, budget.Status())
	}
	result, err = pool.Apply(t.Context(), `range(1000000)`, []byte(`{}`), 32, membuffer.NewBudget(4096))
	result.Close()
	if !errors.Is(err, membuffer.ErrTooLarge) {
		t.Fatal(err)
	}
}

func BenchmarkPool(b *testing.B) {
	for _, size := range []int{1024, 1 << 20, 8 << 20} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			pool := testPool(b)
			body := []byte(`{"data":"` + strings.Repeat("x", size) + `"}`)
			budget := membuffer.NewBudget(64 << 20)
			output, err := pool.Apply(b.Context(), ".", body, 32<<20, budget)
			if err != nil {
				b.Fatal(err)
			}
			output.Close()
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				output, err := pool.Apply(b.Context(), ".", body, 32<<20, budget)
				if err != nil {
					b.Fatal(err)
				}
				output.Close()
			}
			reportMemory(b, pool)
		})
	}
}

func BenchmarkPoolCold(b *testing.B) {
	pool := testPool(b)
	budget := membuffer.NewBudget(4096)
	for b.Loop() {
		output, err := pool.Apply(b.Context(), ".", []byte(`{}`), 1024, budget)
		if err != nil {
			b.Fatal(err)
		}
		output.Close()
		for _, w := range pool.idle {
			if err := w.Close(); err != nil {
				b.Fatal(err)
			}
		}
		pool.idle = nil
	}
	reportMemory(b, pool)
}
