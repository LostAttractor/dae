// SPDX-License-Identifier: AGPL-3.0-only

package jq

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/membuffer"
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
		tb.Skipf("jq cgroup unavailable: %v", err)
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
	entries, err := os.ReadDir(pool.group.path)
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
	events, err := os.ReadFile(filepath.Join(pool.group.path, "memory.events"))
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
		t.Skip(err)
	}
	t.Cleanup(func() { _ = release() })
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
	path := pool.group.path
	if err := release(); err != nil {
		t.Fatal(err)
	}
	jobs.Wait()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cgroup was not removed", err)
	}
}

func reportMemory(b *testing.B, pool *Pool) {
	data, err := os.ReadFile(filepath.Join(pool.group.path, "memory.peak"))
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
			w.close()
		}
		pool.idle = nil
	}
	reportMemory(b, pool)
}
