//go:build linux && surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package nodejs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPoolProbeCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nwhile :; do :; done\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	pool, err := NewPool(ctx, path, 64<<20, 1, "")
	if pool != nil {
		pool.Close()
		t.Fatal("accepted an unresponsive runtime")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("probe ignored cancellation: %v", err)
	}
}

func testPool(t *testing.T, memory int64) *Pool {
	t.Helper()
	p, err := NewPool(t.Context(), "", memory, 1, "delete globalThis.__daeHost; delete globalThis.__daeInput;")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
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
	p.Close()
	p.Close()
	if w.cmd.ProcessState == nil || !w.cmd.ProcessState.Exited() && w.cmd.ProcessState.String() != "signal: killed" {
		t.Fatalf("child not reaped: %v", w.cmd.ProcessState)
	}
	if _, err := p.Acquire(t.Context()); err == nil {
		t.Fatal("closed pool accepted a lease")
	}
}

func TestPoolCancellationAndCrashRecovery(t *testing.T) {
	p := testPool(t, 64<<20)
	vm := acquire(t, p)
	w := vm.worker
	if err := w.cmd.Process.Kill(); err != nil {
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
	p.Close()
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

func TestPoolHeapFailureRecovery(t *testing.T) {
	p := testPool(t, 16<<20)
	vm := acquire(t, p)
	w := vm.worker
	// Ordinary arrays consume V8 heap; ArrayBuffer backing stores do not.
	err := vm.Eval(`const retained = []; for (;;) retained.push(new Array(100000).fill(42));`)
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("V8 heap limit was not enforced: %v", err)
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
