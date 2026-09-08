//go:build cgo

// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestRuntimeCGOConcurrentGlobalsAndCallbacksStayIsolated(t *testing.T) {
	const count = 8
	ready := make(chan string, count)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	r := testRuntime(t, RuntimeOptions{Timeout: 5 * time.Second, Logger: testSurgeLogger(func(e *log.Entry) {
		ready <- e.Message
		<-release
	})})
	finished := make(chan error, count)
	for i := range count {
		go func() {
			id := fmt.Sprintf("invocation-%d", i)
			result, err := r.Run(context.Background(), `
if ("nativeRunID" in globalThis || "nativeRunID" in Object.prototype) throw Error("VM state leaked");
globalThis.nativeRunID = $argument;
Object.prototype.nativeRunID = $argument;
console.log($argument);
Promise.resolve().then(() => setTimeout(() => {
  if (globalThis.nativeRunID !== $argument || ({}).nativeRunID !== $argument) throw Error("concurrent VM collision");
  $done({body: $argument});
}, 0));
`, Invocation{Argument: id})
			if err == nil && (result == nil || result.Body == nil || string(result.Body.Bytes()) != id) {
				err = fmt.Errorf("invocation %s returned another VM's result: %#v", id, result)
			}
			finished <- err
		}()
	}
	seen := make(map[string]bool)
	for range count {
		select {
		case id := <-ready:
			if seen[id] {
				t.Fatalf("duplicate bridge invocation %q", id)
			}
			seen[id] = true
		case err := <-finished:
			t.Fatalf("VM exited before all concurrent callbacks started: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent VMs did not all enter the host bridge")
		}
	}
	releaseOnce.Do(func() { close(release) })
	for range count {
		select {
		case err := <-finished:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent VM did not finish")
		}
	}
	_, err := r.Run(context.Background(), `
if ("nativeRunID" in globalThis || "nativeRunID" in Object.prototype) throw Error("closed VM state survived");
if (typeof $argument !== "undefined") throw Error("argument leaked");
$done();
`, Invocation{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeCGORepeatedCancellationAndClose(t *testing.T) {
	// Each signal originates inside executing JS (including jobs/callbacks).
	// Cancellation races both native execution and the finite $done/VM-close
	// path, without depending on a goroutine moving between OS threads.
	var signals sync.Map
	r := testRuntime(t, RuntimeOptions{Timeout: 5 * time.Second, Logger: testSurgeLogger(func(e *log.Entry) {
		if ch, ok := signals.Load(e.Message); ok {
			close(ch.(chan struct{}))
		}
	})})
	client := &http.Client{Transport: runtimeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ready")), Request: req}, nil
	})}
	sources := []string{
		`console.log($argument); while (true) {}`,
		`Promise.resolve().then(() => {console.log($argument); while (true) {}})`,
		`$httpClient.get("https://fixture.test/", (error) => {if(error) throw Error(error); console.log($argument); while (true) {}})`,
		`console.log($argument); $done({body:"finished"})`,
	}
	var workers sync.WaitGroup
	for worker := range 6 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for iteration := range 12 {
				id := fmt.Sprintf("cancel-%d-%d", worker, iteration)
				ready := make(chan struct{})
				signals.Store(id, ready)
				ctx, cancel := context.WithCancel(context.Background())
				finished := make(chan error, 1)
				kind := (worker + iteration) % len(sources)
				go func() {
					_, err := r.Run(ctx, sources[kind], Invocation{Argument: id, HTTPClient: client})
					finished <- err
				}()
				select {
				case <-ready:
				case err := <-finished:
					cancel()
					// The finite script can close before the consumer sees ready.
					if kind != 3 || err != nil {
						t.Errorf("%s exited before executing its signal: %v", id, err)
					}
					signals.Delete(id)
					continue
				case <-time.After(5 * time.Second):
					cancel()
					t.Errorf("%s did not reach JS", id)
					return
				}
				cancel()
				select {
				case err := <-finished:
					if !errors.Is(err, context.Canceled) && !(kind == 3 && err == nil) {
						t.Errorf("%s cancellation result: %v", id, err)
					}
				case <-time.After(5 * time.Second):
					t.Errorf("%s did not stop after cancellation", id)
					return
				}
				cancel()
				signals.Delete(id)
			}
		}()
	}
	workers.Wait()
	result, err := r.Run(context.Background(), `$done({body:"new VM remains usable"})`, Invocation{})
	if err != nil || result.Body == nil || string(result.Body.Bytes()) != "new VM remains usable" {
		t.Fatalf("canceled VMs poisoned a later invocation: result=%#v err=%v", result, err)
	}
}

func TestRuntimeCGOCancelPendingHTTPRequest(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	client := &http.Client{Transport: runtimeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-req.Context().Done()
		close(stopped)
		return nil, req.Context().Err()
	})}
	r := testRuntime(t, RuntimeOptions{Timeout: 5 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, err := r.Run(ctx, `$httpClient.get("https://fixture.test/blocked", () => {throw Error("callback after cancellation")})`, Invocation{HTTPClient: client})
		finished <- err
	}()
	select {
	case <-started:
	case err := <-finished:
		t.Fatalf("script did not start its HTTP request: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP request was not started")
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("pending HTTP cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("VM did not close while HTTP was canceled")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("VM cancellation left its HTTP request running")
	}
}

func TestRuntimeCGONativeModulesAndFilesystemUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "native-loader-probe.mjs")
	if err := os.WriteFile(path, []byte(`globalThis.nativeFileModuleLoaded = true; export default "filesystem access";`), 0600); err != nil {
		t.Fatal(err)
	}
	r := testRuntime(t, RuntimeOptions{})
	result, err := r.Run(context.Background(), fmt.Sprintf(`
(async () => {
  for (const name of ["std", "os", "require", "process", "Deno", "readFile", "loadScript", "__daeHost"])
    if (typeof globalThis[name] !== "undefined") throw Error("unexpected native capability: " + name);
  for (const name of ["std", "os", "fs", "node:fs", %q]) {
    let loaded = false;
    try { await import(name); loaded = true; } catch (_) {}
    if (loaded) throw Error("native module loader accepted " + name);
  }
  if (typeof nativeFileModuleLoaded !== "undefined") throw Error("filesystem module executed");
  $done({body:"native modules unavailable"});
})();
`, path), Invocation{})
	if err != nil || result.Body == nil || string(result.Body.Bytes()) != "native modules unavailable" {
		t.Fatalf("unexpected native module capability: result=%#v err=%v", result, err)
	}
}

func TestRuntimeCGORecoversAfterMemoryFailure(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{MemoryLimit: 2 << 20})
	for range 8 {
		result, err := r.Run(context.Background(), `globalThis.beforeOOM = true; const huge = new Uint8Array(16*1024*1024); $done()`, Invocation{})
		if err == nil || result != nil {
			t.Fatalf("native allocation limit was not enforced: result=%#v err=%v", result, err)
		}
		result, err = r.Run(context.Background(), `
if (typeof beforeOOM !== "undefined") throw Error("failed VM was reused");
const buffer = new Uint8Array(65536); buffer[65535] = 123;
$done({body:String(buffer[65535])});
`, Invocation{})
		if err != nil || result.Body == nil || string(result.Body.Bytes()) != "123" {
			t.Fatalf("allocation failure damaged later VM: result=%#v err=%v", result, err)
		}
	}
}

func TestRuntimeCGONonblockingAtomics(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{Timeout: 250 * time.Millisecond})
	started := time.Now()
	result, err := r.Run(context.Background(), `
const words = new Int32Array(new SharedArrayBuffer(4));
let rejected = false;
try { Atomics.wait(words, 0, 0, 1000); }
catch (error) {
  if (!(error instanceof TypeError)) throw error;
  rejected = true;
}
if (!rejected) throw Error("Atomics.wait was allowed to block the VM thread");
$done({body:"nonblocking"});
`, Invocation{})
	if err != nil || result.Body == nil || string(result.Body.Bytes()) != "nonblocking" {
		t.Fatalf("Atomics.wait did not throw a catchable error: result=%#v err=%v", result, err)
	}
	if elapsed := time.Since(started); elapsed >= 750*time.Millisecond {
		t.Fatalf("Atomics.wait blocked the native thread for %v", elapsed)
	}
}

func TestRuntimeCGOWorkerStackLimit(t *testing.T) {
	// C execution on Go-created pthreads must respect their actual available
	// stack, including musl's smaller default worker stack.
	r := testRuntime(t, RuntimeOptions{})
	finished := make(chan error, 4)
	for range 4 {
		go func() {
			result, err := r.Run(context.Background(), `
function recurse(depth) { return 1 + recurse(depth + 1); }
let caught = false;
try { recurse(0); }
catch (error) {
  if (!(error instanceof Error) || !String(error).includes("stack")) throw error;
  caught = true;
}

if (!caught) throw Error("recursion exceeded no limit");
$done({body:"stack failure recovered"});
`, Invocation{})
			if err == nil && (result == nil || result.Body == nil || string(result.Body.Bytes()) != "stack failure recovered") {
				err = fmt.Errorf("worker stack failure did not recover: %#v", result)
			}
			finished <- err
		}()
	}
	for range 4 {
		select {
		case err := <-finished:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("worker recursion did not stop at the native stack limit")
		}
	}
}

func TestRuntimeCGOAtomics64(t *testing.T) {
	// 32-bit targets can require compiler runtime helpers for 64-bit atomics.
	// Exercise them with high bits set so a wrong ABI cannot pass by truncating.
	r := testRuntime(t, RuntimeOptions{})
	result, err := r.Run(context.Background(), `
const words = new BigInt64Array(new SharedArrayBuffer(8));
const base = 0x1234567800000000n;
function equal(actual, expected) {
  if (actual !== expected) throw Error("64-bit atomic value mismatch: " + actual + " != " + expected);
}
equal(Atomics.store(words, 0, base), base);
equal(Atomics.load(words, 0), base);
equal(Atomics.add(words, 0, 3n), base);
equal(Atomics.sub(words, 0, 1n), base + 3n);
equal(Atomics.or(words, 0, 4n), base + 2n);
equal(Atomics.xor(words, 0, 1n), base + 6n);
equal(Atomics.and(words, 0, ~2n), base + 7n);
equal(Atomics.compareExchange(words, 0, base + 5n, base + 9n), base + 5n);
equal(Atomics.exchange(words, 0, -base), base + 9n);
equal(Atomics.load(words, 0), -base);
$done({body:"64-bit atomics work"});
`, Invocation{})
	if err != nil || result == nil || result.Body == nil || string(result.Body.Bytes()) != "64-bit atomics work" {
		t.Fatalf("64-bit atomics: result=%#v err=%v", result, err)
	}
}
