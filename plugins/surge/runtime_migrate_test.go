// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
)

func TestRuntimeMigrationProtectsExecutingScopes(t *testing.T) {
	to, other := [6]byte{2, 0, 0, 0, 0, 2}, [6]byte{2, 0, 0, 0, 0, 3}
	for _, disk := range []bool{false, true} {
		for _, test := range []struct {
			name  string
			scope ScriptScope
			busy  bool
		}{
			{"source", testDeviceScope, true},
			{"target", testMACScope(to), true},
			{"other", testMACScope(other), false},
			{"local", testLocalScope, false},
			{"unknown", ScriptScope{}, false},
		} {
			t.Run(fmt.Sprintf("%t/%s", disk, test.name), func(t *testing.T) {
				path := ""
				if disk {
					path = filepath.Join(t.TempDir(), "store.json")
				}
				r := testRuntime(t, RuntimeOptions{StorePath: path})
				store := r.data
				if disk {
					otherRuntime := testRuntime(t, RuntimeOptions{StorePath: path})
					store = otherRuntime.data
					if store != r.data {
						t.Fatal("reload did not share store")
					}
				}
				if !store.write(t.Context(), testDeviceScope, "cookie", "captured", false) {
					t.Fatal("seed")
				}
				started, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				defer unblock()
				client := &http.Client{Transport: runtimeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					close(started)
					select {
					case <-release:
						return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: request}, nil
					case <-request.Context().Done():
						return nil, request.Context().Err()
					}
				})}
				code := `const before=$persistentStore.read("cookie"); $httpClient.get("http://fixture.test/", function(error) { if(error) throw Error(error); `
				want := "captured"
				if test.scope == testDeviceScope {
					code += `if (!$persistentStore.write(before+"-updated", "cookie")) throw Error("write failed"); `
					want += "-updated"
				}
				code += `$done(); });`
				done := make(chan error, 1)
				go func() {
					result, err := r.Runtime.Run(t.Context(), code, Invocation{Scope: test.scope, HTTPClient: client, BodyMemory: r.budget, BodyLimit: 1 << 20})
					result.Close()
					done <- err
				}()
				select {
				case <-started:
				case err := <-done:
					t.Fatalf("script ended before barrier: %v", err)
				case <-time.After(5 * time.Second):
					t.Fatal("script did not reach barrier")
				}
				moved, err := store.migrate(t.Context(), testDeviceMAC, to)
				if test.busy {
					if moved != 0 || !errors.Is(err, plugin.ErrScriptStoreBusy) || store.generation.Load() != 0 {
						t.Fatalf("active migration: %d %v", moved, err)
					}
				} else if err != nil || moved != 1 {
					t.Fatalf("unrelated execution blocked migration: %d %v", moved, err)
				}
				unblock()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				if test.busy {
					if moved, err := store.migrate(t.Context(), testDeviceMAC, to); err != nil || moved != 1 {
						t.Fatalf("after execution: %d %v", moved, err)
					}
				}
				if len(store.active) != 0 {
					t.Fatalf("retained execution counters: %v", store.active)
				}
				if got, err := store.read(t.Context(), testMACScope(to), "cookie"); err != nil || got != want {
					t.Fatalf("lost script write: %v %v", got, err)
				}
			})
		}
	}
}

func TestRuntimeMigrationWaitsForCanceledHTTPWorker(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	if !r.data.write(t.Context(), testDeviceScope, "cookie", "value", false) {
		t.Fatal("seed")
	}
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	client := &http.Client{Transport: runtimeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		close(started)
		// Simulate host I/O cleanup after cancellation; keep execution guarded until it exits.
		<-release
		return nil, request.Context().Err()
	})}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		result, err := r.Runtime.Run(ctx, `$httpClient.get("http://fixture.test/", function() {});`, Invocation{Scope: testDeviceScope, HTTPClient: client, BodyMemory: r.budget, BodyLimit: 1 << 20})
		result.Close()
		done <- err
	}()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("script ended early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("script did not reach HTTP worker")
	}
	cancel()
	to := [6]byte{2, 0, 0, 0, 0, 2}
	if _, err := r.data.migrate(t.Context(), testDeviceMAC, to); !errors.Is(err, plugin.ErrScriptStoreBusy) {
		t.Fatalf("cleanup released scope too early: %v", err)
	}
	select {
	case err := <-done:
		t.Fatalf("runtime returned before worker cleanup: %v", err)
	default:
	}
	unblock()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled runtime: %v", err)
	}
	if _, err := r.data.migrate(t.Context(), testDeviceMAC, to); err != nil {
		t.Fatalf("canceled execution retained scope: %v", err)
	}
}

func TestRuntimeMigrationExecutionCleanup(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	for _, code := range []string{`$done();`, `throw Error("fixture");`, `void 0;`} {
		result, _ := r.Run(t.Context(), code, Invocation{Scope: testDeviceScope, Timeout: 50 * time.Millisecond})
		result.Close()
		if len(r.data.active) != 0 {
			t.Fatalf("execution leaked scope: %s", code)
		}
	}
	if err := r.data.lock(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	result, err := r.Run(ctx, `$done();`, Invocation{Scope: testDeviceScope})
	result.Close()
	cancel()
	r.data.unlock()
	if !errors.Is(err, context.DeadlineExceeded) || len(r.data.active) != 0 {
		t.Fatalf("canceled admission leaked: %v", err)
	}
	if compiledJSRuntime == "nodejs" {
		// Failed VM acquisition after pool closure must release the registered execution.
		r.backend.Close()
		result, err = r.Run(t.Context(), `$done();`, Invocation{Scope: testDeviceScope})
		result.Close()
		if err == nil || len(r.data.active) != 0 {
			t.Fatalf("failed VM acquisition leaked: %v", err)
		}
	}
}
