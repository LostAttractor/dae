//go:build surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/pluginhost"
	"github.com/daeuniverse/dae/pkg/config_parser"
	log "github.com/sirupsen/logrus"
)

func TestNodeRuntimePreparationCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nwhile :; do :; done\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	engine, err := prepare(ctx, Config{
		NodePath: path, MemoryLimit: 64 << 20, MaxBodySize: 1 << 20,
		MaxConcurrentScripts: 1, ScriptTimeout: DefaultScriptTimeout,
	}, plugin.Services{Prepared: []*Module{}, BodyMemory: testBodyMemory}, "test")
	if engine != nil {
		_ = engine.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 2*time.Second {
		t.Fatalf("runtime preparation outlived caller: %v after %v", err, time.Since(started))
	}
}

func TestNodeTaskCancellation(t *testing.T) {
	m := cronModule(t, "[Script]\njob=type=generic,script-path=job.js")
	e := cronTestEngine(t, m, map[string]string{"job": `
if ($trigger !== "http-api") throw Error("wrong trigger");
$persistentStore.write("started", "state");
$httpClient.get("https://task.test/", () => $done());`}, 1)
	entered, canceled := make(chan struct{}), make(chan struct{})
	client := &http.Client{Transport: runtimeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
		return nil, r.Context().Err()
	})}
	host, err := mitm.New(mitm.Options{HTTPClient: client}, mitm.Instance{ID: "test", Type: "surge", Plugin: e})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	if err := host.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for cronStatus(t, e, 0).State != "ready" {
		if time.Now().After(deadline) {
			t.Fatal("task worker did not start")
		}
		time.Sleep(time.Millisecond)
	}
	request := api.ScriptRunRequest{Script: "job"}
	if _, err := host.TriggerScript("test", request); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Node task did not reach the host HTTP client")
	}
	if _, err := host.TriggerScript("test", request); !errors.Is(err, plugin.ErrScriptBusy) {
		t.Fatalf("overlapping task accepted: %v", err)
	}
	if got, err := e.options.Runtime.data.read(t.Context(), "state"); err != nil || got != "started" {
		t.Fatalf("task storage: %q, %v", got, err)
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	default:
		t.Fatal("retirement did not join the task's HTTP request")
	}
	status := cronStatus(t, e, 0)
	if status.Runs != 1 || status.State != "stopped" || status.LastError != "canceled" || len(e.slots) != 0 {
		t.Fatalf("retired task: %+v", status)
	}
	if _, err := host.TriggerScript("test", request); !errors.Is(err, plugin.ErrScriptInactive) {
		t.Fatalf("retired host accepted task: %v", err)
	}
}

func TestNodeHTTPDeadline(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{Timeout: 5 * time.Second})
	called := false
	client := &http.Client{Transport: runtimeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		<-req.Context().Done()
		return nil, req.Context().Err()
	})}
	result, err := r.Run(t.Context(), `$httpClient.get({url:"https://deadline.test/",timeout:0.05}, e => $done({body:e ? "timeout" : "missing"}));`, Invocation{HTTPClient: client})
	if err != nil || !called || result == nil || string(result.Body.Bytes()) != "timeout" {
		t.Fatalf("HTTP timeout callback: result=%+v called=%t err=%v", result, called, err)
	}
}

func TestRuntimeNodeJSLimitsAndRecovery(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{Timeout: 300 * time.Millisecond, NodeWorkers: 1})
	for _, source := range []string{
		`while (true) {}`,
		`Promise.resolve().then(() => {while (true) {}})`,
		`function spin(){Promise.resolve().then(spin)}; spin()`,
		`setTimeout(() => {while (true) {}}, 0)`,
		`setTimeout(() => $done(), 10000)`,
		`$done(); while (true) {}`,
	} {
		t.Run(source, func(t *testing.T) {
			start := time.Now()
			result, err := r.Run(t.Context(), source, Invocation{})
			if result != nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
				t.Fatalf("timeout: result=%v err=%v elapsed=%v", result, err, time.Since(start))
			}
			result, err = r.Run(t.Context(), `$done({body:$environment["dae-runtime"]})`, Invocation{Timeout: 5 * time.Second})
			if err != nil || string(result.Body.Bytes()) != "nodejs" {
				t.Fatalf("recovery: result=%v err=%v", result, err)
			}
		})
	}
	for _, source := range []string{`throw Error("test failure")`, `function (`} {
		if result, err := r.Run(t.Context(), source, Invocation{}); err == nil || result != nil {
			t.Fatalf("script error: result=%v err=%v", result, err)
		}
	}
}

func TestConfiguredNodeRuntimeLifecycle(t *testing.T) {
	m := moduleScopeModule(t, "node", "example.test", `[Script]
request=type=http-request,pattern=.,script-path=request.js
`, map[string]string{"request": `$done({response:{status:201,body:$environment["dae-runtime"]}})`})
	sections, err := config_parser.Parse(`surge {
  max_concurrent_scripts: 1
  store: false
  module { 'file:module' }
}`)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := Configure(plugin.Spec{ID: "node", Type: "surge", Config: sections[0]})
	if err != nil {
		t.Fatal(err)
	}
	logger := log.New()
	logger.SetOutput(io.Discard)
	p, err := factory(t.Context(), plugin.Services{Prepared: []*Module{m}, BodyMemory: testBodyMemory, Logger: log.NewEntry(logger)})
	if err != nil {
		t.Fatal(err)
	}
	e := p.(*Engine)
	t.Cleanup(func() { _ = e.Close() })
	owner := pluginhost.Adopt("node", "surge", p)
	handler := e.Wrap(plugin.Flow{Host: "example.test", Port: 443}, func(*plugin.Exchange) (*http.Response, error) {
		t.Fatal("synthetic response reached upstream")
		return nil, nil
	})
	response, err := handler(&plugin.Exchange{Request: httptest.NewRequest(http.MethodGet, "https://example.test/", nil)})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 201 || string(body) != "nodejs" {
		t.Fatalf("configured runtime result: status=%d body=%s err=%v", response.StatusCode, body, err)
	}
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.options.Runtime.Run(t.Context(), `$done()`, Invocation{}); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("host retirement did not close Node runtime: %v", err)
	}
}
