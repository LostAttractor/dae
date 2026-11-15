// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

type triggerPlugin struct {
	testPlugin
	trigger func(context.Context, api.ScriptRunRequest) (api.ScriptRunResponse, error)
	closed  atomic.Bool
}

func (p *triggerPlugin) TriggerScript(ctx context.Context, request api.ScriptRunRequest) (api.ScriptRunResponse, error) {
	return p.trigger(ctx, request)
}
func (p *triggerPlugin) Close() error { p.closed.Store(true); return nil }

func TestScriptTriggerHostAdmission(t *testing.T) {
	p := &triggerPlugin{}
	h := testHost(t, Options{DisableHTTP: true}, Instance{ID: "scripts", Plugin: p}, Instance{ID: "unsupported", Plugin: &testPlugin{}})
	request := api.ScriptRunRequest{Script: "job", MAC: "02:00:00:00:00:01"}
	p.trigger = func(_ context.Context, got api.ScriptRunRequest) (api.ScriptRunResponse, error) {
		if !h.mu.TryLock() {
			t.Fatal("script trigger ran under host lock")
		}
		h.mu.Unlock()
		if got != request {
			t.Fatalf("request changed: %+v", got)
		}
		return api.ScriptRunResponse{Run: 1}, nil
	}
	if _, err := h.TriggerScript(t.Context(), "scripts", request); !errors.Is(err, plugin.ErrScriptInactive) {
		t.Fatalf("unstarted host: %v", err)
	}
	if err := h.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	response, err := h.TriggerScript(t.Context(), "scripts", request)
	if err != nil || response.Instance != "scripts" || response.Run != 1 {
		t.Fatalf("trigger: %+v %v", response, err)
	}
	for _, instance := range []string{"missing", "unsupported"} {
		if _, err := h.TriggerScript(t.Context(), instance, request); !errors.Is(err, plugin.ErrScriptNotFound) {
			t.Fatalf("%s: %v", instance, err)
		}
	}
	h.StopWorkers()
	if _, err := h.TriggerScript(t.Context(), "scripts", request); !errors.Is(err, plugin.ErrScriptInactive) {
		t.Fatalf("retired host: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.TriggerScript(t.Context(), "scripts", request); !errors.Is(err, plugin.ErrScriptInactive) {
		t.Fatalf("closed host: %v", err)
	}
}

type triggerWorkerPlugin struct {
	triggerPlugin
	run func(context.Context) error
}

func (p *triggerWorkerPlugin) Run(ctx context.Context, _ *http.Client) error { return p.run(ctx) }

func TestScriptTriggerCloseCancelsAndJoins(t *testing.T) {
	ready, entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var workerContext context.Context
	p := &triggerWorkerPlugin{run: func(ctx context.Context) error {
		workerContext = ctx
		close(ready)
		<-ctx.Done()
		return ctx.Err()
	}}
	p.trigger = func(context.Context, api.ScriptRunRequest) (api.ScriptRunResponse, error) {
		close(entered)
		select {
		case <-workerContext.Done():
			close(canceled)
		case <-release:
			return api.ScriptRunResponse{}, context.Canceled
		}
		<-release
		return api.ScriptRunResponse{}, workerContext.Err()
	}
	h := testHost(t, Options{DisableHTTP: true, HTTPClient: http.DefaultClient}, Instance{ID: "scripts", Plugin: p})
	defer close(release)
	if err := h.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-ready
	triggered := make(chan error, 1)
	go func() {
		_, err := h.TriggerScript(t.Context(), "scripts", api.ScriptRunRequest{Script: "job", MAC: "02:00:00:00:00:01"})
		triggered <- err
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- h.Close() }()
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("close did not cancel the trigger's worker context")
	}
	if p.closed.Load() {
		t.Fatal("plugin resources closed before trigger cleanup")
	}
	select {
	case <-closed:
		t.Fatal("host did not join trigger cleanup")
	default:
	}
	release <- struct{}{}
	if err := <-triggered; !errors.Is(err, context.Canceled) {
		t.Fatalf("trigger cancellation: %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if !p.closed.Load() {
		t.Fatal("plugin resources were not released")
	}
}

func TestScriptTriggerSharedHostCancellation(t *testing.T) {
	for _, closeHost := range []bool{false, true} {
		name := "request"
		if closeHost {
			name = "host drain"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var workerContext context.Context
				p := &triggerWorkerPlugin{run: func(ctx context.Context) error {
					workerContext = ctx
					<-ctx.Done()
					return ctx.Err()
				}}
				entered := make(chan struct{})
				p.trigger = func(ctx context.Context, _ api.ScriptRunRequest) (api.ScriptRunResponse, error) {
					close(entered)
					<-ctx.Done()
					return api.ScriptRunResponse{}, ctx.Err()
				}
				h := testHost(t, Options{DisableHTTP: true, HTTPClient: http.DefaultClient, DrainTimeout: time.Second}, Instance{ID: "scripts", Plugin: p})
				if err := h.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				next, err := h.PrepareSuccessor()
				if err != nil {
					t.Fatal(err)
				}
				defer next.Close()
				if err := next.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				triggered := make(chan error, 1)
				go func() {
					_, err := h.TriggerScript(ctx, "scripts", api.ScriptRunRequest{Script: "job"})
					triggered <- err
				}()
				<-entered
				if closeHost {
					if err := h.Close(); err != nil {
						t.Fatal(err)
					}
				} else {
					cancel()
				}
				if err := <-triggered; !errors.Is(err, context.Canceled) {
					t.Fatalf("admission cancellation: %v", err)
				}
				if workerContext.Err() != nil || p.closed.Load() {
					t.Fatal("admission cancellation stopped the successor's worker")
				}
			})
		})
	}
}

func TestScriptTriggerRejectsForcedHost(t *testing.T) {
	h := testHost(t, Options{DisableHTTP: true})
	if err := h.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	h.forceCancel()
	if _, err := h.TriggerScript(t.Context(), "missing", api.ScriptRunRequest{}); !errors.Is(err, plugin.ErrScriptInactive) {
		t.Fatalf("forced host: %v", err)
	}
}
