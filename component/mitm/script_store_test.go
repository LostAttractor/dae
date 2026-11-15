// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

type migrationPlugin struct {
	migrate func(context.Context, api.ScriptStoreMigrateRequest) (api.ScriptStoreMigrateResponse, error)
	closed  atomic.Bool
}

func (*migrationPlugin) Plan() plugin.Plan { return plugin.Plan{} }
func (p *migrationPlugin) Close() error    { p.closed.Store(true); return nil }
func (p *migrationPlugin) MigrateScriptStore(ctx context.Context, request api.ScriptStoreMigrateRequest) (api.ScriptStoreMigrateResponse, error) {
	return p.migrate(ctx, request)
}

func TestScriptStoreMigrationHostAdmission(t *testing.T) {
	p := &migrationPlugin{}
	h := testHost(t, Options{DisableHTTP: true}, Instance{ID: "store", Plugin: p}, Instance{ID: "unsupported", Plugin: &testPlugin{}})
	request := api.ScriptStoreMigrateRequest{FromMAC: "02:00:00:00:00:11", ToMAC: "02:00:00:00:00:22"}
	p.migrate = func(ctx context.Context, got api.ScriptStoreMigrateRequest) (api.ScriptStoreMigrateResponse, error) {
		if !h.mu.TryLock() {
			t.Fatal("migration ran under host lock")
		}
		h.mu.Unlock()
		if got != request || ctx.Err() != nil {
			t.Fatalf("request/context lost: %+v %v", got, ctx.Err())
		}
		return api.ScriptStoreMigrateResponse{FromMAC: got.FromMAC, ToMAC: got.ToMAC, KeysMoved: 2}, nil
	}
	if _, err := h.MigrateScriptStore(t.Context(), "store", request); !errors.Is(err, plugin.ErrScriptStoreUnavailable) {
		t.Fatalf("unstarted host: %v", err)
	}
	if err := h.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	response, err := h.MigrateScriptStore(t.Context(), "store", request)
	if err != nil || response.Instance != "store" || response.KeysMoved != 2 {
		t.Fatalf("migration: %+v %v", response, err)
	}
	for _, test := range []struct {
		instance string
		want     error
	}{
		{"missing", plugin.ErrScriptStoreNotFound}, {"unsupported", plugin.ErrScriptStoreUnavailable},
	} {
		if _, err := h.MigrateScriptStore(t.Context(), test.instance, request); !errors.Is(err, test.want) {
			t.Fatalf("%s: %v", test.instance, err)
		}
	}
	h.StopWorkers()
	if _, err := h.MigrateScriptStore(t.Context(), "store", request); !errors.Is(err, plugin.ErrScriptStoreUnavailable) {
		t.Fatalf("retired host: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.MigrateScriptStore(t.Context(), "store", request); !errors.Is(err, plugin.ErrScriptStoreUnavailable) {
		t.Fatalf("closed host: %v", err)
	}
	if _, err := (*Host)(nil).MigrateScriptStore(t.Context(), "store", request); !errors.Is(err, plugin.ErrScriptStoreUnavailable) {
		t.Fatalf("nil host: %v", err)
	}
}

func TestScriptStoreMigrationCloseCancelsAndJoins(t *testing.T) {
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	p := &migrationPlugin{migrate: func(ctx context.Context, _ api.ScriptStoreMigrateRequest) (api.ScriptStoreMigrateResponse, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return api.ScriptStoreMigrateResponse{}, ctx.Err()
	}}
	h := testHost(t, Options{DisableHTTP: true, DrainTimeout: time.Millisecond}, Instance{ID: "store", Plugin: p})
	if err := h.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer close(release)
	done := make(chan error, 1)
	go func() {
		_, err := h.MigrateScriptStore(t.Context(), "store", api.ScriptStoreMigrateRequest{})
		done <- err
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- h.Close() }()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("close did not cancel migration")
	}
	if p.closed.Load() {
		t.Fatal("plugin closed before migration cleanup")
	}
	select {
	case <-closed:
		t.Fatal("close did not join migration cleanup")
	default:
	}
	// Release cleanup before the test host's registered Close runs.
	release <- struct{}{}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("migration cancellation: %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if !p.closed.Load() {
		t.Fatal("plugin resources were not released")
	}
}

func TestScriptStoreMigrationRejectsForcedHost(t *testing.T) {
	h := testHost(t, Options{DisableHTTP: true})
	if err := h.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	h.forceCancel()
	if _, err := h.MigrateScriptStore(t.Context(), "missing", api.ScriptStoreMigrateRequest{}); !errors.Is(err, plugin.ErrScriptStoreUnavailable) {
		t.Fatalf("forced host: %v", err)
	}
}
