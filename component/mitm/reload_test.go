// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/pluginhost"
	"github.com/prometheus/client_golang/prometheus"
)

type reloadPlugin struct {
	metricsTestPlugin
	runs    atomic.Int32
	started chan struct{}
	stopped chan struct{}
	ctx     context.Context
}

func (p *reloadPlugin) Run(ctx context.Context, _ *http.Client) error {
	p.ctx = ctx
	p.runs.Add(1)
	close(p.started)
	<-ctx.Done()
	close(p.stopped)
	return nil
}

type persistedReloadPlugin struct {
	store   *atomic.Int32
	state   atomic.Int32
	started chan struct{}
	stopped chan struct{}
}

func (*persistedReloadPlugin) Plan() plugin.Plan { return plugin.Plan{} }

func (p *persistedReloadPlugin) Run(ctx context.Context, _ *http.Client) error {
	p.state.Store(p.store.Load())
	close(p.started)
	<-ctx.Done()
	close(p.stopped)
	return nil
}

func (p *persistedReloadPlugin) Close() error {
	p.store.Store(p.state.Load())
	return nil
}

func TestReloadSuccessorAbandonmentPreservesActiveInstance(t *testing.T) {
	for _, mode := range []string{"unstarted", "activation rejected", "started"} {
		t.Run(mode, func(t *testing.T) {
			var store atomic.Int32
			store.Store(1)
			worker := &persistedReloadPlugin{store: &store, started: make(chan struct{}), stopped: make(chan struct{})}
			host, err := New(Options{}, Instance{ID: "state", Type: "fixture", Plugin: worker})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = host.Close() })
			if err := host.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			<-worker.started
			worker.state.Store(2)
			next, err := host.PrepareSuccessor()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = next.Close() })
			if mode == "activation rejected" {
				if err := next.Close(); err != nil {
					t.Fatal(err)
				}
				if err := next.Start(t.Context()); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("closed successor activation: %v", err)
				}
			} else if mode == "started" {
				if err := next.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if err := next.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-worker.stopped:
				t.Fatal("abandoning a successor stopped the active worker")
			default:
			}
			if store.Load() != 1 {
				t.Fatal("abandoning a successor prematurely closed the active instance")
			}
			if err := host.Close(); err != nil || store.Load() != 2 {
				t.Fatalf("last owner did not flush the instance: state=%d err=%v", store.Load(), err)
			}
		})
	}
}

func TestReloadFlushesBeforeSuccessorActivation(t *testing.T) {
	var store atomic.Int32
	store.Store(1)
	makeHost := func() (*Host, *persistedReloadPlugin) {
		t.Helper()
		p := &persistedReloadPlugin{store: &store, started: make(chan struct{}), stopped: make(chan struct{})}
		h, err := New(Options{}, Instance{ID: "state", Type: "fixture", Plugin: p})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = h.Close() })
		return h, p
	}
	old, before := makeHost()
	if err := old.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-before.started
	next, after := makeHost()
	old.requests.Add(1)
	finish := sync.OnceFunc(old.requests.Done)
	t.Cleanup(finish)
	type result struct {
		release func()
		err     error
	}
	drained := make(chan result, 1)
	go func() {
		release, err := old.DrainFor(next, false)
		drained <- result{release, err}
	}()
	<-before.stopped
	select {
	case <-drained:
		t.Fatal("state handoff completed before the old request finished")
	default:
	}
	// The final request can still update the old instance; Close must persist that update.
	before.state.Store(2)
	finish()
	r := <-drained
	if r.err != nil {
		t.Fatal(r.err)
	}
	defer r.release()
	if store.Load() != 2 {
		t.Fatal("old instance did not complete its final flush")
	}
	if err := next.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-after.started
	if after.state.Load() != 2 {
		t.Fatal("successor restored a stale snapshot")
	}
	after.state.Store(3)
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil || store.Load() != 3 {
		t.Fatalf("old instance close overwrote successor state: state=%d err=%v", store.Load(), err)
	}
}

func TestReloadAbortDrainsRequestsAndPreservesSharedWorker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var store atomic.Int32
		store.Store(1)
		before := &persistedReloadPlugin{store: &store, started: make(chan struct{}), stopped: make(chan struct{})}
		shared := &reloadPlugin{started: make(chan struct{}), stopped: make(chan struct{})}
		old, err := New(Options{}, Instance{ID: "state", Type: "fixture", Plugin: before}, Instance{ID: "shared", Type: "fixture", Plugin: shared})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = old.Close() })
		if err := old.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		<-before.started
		<-shared.started
		after := &persistedReloadPlugin{store: &store, started: make(chan struct{}), stopped: make(chan struct{})}
		retained := old.instances[1]
		if !retained.owner.Retain() {
			t.Fatal("shared instance was released")
		}
		next, err := New(Options{}, Instance{ID: "state", Type: "fixture", Plugin: after}, retained)
		if err != nil {
			_ = retained.owner.Release()
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = next.Close() })
		admitted, canceled, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
		finishRequest := sync.OnceFunc(func() { close(finish) })
		t.Cleanup(finishRequest)
		requestDone := make(chan error, 1)
		go func() {
			_, err := old.HandleDNS(t.Context(), &plugin.DNSExchange{}, func(ctx context.Context, _ *plugin.DNSExchange) (*plugin.DNSResponse, error) {
				close(admitted)
				<-ctx.Done()
				close(canceled)
				<-finish
				before.state.Store(2)
				return nil, ctx.Err()
			}, func(*plugin.DNSResponse) error { return nil })
			requestDone <- err
		}()
		<-admitted
		type result struct {
			release func()
			err     error
		}
		drained := make(chan result, 1)
		started := time.Now()
		go func() {
			release, err := old.DrainFor(next, true)
			drained <- result{release, err}
		}()
		synctest.Wait()
		select {
		case <-canceled:
		default:
			t.Fatal("abort waited for the graceful drain timeout")
		}
		if time.Since(started) != 0 {
			t.Fatal("abort consumed the drain grace period")
		}
		select {
		case <-drained:
			t.Fatal("drain returned before canceled request cleanup")
		default:
		}
		if shared.ctx.Err() != nil || shared.closed.Load() || shared.runs.Load() != 1 {
			t.Fatal("abort stopped the shared worker")
		}
		finishRequest()
		r := <-drained
		if r.err != nil {
			t.Fatal(r.err)
		}
		release := sync.OnceFunc(r.release)
		defer release()
		if err := <-requestDone; !errors.Is(err, context.Canceled) || store.Load() != 2 {
			t.Fatalf("request cleanup was not flushed: err=%v state=%d", err, store.Load())
		}
		if err := next.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		<-after.started
		release()
		if after.state.Load() != 2 || shared.ctx.Err() != nil || shared.runs.Load() != 1 {
			t.Fatal("successor lost final state or restarted the shared worker")
		}
	})
}

func TestReloadReusesInstancesWorkersAndMetrics(t *testing.T) {
	var metrics Metrics
	versions := map[string]string{"one": "1", "two": "1"}
	var constructed []*reloadPlugin
	var refreshes atomic.Int32
	definition := testDefinition(func(_ context.Context, _ plugin.Spec, services plugin.Services) (plugin.Plugin, error) {
		p := &reloadPlugin{started: make(chan struct{}), stopped: make(chan struct{})}
		p.counter = prometheus.NewCounter(prometheus.CounterOpts{Name: "fixture_events_total", Help: "Fixture events."})
		constructed = append(constructed, p)
		return p, services.Metrics.Register(p.counter)
	})
	definition.Resources = func(_ context.Context, spec plugin.Spec, _ plugin.Services) (plugin.Resources, error) {
		refreshes.Add(1)
		if versions[spec.ID] == "error" {
			return plugin.Resources{}, errors.New("refresh failed")
		}
		return plugin.Resources{Key: versions[spec.ID]}, nil
	}
	load := func(previous *Host, wantError bool) *Host {
		t.Helper()
		configuration, err := pluginhost.Configure(map[string]plugin.Definition{"fixture": definition}, []plugin.Spec{{ID: "one", Type: "fixture"}, {ID: "two", Type: "fixture"}})
		if err != nil {
			t.Fatal(err)
		}
		host, err := Load(t.Context(), configuration, Options{Metrics: &metrics}, plugin.Services{}, previous)
		if (err != nil) != wantError {
			t.Fatalf("load error = %v", err)
		}
		if host != nil {
			t.Cleanup(func() { _ = host.Close() })
		}
		return host
	}
	first := load(nil, false)
	if err := first.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, p := range constructed {
		<-p.started
		p.counter.Add(7)
	}
	abandoned := load(first, false)
	if !first.SameRuntime(abandoned) || len(constructed) != 2 || refreshes.Load() != 4 {
		t.Fatal("unchanged resource refresh reconstructed instances")
	}
	if err := abandoned.Close(); err != nil {
		t.Fatal(err)
	}
	assertPluginCounters(t, &metrics, map[string]float64{"one": 7, "two": 7})
	versions["one"] = "2"
	versions["two"] = "error"
	load(first, true)
	if len(constructed) != 2 || constructed[0].closed.Load() || constructed[1].closed.Load() {
		t.Fatal("failed resource preparation constructed candidates or released live instances")
	}
	versions["two"] = "1"
	next := load(first, false)
	if first.instances[0].owner == next.instances[0].owner || first.instances[1].owner != next.instances[1].owner {
		t.Fatal("replacement did not follow instance changes")
	}
	releaseWorkers, err := first.DrainFor(next, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := next.Start(t.Context()); err != nil {
		releaseWorkers()
		t.Fatal(err)
	}
	releaseWorkers()
	<-constructed[2].started
	<-constructed[0].stopped
	if constructed[1].runs.Load() != 1 || constructed[1].closed.Load() {
		t.Fatal("retiring a host stopped a shared worker")
	}
	if err := constructed[1].ctx.Err(); err != nil {
		t.Fatalf("shared worker lost its active owner: %v", err)
	}
	select {
	case <-constructed[1].stopped:
		t.Fatal("shared worker canceled")
	default:
	}
	assertPluginCounters(t, &metrics, map[string]float64{"one": 0, "two": 7})
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{1, 2} {
		<-constructed[index].stopped
		if !constructed[index].closed.Load() {
			t.Fatal("final host leaked an instance")
		}
	}
}
