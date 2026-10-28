// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/settings"
)

type reloadStatePlugin struct {
	store    *atomic.Int32
	state    atomic.Int32
	started  chan struct{}
	closed   atomic.Bool
	closeErr error
}

func (*reloadStatePlugin) Plan() plugin.Plan { return plugin.Plan{} }
func (p *reloadStatePlugin) Run(ctx context.Context, _ *http.Client) error {
	p.state.Store(p.store.Load())
	close(p.started)
	<-ctx.Done()
	return nil
}
func (p *reloadStatePlugin) Close() error {
	p.store.Store(p.state.Load())
	p.closed.Store(true)
	return p.closeErr
}

func TestReplaceMITMFlushesRetiredState(t *testing.T) {
	for _, routingRetirement := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			var store atomic.Int32
			store.Store(1)
			makeHost := func() (*mitm.Host, *reloadStatePlugin) {
				t.Helper()
				p := &reloadStatePlugin{store: &store, started: make(chan struct{})}
				h, err := mitm.New(mitm.Options{}, mitm.Instance{ID: "state", Type: "fixture", Plugin: p})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = h.Close() })
				return h, p
			}
			first, before := makeHost()
			if err := first.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			<-before.started
			before.state.Store(2)
			plane := &ControlPlane{core: &controlPlaneCore{bpf: &BPFState{}}, ctx: t.Context(), mitmHost: first, tcpSetupCtx: t.Context()}
			shared, err := first.PrepareSuccessor()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = shared.Close() })
			if routingRetirement {
				if err := shared.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
				first.StopWorkers()
				plane.mitmHost = shared
				retired := make(chan struct{})
				plane.core.bpf.Runtime = &Runtime{retired: retired, done: make(chan struct{})}
				go func() {
					time.Sleep(handoffLifetime)
					_ = first.Close()
					close(retired)
				}()
			} else if err := plane.ReplaceMITM(PreparedMITM{Host: shared}, nil); err != nil {
				t.Fatal(err)
			}
			if before.closed.Load() {
				t.Fatal("unchanged instance was closed")
			}
			next, after := makeHost()
			// The first generation still owns the instance; retire all old hosts before restoring state.
			if err := plane.ReplaceMITM(PreparedMITM{Host: next}, nil); err != nil {
				t.Fatal(err)
			}
			<-after.started
			if !before.closed.Load() || after.state.Load() != 2 {
				t.Fatalf("incorrect state handoff: old_closed=%t restored=%d", before.closed.Load(), after.state.Load())
			}
			after.state.Store(3)
			if err := next.Close(); err != nil {
				t.Fatal(err)
			}
			plane.retiredHosts.Wait()
			if store.Load() != 3 {
				t.Fatal("retired generation overwrote successor state")
			}
		})
	}
}

func TestPublishWaitsForRetiredHostsOnlyWhenInstancesChange(t *testing.T) {
	const requestDrain = time.Second
	for _, rebuild := range []bool{false, true} {
		for _, abort := range []bool{false, true} {
			synctest.Test(t, func(t *testing.T) {
				var store atomic.Int32
				makeHost := func() (*mitm.Host, *reloadStatePlugin) {
					t.Helper()
					p := &reloadStatePlugin{store: &store, started: make(chan struct{})}
					host, err := mitm.New(mitm.Options{DrainTimeout: requestDrain}, mitm.Instance{ID: "state", Type: "fixture", Plugin: p})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = host.Close() })
					return host, p
				}
				first, worker := makeHost()
				if err := first.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
				<-worker.started
				worker.state.Store(2)
				runtime := NewRuntime()
				t.Cleanup(func() { clear(runtime.planes); _ = runtime.Close() })
				matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "domain(suffix:example.test) -> direct"))
				makePlane := func(generation uint32, host *mitm.Host) *ControlPlane {
					t.Helper()
					registry, _ := newTestRegistry(16, time.Hour)
					t.Cleanup(func() { _ = registry.Close() })
					closed, cancel := context.WithCancel(t.Context())
					t.Cleanup(cancel)
					plane := &ControlPlane{
						core: &controlPlaneCore{bpf: &BPFState{bpfObjects: new(bpfObjects), Runtime: runtime}, domainRegistry: registry, closed: closed, close: cancel},
						ctx:  t.Context(), planeTraffic: newPlaneTraffic(t.Context(), &runtime.tcpConnections, runtime.udpEndpoints),
						mitmHost: host, settings: new(settings.Store), routingMatcher: matcher, routingGeneration: generation,
					}
					t.Cleanup(func() { plane.cancelTCPSetups(); plane.udpTaskPool.close() })
					return plane
				}
				old := makePlane(1, first)
				runtime.current, runtime.planes[1] = old, old
				shared, err := first.PrepareSuccessor()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = shared.Close() })
				if err := old.ReplaceMITM(PreparedMITM{Host: shared}, nil); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				var host *mitm.Host
				var requestDone chan error
				if rebuild {
					host, _ = makeHost()
					admitted := make(chan struct{})
					requestDone = make(chan error, 1)
					go func() {
						_, err := shared.HandleDNS(t.Context(), &plugin.DNSExchange{}, func(ctx context.Context, _ *plugin.DNSExchange) (*plugin.DNSResponse, error) {
							close(admitted)
							<-ctx.Done()
							worker.state.Store(3)
							return nil, ctx.Err()
						}, func(*plugin.DNSResponse) error { return nil })
						requestDone <- err
					}()
					<-admitted
				} else {
					host, err = shared.PrepareSuccessor()
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = host.Close() })
				}
				next := makePlane(2, host)
				// Stop at link activation: the handoff ordering needs no real kernel attachments.
				next.core.close()
				started := time.Now()
				if err := runtime.Publish(next, abort); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("publication did not reach link activation: %v", err)
				}
				want := time.Duration(0)
				if rebuild {
					if !abort {
						want = handoffLifetime + requestDrain
					}
					if err := <-requestDone; !errors.Is(err, context.Canceled) {
						t.Fatalf("in-flight request was not canceled: %v", err)
					}
					if !worker.closed.Load() || store.Load() != 3 {
						t.Fatal("instance replacement skipped the final request state")
					}
				} else if worker.closed.Load() {
					t.Fatal("shared instance was closed")
				}
				if elapsed := time.Since(started); elapsed != want {
					t.Fatalf("publication delay = %v, want %v (rebuild=%t abort=%t)", elapsed, want, rebuild, abort)
				}
				old.retiredHosts.Wait()
			})
		}
	}
}

func TestReplaceMITMFlushFailureIsNotRejection(t *testing.T) {
	failure := errors.New("fixture flush failed")
	var store atomic.Int32
	p := &reloadStatePlugin{store: &store, started: make(chan struct{}), closeErr: failure}
	host, err := mitm.New(mitm.Options{}, mitm.Instance{ID: "state", Type: "fixture", Plugin: p})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	if err := host.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-p.started
	plane := &ControlPlane{core: &controlPlaneCore{bpf: &BPFState{}}, ctx: t.Context(), mitmHost: host}
	if err := plane.ReplaceMITM(PreparedMITM{}, nil); !errors.Is(err, failure) || errors.Is(err, ErrPublicationRejected) {
		t.Fatalf("final flush failure must not be reported as a rollback-safe rejection: %v", err)
	}
}
