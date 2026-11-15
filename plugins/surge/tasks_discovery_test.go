// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/prometheus/client_golang/prometheus"
)

type taskDiscoveryDevices struct {
	*testDeviceService
	query  func(context.Context, int) ([][6]byte, error)
	calls  atomic.Int32
	active atomic.Int32
	peak   atomic.Int32
}

func (d *taskDiscoveryDevices) MITMEnabled(ctx context.Context) ([][6]byte, error) {
	active := d.active.Add(1)
	defer d.active.Add(-1)
	for peak := d.peak.Load(); active > peak; peak = d.peak.Load() {
		if d.peak.CompareAndSwap(peak, active) {
			break
		}
	}
	return d.query(ctx, int(d.calls.Add(1)))
}

func TestTaskDiscoveryDoesNotBlockLocal(t *testing.T) {
	for _, startup := range []bool{true, false} {
		name := "cron"
		if startup {
			name = "startup"
		}
		t.Run(name, func(t *testing.T) {
			runtimeFakeClockTest(t, func(t *testing.T) {
				module := cronModule(t, `[Script]
job=type=cron,cronexp=* * * * * *,timeout=1,script-path=job.js
manual=type=generic,timeout=1,script-path=manual.js
shared=type=cron,cronexp=* * * * * *,timeout=1,script-path=shared.js`)
				if err := applyModuleIsolation(module, ModuleSource{ScriptIsolation: map[string]bool{"shared": false}}); err != nil {
					t.Fatal(err)
				}
				source := `$persistentStore.write("ran", $script.name); $done();`
				e := cronTestEngine(t, module, map[string]string{"job": source, "manual": source, "shared": source}, 1)
				entered, release := make(chan struct{}), make(chan struct{})
				blocked := 2
				if startup {
					blocked = 1
				}
				devices := &taskDiscoveryDevices{testDeviceService: newTestDevices()}
				devices.query = func(ctx context.Context, call int) ([][6]byte, error) {
					if call != blocked {
						return [][6]byte{testDeviceMAC}, nil
					}
					close(entered)
					select {
					case <-release:
						return nil, errors.New("LAN discovery failed")
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				e.options.Devices = devices
				host := startCronTestHost(t, e, http.DefaultClient)
				time.Sleep(time.Until(cronStatus(t, e, 0).NextRun) + time.Millisecond)
				synctest.Wait()
				select {
				case <-entered:
				default:
					t.Fatal("discovery did not start")
				}
				if _, err := host.TriggerScript(t.Context(), "test", api.ScriptRunRequest{Script: "manual"}); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				for _, name := range []string{"job", "manual", "shared"} {
					if value, err := e.options.Runtime.data.read(t.Context(), testLocalScope, name); err != nil || value != "ran" {
						t.Fatalf("local %s waited for LAN discovery: %v %v", name, value, err)
					}
				}
				time.Sleep(2100 * time.Millisecond)
				synctest.Wait()
				if got := devices.calls.Load(); got != int32(blocked) {
					t.Fatalf("slow discovery spawned more queries: %d", got)
				}
				close(release)
				synctest.Wait()
				for _, status := range e.Status().Modules[0].Tasks {
					if status.Scope == "local" && (status.LastResult != "success" || status.Failures != 0) {
						t.Fatalf("LAN failure affected local task: %+v", status)
					}
					if !startup && status.Scope == "device" && status.Runs != 0 {
						t.Fatalf("failed discovery reused old LAN target: %+v", status)
					}
				}
				if devices.peak.Load() != 1 {
					t.Fatalf("automatic discoveries overlapped: %d", devices.peak.Load())
				}
			})
		})
	}
}

func TestTaskDiscoveryCoalescesTicksBeforeLANAdmission(t *testing.T) {
	runtimeFakeClockTest(t, func(t *testing.T) {
		module := cronModule(t, "[Script]\njob=type=cron,cronexp=* * * * * *,timeout=1,script-path=job.js")
		e := cronTestEngine(t, module, map[string]string{"job": `$persistentStore.write("ran", "task"); $done();`}, 1)
		registry := prometheus.NewRegistry()
		registry.MustRegister(e.metrics)
		release := make(chan struct{})
		devices := &taskDiscoveryDevices{testDeviceService: newTestDevices()}
		devices.query = func(ctx context.Context, call int) ([][6]byte, error) {
			if call == 2 {
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return [][6]byte{testDeviceMAC}, nil
		}
		e.options.Devices = devices
		startCronTestHost(t, e, http.DefaultClient)
		time.Sleep(time.Until(cronStatus(t, e, 0).NextRun) + 2100*time.Millisecond)
		synctest.Wait()
		if got := devices.calls.Load(); got != 2 {
			t.Fatalf("slow discovery spawned %d queries", got)
		}
		if status := cronStatus(t, e, 0); status.Runs != 3 || status.LastResult != "success" {
			t.Fatalf("local ticks were delayed: %+v", status)
		}
		if status := deviceTaskStatus(t, e, testDeviceMAC); status.Runs != 0 || status.State != "scheduled" {
			t.Fatalf("LAN task admitted before discovery: %+v", status)
		}
		admitted := time.Now()
		close(release)
		synctest.Wait()
		status := deviceTaskStatus(t, e, testDeviceMAC)
		if status.Runs != 1 || status.Skipped != 2 || status.LastResult != "success" || !status.LastStartedAt.Equal(admitted) || status.LastDurationMS != 0 {
			t.Fatalf("LAN admission reused old time or replayed ticks: %+v", status)
		}
		if got := surgeMetric(t, registry, "surge_processing_skips_total", map[string]string{"stage": "cron", "reason": "overlap"}).GetCounter().GetValue(); got != 2 {
			t.Fatalf("coalesced overlap metric = %v", got)
		}
		if devices.calls.Load() != 3 || devices.peak.Load() != 1 {
			t.Fatalf("discovery/revalidation counts: calls=%d peak=%d", devices.calls.Load(), devices.peak.Load())
		}
	})
}

func TestTaskDiscoveryBatchesUseTheirOwnQuery(t *testing.T) {
	for _, startup := range []bool{true, false} {
		name := "cron"
		if startup {
			name = "startup"
		}
		t.Run(name, func(t *testing.T) {
			runtimeFakeClockTest(t, func(t *testing.T) {
				module := cronModule(t, `[Script]
early=type=cron,cronexp=1 * * * * *,script-path=early.js
late=type=cron,cronexp=2 * * * * *,script-path=late.js`)
				source := `$persistentStore.write("ran", $script.name); $done();`
				e := cronTestEngine(t, module, map[string]string{"early": source, "late": source}, 2)
				a, b := testDeviceMAC, [6]byte{2, 0, 0, 0, 0, 2}
				blocked := int32(2)
				if startup {
					blocked = 1
				}
				release := make(chan struct{})
				var queries atomic.Int32
				devices := &taskDiscoveryDevices{testDeviceService: newTestDevices()}
				devices.query = func(ctx context.Context, _ int) ([][6]byte, error) {
					if _, bounded := ctx.Deadline(); bounded {
						return [][6]byte{a, b}, nil
					}
					switch call := queries.Add(1); {
					case call < blocked:
						return nil, nil
					case call == blocked:
						select {
						case <-release:
							return [][6]byte{a}, nil
						case <-ctx.Done():
							return nil, ctx.Err()
						}
					default:
						return [][6]byte{b}, nil
					}
				}
				e.options.Devices = devices
				startCronTestHost(t, e, http.DefaultClient)
				time.Sleep(time.Until(cronStatus(t, e, 0).NextRun) + 1100*time.Millisecond)
				synctest.Wait()
				if queries.Load() != blocked {
					t.Fatalf("concurrent automatic queries: %d", queries.Load())
				}
				close(release)
				synctest.Wait()
				if queries.Load() != blocked+1 {
					t.Fatalf("later due reused an earlier query: %d", queries.Load())
				}
				for _, mac := range [][6]byte{a, b} {
					for _, name := range []string{"early", "late"} {
						var want any
						if mac == b && (name == "late" || startup) || mac == a && name == "early" && !startup {
							want = "ran"
						}
						if value, err := e.options.Runtime.data.read(t.Context(), testMACScope(mac), name); err != nil || value != want {
							t.Fatalf("%s on %v = %v, want %v: %v", name, mac, value, want, err)
						}
					}
				}
			})
		})
	}
}

func TestTaskDiscoveryDoesNotReplayCompletedOverlap(t *testing.T) {
	runtimeFakeClockTest(t, func(t *testing.T) {
		module := cronModule(t, "[Script]\njob=type=cron,cronexp=* * * * * *,script-path=job.js")
		e := cronTestEngine(t, module, map[string]string{"job": `if (typeof $trigger !== "undefined") setTimeout(() => $done(), 1500); else $done();`}, 2)
		release := make(chan struct{})
		devices := &taskDiscoveryDevices{testDeviceService: newTestDevices()}
		devices.query = func(ctx context.Context, call int) ([][6]byte, error) {
			if call == 4 {
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return [][6]byte{testDeviceMAC}, nil
		}
		e.options.Devices = devices
		host := startCronTestHost(t, e, http.DefaultClient)
		if _, err := host.TriggerScript(t.Context(), "test", api.ScriptRunRequest{Script: "job", MAC: testDeviceName}); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if status := deviceTaskStatus(t, e, testDeviceMAC); status.State != "running" {
			t.Fatalf("manual task did not start: %+v", status)
		}
		time.Sleep(time.Until(cronStatus(t, e, 0).NextRun) + 1100*time.Millisecond)
		synctest.Wait()
		if status := deviceTaskStatus(t, e, testDeviceMAC); status.LastResult != "success" {
			t.Fatalf("manual task did not finish during discovery: %+v", status)
		}
		close(release)
		synctest.Wait()
		if status := deviceTaskStatus(t, e, testDeviceMAC); status.Runs != 1 || status.Skipped != 2 || status.LastTrigger != "http-api" {
			t.Fatalf("late discovery replayed an overlapped tick: %+v", status)
		}
	})
}

func TestTaskDiscoveryAllowsLocalManualExecution(t *testing.T) {
	module := cronModule(t, "[Script]\njob=type=generic,script-path=job.js")
	e := cronTestEngine(t, module, map[string]string{"job": `$persistentStore.write("ran", "task"); $httpClient.get("https://task.test/", () => $done());`}, 1)
	entered, executed := make(chan struct{}), make(chan struct{})
	devices := &taskDiscoveryDevices{testDeviceService: newTestDevices()}
	devices.query = func(ctx context.Context, _ int) ([][6]byte, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	e.options.Devices = devices
	client := &http.Client{Transport: runtimeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(executed)
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	host, err := mitm.New(mitm.Options{HTTPClient: client}, mitm.Instance{ID: "test", Type: "surge", Plugin: e})
	if err != nil {
		t.Fatal(err)
	}
	if err := host.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	<-entered
	if _, err := host.TriggerScript(t.Context(), "test", api.ScriptRunRequest{Script: "job"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-executed:
	case <-time.After(5 * time.Second):
		t.Fatal("local manual execution waited for discovery")
	}
	if value, err := e.options.Runtime.data.read(t.Context(), testLocalScope, "task"); err != nil || value != "ran" {
		t.Fatalf("manual execution did not use local storage: %v %v", value, err)
	}
	if devices.calls.Load() != 1 || devices.active.Load() != 1 {
		t.Fatal("local execution performed another device query")
	}
}

func TestOlderTaskDiscoveryCannotReplaceManualSnapshot(t *testing.T) {
	for _, oldErr := range []error{nil, errors.New("old scan failed")} {
		runtimeFakeClockTest(t, func(t *testing.T) {
			module := cronModule(t, "[Script]\njob=type=generic,script-path=job.js")
			e := cronTestEngine(t, module, map[string]string{"job": `$done();`}, 1)
			entered, release := make(chan struct{}), make(chan struct{})
			devices := &taskDiscoveryDevices{testDeviceService: newTestDevices(testDeviceMAC)}
			devices.query = func(ctx context.Context, call int) ([][6]byte, error) {
				if call == 1 {
					close(entered)
					select {
					case <-release:
						return nil, oldErr
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				return [][6]byte{testDeviceMAC}, nil
			}
			e.options.Devices = devices
			host := startCronTestHost(t, e, http.DefaultClient)
			<-entered
			if _, err := host.TriggerScript(t.Context(), "test", api.ScriptRunRequest{Script: "job", MAC: testDeviceName}); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			close(release)
			synctest.Wait()
			if got := deviceTaskStatus(t, e, testDeviceMAC); got.Runs != 1 || got.LastResult != "success" || got.State != "ready" {
				t.Fatalf("stale discovery replaced successful task: %+v", got)
			}
		})
	}
}

func TestConcurrentTaskDeviceChecksShareOnlyInFlightScan(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		second := [6]byte{2, 0, 0, 0, 0, 2}
		entered, release := make(chan struct{}), make(chan struct{})
		devices := &taskDiscoveryDevices{testDeviceService: newTestDevices(testDeviceMAC, second)}
		devices.query = func(ctx context.Context, call int) ([][6]byte, error) {
			if call == 1 {
				close(entered)
				<-release
			}
			return [][6]byte{testDeviceMAC, second}, nil
		}
		module := cronModule(t, "[Script]\njob=type=generic,script-path=job.js")
		e := cronTestEngine(t, module, map[string]string{"job": `$done();`}, 2)
		e.options.Devices, e.tasks.ctx = devices, t.Context()
		e.tasks.deviceQueryID = 1
		e.applyTaskDevices(taskDeviceResult{id: 1, err: errors.New("previous scan failed")})
		first, next := make(chan error, 1), make(chan error, 1)
		firstScope := ScriptScope{Kind: ScriptScopeDevice, MAC: testDeviceMAC}
		secondScope := ScriptScope{Kind: ScriptScopeDevice, MAC: second}
		firstCtx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go func() { first <- e.checkTaskDevice(firstCtx, firstScope) }()
		<-entered
		go func() { next <- e.checkTaskDevice(t.Context(), secondScope) }()
		synctest.Wait()
		cancel()
		if err := <-first; !errors.Is(err, context.Canceled) {
			t.Fatalf("first check: %v", err)
		}
		close(release)
		if err := <-next; err != nil {
			t.Fatal(err)
		}
		if e.tasks.lanQueryFailed {
			t.Fatal("successful recheck did not recover from the previous failure")
		}
		if calls := devices.calls.Load(); calls != 1 {
			t.Fatalf("concurrent checks started %d scans, want 1", calls)
		}
		if err := e.checkTaskDevice(t.Context(), secondScope); err != nil {
			t.Fatal(err)
		}
		e.tasks.running.Wait()
		if calls := devices.calls.Load(); calls != 2 {
			t.Fatalf("later check reused old scan: %d calls, want 2", calls)
		}
	})
}

func TestTaskDiscoveryDoesNotStartAfterCancellation(t *testing.T) {
	module := cronModule(t, "[Script]\njob=type=generic,script-path=job.js")
	e := cronTestEngine(t, module, map[string]string{"job": `$done();`}, 1)
	devices := &taskDiscoveryDevices{testDeviceService: newTestDevices(), query: func(context.Context, int) ([][6]byte, error) {
		return [][6]byte{testDeviceMAC}, nil
	}}
	e.options.Devices = devices
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := e.Run(ctx, http.DefaultClient); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if devices.calls.Load() != 0 || cronStatus(t, e, 0).State != "stopped" {
		t.Fatal("canceled worker started discovery")
	}
}

func TestTaskDiscoveryCloseJoinsQuery(t *testing.T) {
	module := cronModule(t, "[Script]\njob=type=generic,script-path=job.js")
	e := cronTestEngine(t, module, map[string]string{"job": `$done();`}, 1)
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	devices := &taskDiscoveryDevices{testDeviceService: newTestDevices()}
	devices.query = func(ctx context.Context, _ int) ([][6]byte, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return [][6]byte{testDeviceMAC}, nil
	}
	e.options.Devices = devices
	host, err := mitm.New(mitm.Options{HTTPClient: http.DefaultClient}, mitm.Instance{ID: "test", Type: "surge", Plugin: e})
	if err != nil {
		t.Fatal(err)
	}
	if err := host.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	defer close(release)
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- host.Close() }()
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("close did not cancel discovery")
	}
	select {
	case <-closed:
		t.Fatal("close returned before discovery cleanup")
	default:
	}
	release <- struct{}{}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if devices.active.Load() != 0 || len(e.slots) != 0 {
		t.Fatalf("discovery/slots leaked: %d/%d", devices.active.Load(), len(e.slots))
	}
	if status := cronStatus(t, e, 0); status.State != "stopped" || status.Runs != 0 || len(e.Status().Modules[0].Tasks) != 1 {
		t.Fatalf("late discovery result was applied after cancellation: %+v", status)
	}
}
