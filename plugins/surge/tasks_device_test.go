// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"net"
	"net/http"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/internal/testutil"
)

func deviceTaskStatus(t *testing.T, e *Engine, mac [6]byte) api.ScriptTaskStatus {
	t.Helper()
	for _, status := range e.Status().Modules[0].Tasks {
		if status.MAC == net.HardwareAddr(mac[:]).String() {
			return status
		}
	}
	t.Fatalf("missing task for device %v", mac)
	return api.ScriptTaskStatus{}
}

func TestRemovedBusyTargetCompletion(t *testing.T) {
	for _, outcome := range []string{"removed", "reenabled", "discovery-failed"} {
		t.Run(outcome, func(t *testing.T) {
			runtimeFakeClockTest(t, func(t *testing.T) {
				m := cronModule(t, "[Script]\njob=type=generic,script-path=job.js")
				e := cronTestEngine(t, m, map[string]string{"job": `setTimeout(() => $done(), 1000);`}, 2)
				a, b := testDeviceMAC, [6]byte{2, 0, 0, 0, 0, 2}
				devices := newTestDevices(a, b)
				e.options.Devices = devices
				host := startCronTestHost(t, e, http.DefaultClient)
				trigger := func(mac [6]byte) error {
					_, err := host.TriggerScript(t.Context(), "test", api.ScriptRunRequest{Script: "job", MAC: net.HardwareAddr(mac[:]).String()})
					return err
				}
				if err := trigger(a); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				devices.set(b)
				if err := trigger(b); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				if status := deviceTaskStatus(t, e, a); status.State != "running" {
					t.Fatalf("removed active target was lost: %+v", status)
				}
				switch outcome {
				case "reenabled":
					devices.set(a, b)
					if err := trigger(a); !errors.Is(err, plugin.ErrScriptBusy) {
						t.Fatalf("reenabled active target: %v", err)
					}
				case "discovery-failed":
					devices.mu.Lock()
					devices.err = errors.New("discovery unavailable")
					devices.mu.Unlock()
					if err := trigger(b); !errors.Is(err, plugin.ErrScriptDeviceUnavailable) {
						t.Fatalf("discovery failure: %v", err)
					}
				}
				time.Sleep(2 * time.Second)
				synctest.Wait()
				found := false
				for _, status := range e.Status().Modules[0].Tasks {
					if status.MAC == testDeviceName {
						found = true
						if status.Runs != 1 || status.LastResult != "success" {
							t.Fatalf("completion changed: %+v", status)
						}
					}
				}
				if found != (outcome != "removed") {
					t.Fatalf("target retained=%t after %s", found, outcome)
				}
				if got := surgeMetric(t, surgeRegistry(t, e), "surge_scripts_total", map[string]string{"phase": "generic", "result": "success"}).GetCounter().GetValue(); got != 2 {
					t.Fatalf("target cleanup changed the completion count: %v", got)
				}
				if status := deviceTaskStatus(t, e, b); status.Runs != 1 || status.LastResult != "success" {
					t.Fatalf("enabled target changed: %+v", status)
				}
				if status := cronStatus(t, e, 0); status.Scope != "local" || status.State != "ready" {
					t.Fatalf("local target changed: %+v", status)
				}
			})
		})
	}
}

func TestManualTaskDeviceSelectionAndQueuedDisable(t *testing.T) {
	runtimeFakeClockTest(t, func(t *testing.T) {
		m := cronModule(t, "[Script]\njob=type=generic,script-path=job.js")
		e := cronTestEngine(t, m, map[string]string{"job": `$persistentStore.write("ran", "task"); $done();`}, 1)
		devices := newTestDevices()
		e.options.Devices = devices
		host := startCronTestHost(t, e, http.DefaultClient)
		trigger := func(mac string) error {
			_, err := host.TriggerScript(t.Context(), "test", api.ScriptRunRequest{Script: "job", MAC: mac})
			return err
		}
		if status := cronStatus(t, e, 0); status.State != "ready" || status.Scope != "local" || status.MAC != "" || status.Runs != 0 {
			t.Fatalf("local task without LAN devices: %+v", status)
		}
		if err := trigger(""); err != nil {
			t.Fatalf("local execution without LAN devices: %v", err)
		}
		synctest.Wait()
		if err := trigger("bad"); !errors.Is(err, plugin.ErrScriptDeviceInvalid) {
			t.Fatalf("invalid MAC: %v", err)
		}
		a, b := testDeviceMAC, [6]byte{2, 0, 0, 0, 0, 2}
		bName := net.HardwareAddr(b[:]).String()
		devices.set(a, b, a)
		if err := trigger(""); err != nil {
			t.Fatalf("local execution with multiple devices: %v", err)
		}
		synctest.Wait()
		if status := cronStatus(t, e, 0); status.Scope != "local" || status.Runs != 2 {
			t.Fatalf("default execution selected a LAN device: %+v", status)
		}
		e.slots <- struct{}{}
		if err := trigger(testDeviceName); err != nil {
			t.Fatal(err)
		}
		if err := trigger(testDeviceName); !errors.Is(err, plugin.ErrScriptBusy) {
			t.Fatalf("same device overlap accepted: %v", err)
		}
		if err := trigger(bName); err != nil {
			t.Fatalf("A blocked B: %v", err)
		}
		synctest.Wait()
		if aStatus, bStatus := deviceTaskStatus(t, e, a), deviceTaskStatus(t, e, b); aStatus.State != "waiting" || bStatus.State != "waiting" || aStatus.Runs != 1 || bStatus.Runs != 1 {
			t.Fatalf("device admission: A=%+v B=%+v", aStatus, bStatus)
		}
		devices.set(b)
		<-e.slots
		synctest.Wait()
		if got, err := e.options.Runtime.data.read(t.Context(), testMACScope(a), "task"); err != nil || got != nil {
			t.Fatalf("disabled queued device executed: %v %v", got, err)
		}
		if status := deviceTaskStatus(t, e, a); status.LastResult != "skipped" || status.LastError != "device_disabled" {
			t.Fatalf("disabled queue result: %+v", status)
		}
		if got, err := e.options.Runtime.data.read(t.Context(), testMACScope(b), "task"); err != nil || got != "ran" {
			t.Fatalf("enabled device did not execute: %v %v", got, err)
		}
		if err := trigger(testDeviceName); !errors.Is(err, plugin.ErrScriptDeviceDisabled) {
			t.Fatalf("explicit disabled device accepted: %v", err)
		}
		if err := trigger(""); err != nil {
			t.Fatalf("local execution with one device: %v", err)
		}
		synctest.Wait()
		if status := deviceTaskStatus(t, e, b); status.Runs != 1 || status.LastResult != "success" {
			t.Fatalf("single device was implicitly selected: %+v", status)
		}
		if status := cronStatus(t, e, 0); status.Scope != "local" || status.Runs != 3 || status.LastResult != "success" {
			t.Fatalf("local completion: %+v", status)
		}
	})
}

func TestTaskRevalidationClassifiesOwnCancellation(t *testing.T) {
	for _, reason := range []string{"timeout", "canceled", "device_query_failed"} {
		t.Run(reason, func(t *testing.T) {
			runtimeFakeClockTest(t, func(t *testing.T) {
				module := cronModule(t, "[Script]\njob=type=generic,timeout=1,script-path=job.js")
				e := cronTestEngine(t, module, map[string]string{"job": `$done();`}, 1)
				a, b := testDeviceMAC, [6]byte{2, 0, 0, 0, 0, 2}
				entered := make(chan struct{})
				devices := &taskDiscoveryDevices{testDeviceService: newTestDevices(a, b)}
				devices.query = func(ctx context.Context, call int) ([][6]byte, error) {
					if call == 3 {
						close(entered)
						switch reason {
						case "timeout":
							select {
							case <-time.After(10 * time.Millisecond):
								return [][6]byte{a, b}, nil
							case <-ctx.Done():
							}
						case "canceled":
							<-ctx.Done()
						}
						return nil, errors.New("device query failed")
					}
					return [][6]byte{a, b}, nil
				}
				e.options.Devices = devices
				host := startCronTestHost(t, e, http.DefaultClient)
				registry := surgeRegistry(t, e)
				e.slots <- struct{}{}
				if _, err := host.TriggerScript(t.Context(), "test", api.ScriptRunRequest{Script: "job", MAC: testDeviceName}); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				time.Sleep(995 * time.Millisecond)
				<-e.slots
				<-entered
				if reason == "canceled" {
					host.StopWorkers()
				} else if reason == "timeout" {
					time.Sleep(20 * time.Millisecond)
				}
				synctest.Wait()
				first, second := deviceTaskStatus(t, e, a), deviceTaskStatus(t, e, b)
				result, otherState, failures, skipped := "failed", "ready", uint64(1), uint64(0)
				if reason == "device_query_failed" {
					result, otherState, failures, skipped = "skipped", "unavailable", 0, 1
				} else if reason == "canceled" {
					otherState = "stopped"
				}
				if first.Runs != 1 || first.LastResult != result || first.LastError != reason || first.Failures != failures || first.Skipped != skipped || second.State != otherState || second.Runs != 0 {
					t.Fatalf("revalidation result: selected=%+v unrelated=%+v", first, second)
				}
				e.tasks.mu.Lock()
				failed, enabled := e.tasks.lanQueryFailed, e.tasks.enabled[b]
				e.tasks.mu.Unlock()
				if failed != (reason == "device_query_failed") || enabled == failed {
					t.Fatalf("wrong instance health: failed=%v other_enabled=%v", failed, enabled)
				}
				if got := surgeMetric(t, registry, "surge_scripts_total", map[string]string{"phase": "generic", "result": "skipped"}).GetCounter().GetValue(); got != 1 {
					t.Fatalf("non-executed JS outcome changed: %v", got)
				}
				if reason != "canceled" {
					for _, mac := range []string{net.HardwareAddr(b[:]).String(), testDeviceName} {
						if _, err := host.TriggerScript(t.Context(), "test", api.ScriptRunRequest{Script: "job", MAC: mac}); err != nil {
							t.Fatalf("recovery trigger: %v", err)
						}
						synctest.Wait()
					}
					if first, second := deviceTaskStatus(t, e, a), deviceTaskStatus(t, e, b); first.LastResult != "success" || first.Runs != 2 || first.Failures != failures || second.LastResult != "success" || len(e.Status().Modules[0].Warnings) != 0 {
						t.Fatalf("device discovery did not recover: selected=%+v unrelated=%+v", first, second)
					}
				}
			})
		})
	}
}

func TestTaskCompletionResultsMatchOpenAPI(t *testing.T) {
	results := testutil.LoadSchemas(t, "../../docs/api/openapi.json")["ScriptTaskStatus"].Properties["last_result"].Enum
	for _, result := range []string{"success", "failed", "skipped"} {
		t.Run(result, func(t *testing.T) {
			runtimeFakeClockTest(t, func(t *testing.T) {
				module := cronModule(t, "[Script]\njob=type=generic,script-path=job.js")
				source := `$done();`
				if result == "failed" {
					source = `throw Error("task failed");`
				}
				e := cronTestEngine(t, module, map[string]string{"job": source}, 1)
				devices := newTestDevices(testDeviceMAC)
				e.options.Devices = devices
				host := startCronTestHost(t, e, http.DefaultClient)
				e.slots <- struct{}{}
				if _, err := host.TriggerScript(t.Context(), "test", api.ScriptRunRequest{Script: "job", MAC: testDeviceName}); err != nil {
					t.Fatal(err)
				}
				if result == "skipped" {
					devices.set()
				}
				<-e.slots
				synctest.Wait()
				status := deviceTaskStatus(t, e, testDeviceMAC)
				if status.Runs != 1 || status.LastFinishedAt.IsZero() || status.LastResult != result || result == "skipped" && status.LastError != "device_disabled" {
					t.Fatalf("task did not finish with %s: %+v", result, status)
				}
				if !slices.Contains(results, any(status.LastResult)) {
					t.Fatalf("actual last_result %q is absent from public enum %v", status.LastResult, results)
				}
			})
		})
	}
}

func TestCronDeviceQueryFailureDoesNotReuseTargets(t *testing.T) {
	runtimeFakeClockTest(t, func(t *testing.T) {
		m := cronModule(t, "[Script]\njob=type=cron,cronexp=* * * * * *,script-path=job.js")
		e := cronTestEngine(t, m, map[string]string{"job": `$done();`}, 1)
		devices := e.options.Devices.(*testDeviceService)
		devices.set(testDeviceMAC)
		startCronTestHost(t, e, http.DefaultClient)
		devices.mu.Lock()
		devices.err = errors.New("neighbor query failed")
		devices.mu.Unlock()
		time.Sleep(time.Until(cronStatus(t, e, 0).NextRun) + time.Millisecond)
		synctest.Wait()
		if status := deviceTaskStatus(t, e, testDeviceMAC); status.Runs != 0 || status.State != "unavailable" || status.LastError != "device_query_failed" {
			t.Fatalf("query failure reused old targets or was hidden: %+v", status)
		}
		if status := cronStatus(t, e, 0); status.Scope != "local" || status.Runs != 1 || status.LastResult != "success" || status.LastError != "" || status.NextRun.IsZero() {
			t.Fatalf("LAN query failure poisoned local status: %+v", status)
		}
		devices.mu.Lock()
		devices.err = nil
		devices.mu.Unlock()
		time.Sleep(time.Second)
		synctest.Wait()
		if status := deviceTaskStatus(t, e, testDeviceMAC); status.Runs != 1 || status.State != "scheduled" || status.LastResult != "success" || status.LastError != "" {
			t.Fatalf("query did not recover: %+v", status)
		}
	})
}

func TestCronUsesCurrentEnabledDevicesNotStoredCredentials(t *testing.T) {
	runtimeFakeClockTest(t, func(t *testing.T) {
		m := cronModule(t, "[Script]\njob=type=cron,cronexp=* * * * * *,script-path=job.js")
		e := cronTestEngine(t, m, map[string]string{"job": `
const count=Number($persistentStore.read("count") || 0)+1;
$persistentStore.write(String(count), "count");
if ($persistentStore.read("slow")) setTimeout(() => $done(), 4000); else $done();`}, 2)
		a, b, disabled := testDeviceMAC, [6]byte{2, 0, 0, 0, 0, 2}, [6]byte{2, 0, 0, 0, 0, 3}
		devices := newTestDevices(a, b)
		e.options.Devices = devices
		if !e.options.Runtime.data.write(t.Context(), testMACScope(a), "slow", "yes", false) || !e.options.Runtime.data.write(t.Context(), testMACScope(disabled), "cookie", "private", false) {
			t.Fatal("seed")
		}
		host := startCronTestHost(t, e, http.DefaultClient)
		first := cronStatus(t, e, 0).NextRun
		time.Sleep(time.Until(first) + 2100*time.Millisecond)
		synctest.Wait()
		aStatus, bStatus := deviceTaskStatus(t, e, a), deviceTaskStatus(t, e, b)
		if aStatus.Runs != 1 || aStatus.Skipped != 2 || aStatus.State != "running" || bStatus.Runs != 3 || bStatus.LastResult != "success" {
			t.Fatalf("device-local overlap: A=%+v B=%+v", aStatus, bStatus)
		}
		if got, err := e.options.Runtime.data.read(t.Context(), testMACScope(disabled), "count"); err != nil || got != nil {
			t.Fatalf("stored cookie made disabled device eligible: %v %v", got, err)
		}
		devices.set()
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if status := cronStatus(t, e, 0); status.State != "scheduled" || status.Scope != "local" || status.MAC != "" || status.Runs != 6 {
			t.Fatalf("local task stopped with LAN devices: %+v", status)
		}
		if got, err := e.options.Runtime.data.read(t.Context(), testMACScope(b), "count"); err != nil || got != "3" {
			t.Fatalf("disabled device ran again: %v %v", got, err)
		}
		if err := host.Close(); err != nil || len(e.slots) != 0 {
			t.Fatalf("slots leaked: %v %d", err, len(e.slots))
		}
	})
}
