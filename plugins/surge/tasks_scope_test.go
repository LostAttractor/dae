// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

func TestTaskScriptIsolationOverrides(t *testing.T) {
	for _, instance := range []bool{false, true} {
		t.Run(fmt.Sprint(instance), func(t *testing.T) {
			runtimeFakeClockTest(t, func(t *testing.T) {
				m := cronModule(t, `[Script]
inherited=type=cron,cronexp=* * * * * *,script-path=inherited.js
isolated=type=cron,cronexp=* * * * * *,script-path=isolated.js
shared=type=cron,cronexp=* * * * * *,script-path=shared.js`)
				if err := applyModuleIsolation(m, ModuleSource{ScriptIsolation: map[string]bool{"isolated": true, "shared": false}}); err != nil {
					t.Fatal(err)
				}
				for i := range m.TaskScripts {
					m.TaskScripts[i].Source = `const key=$script.name; $persistentStore.write(String(Number($persistentStore.read(key)||0)+1),key); $done();`
				}
				runtime, err := NewRuntime(t.Context(), RuntimeOptions{})
				if err != nil {
					t.Fatal(err)
				}
				a, b := testDeviceMAC, [6]byte{2, 0, 0, 0, 0, 2}
				e := newTestEngine(t, EngineOptions{Modules: []*Module{m}, Runtime: runtime, Devices: newTestDevices(a, b), IsolateLAN: instance})
				startCronTestHost(t, e, http.DefaultClient)
				time.Sleep(time.Until(cronStatus(t, e, 0).NextRun) + time.Millisecond)
				synctest.Wait()
				counts := make(map[string]int)
				for _, status := range e.Status().Modules[0].Tasks {
					counts[status.Name]++
					if status.Runs != 1 || status.LastResult != "success" {
						t.Fatalf("task scope did not execute once: %+v", status)
					}
				}
				inherited := 1
				if instance {
					inherited = 3
				}
				if counts["inherited"] != inherited || counts["isolated"] != 3 || counts["shared"] != 1 {
					t.Fatalf("instance=%t target counts=%v", instance, counts)
				}
				for _, scope := range []ScriptScope{testLocalScope, testMACScope(a), testMACScope(b)} {
					for name, isolated := range map[string]bool{"inherited": instance, "isolated": true, "shared": false} {
						var want any
						if scope.Kind == ScriptScopeLocal || isolated {
							want = "1"
						}
						if value, err := runtime.data.read(t.Context(), scope, name); err != nil || value != want {
							t.Fatalf("script=%s scope=%+v value=%v want=%v error=%v", name, scope, value, want, err)
						}
					}
				}
			})
		})
	}
}

func TestSharedTasksNeverQueryLAN(t *testing.T) {
	runtimeFakeClockTest(t, func(t *testing.T) {
		m := cronModule(t, `[Script]
job=type=cron,cronexp=* * * * * *,script-path=job.js
manual=type=generic,script-path=manual.js`)
		if err := applyModuleIsolation(m, ModuleSource{IsolateLANSet: true, IsolateLAN: false}); err != nil {
			t.Fatal(err)
		}
		source := `const key=$script.name; $persistentStore.write(String(Number($persistentStore.read(key)||0)+1),key); $done();`
		e := cronTestEngine(t, m, map[string]string{"job": source, "manual": source}, 1)
		devices := newTestDevices(testDeviceMAC, [6]byte{2, 0, 0, 0, 0, 2})
		devices.err = errors.New("LAN unavailable")
		e.options.Devices = devices
		host := startCronTestHost(t, e, http.DefaultClient)
		if _, err := host.TriggerScript(t.Context(), "test", api.ScriptRunRequest{Script: "manual", MAC: testDeviceName}); !errors.Is(err, plugin.ErrScriptDeviceUnsupported) {
			t.Fatalf("shared script accepted explicit device: %v", err)
		}
		accepted, err := host.TriggerScript(t.Context(), "test", api.ScriptRunRequest{Script: "manual"})
		if err != nil || accepted.Status.Scope != "local" || accepted.Status.MAC != "" {
			t.Fatalf("shared manual target: %+v %v", accepted, err)
		}
		synctest.Wait()
		time.Sleep(time.Until(cronStatus(t, e, 0).NextRun) + 1100*time.Millisecond)
		synctest.Wait()
		if status := cronStatus(t, e, 0); status.Runs != 2 || status.LastResult != "success" || status.Scope != "local" {
			t.Fatalf("shared cron did not execute exactly once per tick: %+v", status)
		}
		devices.mu.Lock()
		queries := devices.queries
		devices.mu.Unlock()
		if queries != 0 {
			t.Fatalf("shared tasks queried LAN %d times", queries)
		}
		if value, err := e.options.Runtime.data.read(t.Context(), testLocalScope, "job"); err != nil || value != "2" {
			t.Fatalf("shared scope ran repeatedly per LAN target: %v %v", value, err)
		}
	})
}

func TestLocalTasksSurviveUnavailableLAN(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(fmt.Sprint(unavailable), func(t *testing.T) {
			runtimeFakeClockTest(t, func(t *testing.T) {
				m := cronModule(t, "[Script]\njob=type=cron,cronexp=* * * * * *,script-path=job.js")
				e := cronTestEngine(t, m, map[string]string{"job": `$persistentStore.write("ok", "local"); $done();`}, 1)
				devices := newTestDevices()
				if unavailable {
					devices.err = errors.New("LAN unavailable")
					e.options.Devices = devices
				} else {
					e.options.Devices = nil
				}
				host := startCronTestHost(t, e, http.DefaultClient)
				if unavailable {
					if _, err := host.TriggerScript(t.Context(), "test", api.ScriptRunRequest{Script: "job", MAC: testDeviceName}); !errors.Is(err, plugin.ErrScriptDeviceUnavailable) {
						t.Fatalf("missing discovery error: %v", err)
					}
				}
				if _, err := host.TriggerScript(t.Context(), "test", api.ScriptRunRequest{Script: "job"}); err != nil {
					t.Fatalf("LAN outage blocked local manual run: %v", err)
				}
				synctest.Wait()
				time.Sleep(time.Until(cronStatus(t, e, 0).NextRun) + time.Millisecond)
				synctest.Wait()
				status := e.Status().Modules[0]
				if len(status.Tasks) != 1 || status.Tasks[0].Scope != "local" || status.Tasks[0].Runs != 2 || status.Tasks[0].LastResult != "success" || status.Tasks[0].LastError != "" {
					t.Fatalf("LAN outage affected local task: %+v", status)
				}
				if unavailable && (len(status.Warnings) != 1 || !strings.Contains(status.Warnings[0], "device_query_failed")) {
					t.Fatalf("LAN query failure without targets was hidden: %+v", status)
				}
				if unavailable {
					devices.mu.Lock()
					devices.err = nil
					devices.mu.Unlock()
					devices.set(testDeviceMAC)
					time.Sleep(time.Second)
					synctest.Wait()
					status = e.Status().Modules[0]
					if len(status.Warnings) != 0 || len(status.Tasks) != 2 || status.Tasks[0].Runs != 3 || status.Tasks[1].Runs != 1 {
						t.Fatalf("LAN recovery lost local history or retained warning: %+v", status)
					}
				}
			})
		})
	}
}
