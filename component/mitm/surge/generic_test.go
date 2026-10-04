// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

func TestGenericDeclarations(t *testing.T) {
	m := cronModule(t, `[Script]
explicit=type=generic,script-path=tool.js,argument="",timeout=2
implicit=script-path=tool.js
disabled=type=generic,enable=false,script-path=missing.js`)
	if len(m.Scripts) != 0 || len(m.TaskScripts) != 2 || len(m.Warnings) != 0 {
		t.Fatalf("unexpected generic declarations: %+v", m)
	}
	for _, script := range m.TaskScripts {
		if script.Type != "generic" || script.schedule != nil || script.CronExp != "" || script.pattern != nil {
			t.Fatalf("generic acquired type-specific requirements: %+v", script)
		}
	}
	if !m.TaskScripts[0].ArgumentSet || m.TaskScripts[0].Argument != "" || m.TaskScripts[0].Timeout != 2*time.Second || m.TaskScripts[1].ArgumentSet {
		t.Fatalf("lost common parameters: %+v", m.TaskScripts)
	}
	for _, declaration := range []string{"tool=type=generic", "tool=type=generic,script-path=x.js,timeout=0"} {
		if _, err := Parse("[Script]\n"+declaration, nil); err == nil {
			t.Fatalf("accepted invalid declaration: %s", declaration)
		}
	}
}

func TestGenericManualRuntime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := cronModule(t, "[Script]\ntool=script-path=tool.js,argument=demo")
		m.Name = "utilities"
		e := cronTestEngine(t, m, map[string]string{"tool": `
if ($script.type !== "generic" || $script.name !== "tool" || $trigger !== "http-api" || $argument !== "demo") throw Error("metadata");
for (const name of ["$request", "$response", "$domain", "$cronexp", "$input", "$intent"]) {
  if (name in globalThis) throw Error("unexpected input: " + name);
}
if (typeof previousRun !== "undefined") throw Error("VM reused");
globalThis.previousRun = true;
const previous = $persistentStore.read();
if (previous === $script.sessionID) throw Error("session reused");
$httpClient.get("https://generic.test/", (error, response, body) => {
  if (error || body !== "routed" || response.status !== 200) throw Error("HTTP client");
  if (!$persistentStore.write($script.sessionID)) throw Error("store");
  $notification.post("manual", $script.type, previous || "first");
  const ignored = {}; ignored.self = ignored; $done(ignored); $done("also ignored");
});`}, 1)
		request := api.ScriptRunRequest{Script: "tool"}
		if _, err := e.TriggerScript(request); !errors.Is(err, plugin.ErrScriptInactive) {
			t.Fatalf("accepted before activation: %v", err)
		}
		if before := cronStatus(t, e, 0); before.State != "pending" || before.Type != "generic" {
			t.Fatalf("pending status: %+v", before)
		}
		if plan := e.Plan(); !reflect.DeepEqual(plan, plugin.Plan{}) {
			t.Fatalf("generic-only module requires interception: %+v", plan)
		}
		calls := 0
		client := &http.Client{Transport: runtimeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.URL.String() != "https://generic.test/" {
				t.Errorf("unexpected request: %s", r.URL)
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("routed"))}, nil
		})}
		host := startCronTestHost(t, e, client)
		time.Sleep(24 * time.Hour)
		synctest.Wait()
		if status := cronStatus(t, e, 0); status.State != "ready" || status.Runs != 0 || calls != 0 || !status.NextRun.IsZero() || status.Timezone != "" || status.CronExp != "" {
			t.Fatalf("generic acquired a schedule: %+v, calls=%d", status, calls)
		}
		registry := surgeRegistry(t, e)
		for run := uint64(1); run <= 2; run++ {
			accepted, err := host.TriggerScript("test", request)
			if err != nil || accepted.Run != run || accepted.Module != "utilities" || accepted.Status.Type != "generic" || accepted.Status.State != "waiting" || !accepted.Status.NextRun.IsZero() {
				t.Fatalf("acceptance: %+v %v", accepted, err)
			}
			synctest.Wait()
			status := cronStatus(t, e, 0)
			if status.Runs != run || status.LastResult != "success" || status.Failures != 0 || status.State != "ready" || status.LastTrigger != "http-api" {
				t.Fatalf("manual completion: %+v", status)
			}
		}
		notifications := e.Status().Notifications
		if calls != 2 || len(notifications) != 2 || notifications[0].ScriptType != "generic" || notifications[0].Module != "utilities" || notifications[0].Body == "first" || notifications[1].Body != "first" {
			t.Fatalf("HTTP/store/notifications not shared across runs: calls=%d notifications=%+v", calls, notifications)
		}
		if got := surgeMetric(t, registry, "surge_scripts_total", map[string]string{"phase": "generic", "result": "success"}).GetCounter().GetValue(); got != 2 {
			t.Fatalf("generic metric = %v", got)
		}
		if err := host.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := host.TriggerScript("test", request); !errors.Is(err, plugin.ErrScriptInactive) {
			t.Fatalf("host accepted after close: %v", err)
		}
		if _, err := e.TriggerScript(request); !errors.Is(err, plugin.ErrScriptInactive) {
			t.Fatalf("worker accepted after close: %v", err)
		}
		if status := cronStatus(t, e, 0); status.State != "stopped" || status.Runs != 2 {
			t.Fatalf("stopped status: %+v", status)
		}
	})
}

func TestGenericAndCronShareAdmissionAndCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := cronModule(t, `[Script]
manual=type=generic,timeout=10,script-path=manual.js
timer=type=cron,cronexp="* * * * * *",timeout=10,script-path=timer.js`)
		e := cronTestEngine(t, m, map[string]string{
			"manual": `$persistentStore.write("shared", "value"); $httpClient.get("https://generic.test/", () => $done());`,
			"timer":  `if ($persistentStore.read("value") !== "shared") throw Error("store not shared"); $done();`,
		}, 1)
		release := make(chan struct{})
		canceled := make(chan struct{}, 1)
		client := &http.Client{Transport: runtimeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			select {
			case <-release:
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: http.NoBody}, nil
			case <-r.Context().Done():
				canceled <- struct{}{}
				return nil, r.Context().Err()
			}
		})}
		host := startCronTestHost(t, e, client)
		if _, err := host.TriggerScript("test", api.ScriptRunRequest{Script: "manual"}); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		time.Sleep(time.Until(cronStatus(t, e, 1).NextRun) + time.Millisecond)
		synctest.Wait()
		for i, state := range []string{"running", "waiting"} {
			status := cronStatus(t, e, i)
			if status.Runs != 1 || status.State != state {
				t.Fatalf("tasks bypassed shared slots: %+v", status)
			}
			if _, err := host.TriggerScript("test", api.ScriptRunRequest{Script: status.Name}); !errors.Is(err, plugin.ErrScriptBusy) {
				t.Fatalf("overlapping trigger: %v", err)
			}
		}
		release <- struct{}{}
		synctest.Wait()
		for i := range 2 {
			if status := cronStatus(t, e, i); status.LastResult != "success" {
				t.Fatalf("tasks did not share runtime/store: %+v", status)
			}
		}
		if _, err := host.TriggerScript("test", api.ScriptRunRequest{Script: "manual"}); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if _, err := host.TriggerScript("test", api.ScriptRunRequest{Script: "timer"}); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if err := host.Close(); err != nil {
			t.Fatal(err)
		}
		for i := range 2 {
			if status := cronStatus(t, e, i); status.State != "stopped" || status.LastError != "canceled" || status.Failures != 1 {
				t.Fatalf("shutdown did not join tasks: %+v", status)
			}
		}
		if len(canceled) != 1 || len(e.slots) != 0 {
			t.Fatalf("shutdown leaked requests or slots: canceled=%d slots=%d", len(canceled), len(e.slots))
		}
	})
}

func TestGenericTimeoutAndRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := cronModule(t, "[Script]\ntool=type=generic,timeout=0.1,script-path=tool.js")
		e := cronTestEngine(t, m, map[string]string{"tool": `if ($persistentStore.read("done")) $done();`}, 1)
		host := startCronTestHost(t, e, http.DefaultClient)
		request := api.ScriptRunRequest{Script: "tool"}
		for _, waiting := range []bool{true, false} {
			if waiting {
				e.slots <- struct{}{}
			}
			if _, err := host.TriggerScript("test", request); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			time.Sleep(200 * time.Millisecond)
			synctest.Wait()
			if status := cronStatus(t, e, 0); status.LastError != "timeout" || status.LastDurationMS != 100 || status.State != "ready" {
				t.Fatalf("timeout while waiting=%v: %+v", waiting, status)
			}
			if waiting {
				<-e.slots
			}
		}
		if !e.options.Runtime.data.write(t.Context(), "done", "yes", false) {
			t.Fatal("store write failed")
		}
		if _, err := host.TriggerScript("test", request); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if status := cronStatus(t, e, 0); status.LastResult != "success" || status.Runs != 3 || status.Failures != 2 || status.State != "ready" {
			t.Fatalf("task did not recover after timeout: %+v", status)
		}
	})
}
