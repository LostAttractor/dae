// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

func TestCronManualLifecycle(t *testing.T) {
	runtimeFakeClockTest(t, func(t *testing.T) {
		m := cronModule(t, `[Script]
sign=type=cron,cronexp="* * * * * *",timeout=10,script-path=sign.js`)
		m.Name = "account"
		e := cronTestEngine(t, m, map[string]string{"sign": `
if ($trigger !== "http-api" || $script.type !== "cron" || $cronexp !== "* * * * * *") throw Error("wrong metadata");
$httpClient.get("https://cron.test/", (error) => { if(error) throw Error(error); $done(); });`}, 1)
		request := api.ScriptRunRequest{Module: "account", Script: "sign"}
		if _, err := e.TriggerScript(request); !errors.Is(err, plugin.ErrScriptInactive) {
			t.Fatalf("trigger before start: %v", err)
		}
		release := make(chan struct{})
		entered := make(chan struct{}, 2)
		canceled := make(chan struct{}, 1)
		client := &http.Client{Transport: runtimeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			entered <- struct{}{}
			select {
			case <-release:
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
			case <-r.Context().Done():
				canceled <- struct{}{}
				return nil, r.Context().Err()
			}
		})}
		host := startCronTestHost(t, e, client)
		next := cronStatus(t, e, 0).NextRun
		e.slots <- struct{}{}
		accepted, err := host.TriggerScript("test", request)
		if err != nil || accepted.Run != 1 || accepted.Instance != "test" || accepted.Module != "account" || accepted.Status.LastTrigger != "http-api" || accepted.Status.State != "waiting" || !accepted.Status.NextRun.Equal(next) {
			t.Fatalf("acceptance: %+v, %v", accepted, err)
		}
		synctest.Wait()
		if len(entered) != 0 {
			t.Fatal("manual run bypassed shared script slots")
		}
		if _, err := host.TriggerScript("test", request); !errors.Is(err, plugin.ErrScriptBusy) {
			t.Fatalf("overlapping trigger: %v", err)
		}
		<-e.slots
		synctest.Wait()
		time.Sleep(time.Until(next) + time.Millisecond)
		synctest.Wait()
		if status := cronStatus(t, e, 0); status.Runs != 1 || status.Skipped != 1 || status.State != "running" || len(entered) != 1 {
			t.Fatalf("scheduled tick overlapped manual execution: %+v", status)
		}
		release <- struct{}{}
		synctest.Wait()
		status := cronStatus(t, e, 0)
		if status.LastResult != "success" || status.Failures != 0 || status.State != "scheduled" || status.LastTrigger != "http-api" {
			t.Fatalf("manual result: %+v", status)
		}
		if _, err := host.TriggerScript("test", request); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if err := host.Close(); err != nil {
			t.Fatal(err)
		}
		status = cronStatus(t, e, 0)
		if len(canceled) != 1 || status.Runs != 2 || status.LastError != "canceled" || status.State != "stopped" || len(e.slots) != 0 {
			t.Fatalf("close did not cancel and join manual task: %+v", status)
		}
		if _, err := host.TriggerScript("test", request); !errors.Is(err, plugin.ErrScriptInactive) {
			t.Fatalf("host accepted work after close: %v", err)
		}
		if _, err := e.TriggerScript(request); !errors.Is(err, plugin.ErrScriptInactive) {
			t.Fatalf("worker accepted work after close: %v", err)
		}
	})
}

func TestTaskManualSelection(t *testing.T) {
	runtimeFakeClockTest(t, func(t *testing.T) {
		modules := make([]*Module, 2)
		for i, name := range []string{"first", "second"} {
			declaration := "type=cron,cronexp=0 0 31 2 *,"
			if i == 1 {
				declaration = "type=generic,"
			}
			modules[i] = cronModule(t, "[Script]\nsign="+declaration+"script-path=sign.js")
			modules[i].Name = name
			modules[i].TaskScripts[0].Source = `$persistentStore.write("yes", "ran"); $done();`
		}
		e := cronTestEngine(t, modules[0], map[string]string{"sign": modules[0].TaskScripts[0].Source}, 1)
		e.options.Modules = modules
		var err error
		e.tasks, err = newTaskRunner(e)
		if err != nil {
			t.Fatal(err)
		}
		host := startCronTestHost(t, e, http.DefaultClient)
		for _, test := range []struct {
			instance, module, script string
			err                      error
		}{
			{"absent", "first", "sign", plugin.ErrScriptNotFound},
			{"test", "absent", "sign", plugin.ErrScriptNotFound},
			{"test", "first", "absent", plugin.ErrScriptNotFound},
			{"test", "", "sign", plugin.ErrScriptAmbiguous},
		} {
			if _, err := host.TriggerScript(test.instance, api.ScriptRunRequest{Module: test.module, Script: test.script}); !errors.Is(err, test.err) {
				t.Fatalf("selection %+v: %v", test, err)
			}
		}
		response, err := host.TriggerScript("test", api.ScriptRunRequest{Module: "second", Script: "sign"})
		if err != nil || response.Module != "second" {
			t.Fatalf("qualified selection: %+v %v", response, err)
		}
		synctest.Wait()
		status := e.Status()
		if status.Modules[0].Tasks[0].Runs != 0 || status.Modules[1].Tasks[0].LastResult != "success" || status.Modules[1].Tasks[0].State != "ready" {
			t.Fatalf("wrong task ran: %+v", status.Modules)
		}
	})
}
