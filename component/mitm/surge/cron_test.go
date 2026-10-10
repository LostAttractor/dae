// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
	log "github.com/sirupsen/logrus"
)

func cronTestEngine(t *testing.T, module *Module, sources map[string]string, slots int) *Engine {
	t.Helper()
	for _, scripts := range [][]Script{module.Scripts, module.TaskScripts} {
		for i := range scripts {
			scripts[i].Source = sources[scripts[i].Name]
		}
	}
	rt, err := NewRuntime(t.Context(), RuntimeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rt.backend.Close)
	budget := membuffer.NewBudget(128 << 20)
	e, err := NewEngine(EngineOptions{Modules: []*Module{module}, Runtime: rt, BodyMemory: budget,
		MaxBodySize: 1 << 20, MaxConcurrentScripts: slots, ScriptTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if used := budget.Status().Used; used != 0 {
			t.Errorf("cron leaked body memory: %d", used)
		}
	})
	return e
}

func cronModule(t *testing.T, text string) *Module {
	t.Helper()
	m, err := Parse(text, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func cronStatus(t *testing.T, e *Engine, index int) api.ScriptTaskStatus {
	t.Helper()
	status := e.Status()
	if len(status.Modules) != 1 || len(status.Modules[0].Tasks) <= index {
		t.Fatalf("missing cron status: %+v", status)
	}
	return status.Modules[0].Tasks[index]
}

func startCronTestHost(t *testing.T, e *Engine, client *http.Client) *mitm.Host {
	t.Helper()
	h, err := mitm.New(mitm.Options{HTTPClient: client}, mitm.Instance{ID: "test", Type: "surge", Plugin: e})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	synctest.Wait()
	return h
}

func TestCronExpressionsAndParameters(t *testing.T) {
	zone := time.FixedZone("UTC+8", 8*60*60)
	for _, test := range []struct {
		expression, from, next string
	}{
		{"5 9 * * *", "2026-09-28 08:00:00", "2026-09-28 09:05:00"},
		{"5 9 * * *", "2026-09-28 09:05:00", "2026-09-29 09:05:00"},
		{"*/10 * * * * *", "2026-09-28 09:05:01", "2026-09-28 09:05:10"},
		{"0 5,17 * * mon-fri", "2026-09-28 09:05:00", "2026-09-28 17:00:00"},
		{"0 0 29 feb *", "2026-09-28 09:05:00", "2028-02-29 00:00:00"},
		{"0 0 1 * mon", "2026-09-29 09:05:00", "2026-10-01 00:00:00"},
	} {
		t.Run(test.expression+test.from, func(t *testing.T) {
			m := cronModule(t, `[Script]
签到=type=cron,cronexp="`+test.expression+`",timeout=60,script-path=youpin.js,argument="x,y",img-url=https://example.com/icon.png`)
			if len(m.Scripts) != 0 || len(m.TaskScripts) != 1 || len(m.Warnings) != 0 {
				t.Fatalf("cron parsed as HTTP or warned: %+v", m)
			}
			s := m.TaskScripts[0]
			from, err := time.ParseInLocation(time.DateTime, test.from, zone)
			if err != nil {
				t.Fatal(err)
			}
			if got := s.schedule.Next(from).Format(time.DateTime); got != test.next || s.Timeout != time.Minute || s.Argument != "x,y" {
				t.Fatalf("next=%s script=%+v", got, s)
			}
		})
	}
	// Unquoted expressions, as used by the original Youpin configuration.
	m := cronModule(t, "[Script]\nx=type=cron,cronexp=5 9 * * *,script-path=x.js")
	if m.TaskScripts[0].CronExp != "5 9 * * *" {
		t.Fatal(m.TaskScripts)
	}
	for _, expression := range []string{"", "* * * *", "* * * * * * *", "61 * * * * *", "0 24 * * *", "*/0 * * * *", "0 0 * bad *", "@every 1s", "CRON_TZ=UTC * * * * *"} {
		if _, err := Parse("[Script]\nx=type=cron,script-path=x.js,cronexp="+expression, nil); err == nil {
			t.Errorf("accepted invalid cron expression %q", expression)
		}
	}
}

func TestModuleRejectsDuplicateTaskNames(t *testing.T) {
	for _, kind := range []string{"generic", "cron,cronexp=* * * * *"} {
		source := "[Script]\njob=type=generic,script-path=a.js\njob=type=" + kind + ",script-path=b.js"
		if _, err := Parse(source, nil); err == nil || !strings.Contains(err.Error(), "duplicate task name") {
			t.Fatalf("accepted ambiguous task %q: %v", kind, err)
		}
		if module, err := Parse(source+",enable=false", nil); err != nil || len(module.TaskScripts) != 1 {
			t.Fatalf("disabled duplicate prevented loading: %+v %v", module, err)
		}
	}
}

func TestTasksLoadSharedScriptDependency(t *testing.T) {
	var downloads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/shared.js" {
			downloads.Add(1)
			_, _ = io.WriteString(w, "$done();")
			return
		}
		_, _ = io.WriteString(w, "[Script]\ncapture=type=http-request,pattern=.,script-path=shared.js\nsign=type=cron,cronexp=5 9 * * *,script-path=shared.js\nmanual=script-path=shared.js\ndisabled=type=generic,enable=false,script-path=missing.js")
	}))
	defer server.Close()
	m, err := Load(t.Context(), server.URL+"/module", server.Client(), LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if downloads.Load() != 1 || len(m.TaskScripts) != 2 || m.Scripts[0].Source != "$done();" || m.TaskScripts[0].Source != "$done();" || m.TaskScripts[1].Source != "$done();" || m.Status().Scripts != 3 {
		t.Fatalf("shared dependency: downloads=%d module=%+v", downloads.Load(), m)
	}
}

func TestCronActivationStatusAndSharedStore(t *testing.T) {
	runtimeFakeClockTest(t, func(t *testing.T) {
		m := cronModule(t, `[Script]
tick=type=cron,cronexp="* * * * * *",script-path=tick.js,argument=example`)
		e := cronTestEngine(t, m, map[string]string{"tick": `
if (typeof $request !== "undefined" || typeof $response !== "undefined") throw Error("HTTP globals leaked");
if ($script.type !== "cron" || $cronexp !== "* * * * * *" || $argument !== "example") throw Error("cron metadata missing");
if (typeof $trigger !== "undefined") throw Error("scheduled run received a manual trigger");
if (typeof previousRun !== "undefined") throw Error("VM reused");
globalThis.previousRun = true;
$persistentStore.write(String(Number($persistentStore.read("count") || "0") + 1), "count");
const ignored = {}; ignored.self = ignored; $done(ignored); $done({body:"ignored"});
`}, 1)
		before := cronStatus(t, e, 0)
		time.Sleep(3 * time.Second)
		count, err := e.options.Runtime.data.read(t.Context(), "count")
		if err != nil || before.State != "pending" || !before.NextRun.IsZero() || count != nil {
			t.Fatalf("cron ran before activation: %+v, count=%v, error=%v", before, count, err)
		}
		if plan := e.Plan(); !reflect.DeepEqual(plan, plugin.Plan{}) {
			t.Fatalf("cron-only module changed interception/routing: %+v", plan)
		}
		host := startCronTestHost(t, e, http.DefaultClient)
		first := cronStatus(t, e, 0).NextRun
		time.Sleep(time.Until(first) + 100*time.Millisecond)
		synctest.Wait()
		status := cronStatus(t, e, 0)
		if status.Runs != 1 || status.LastResult != "success" || status.LastTrigger != "cron" || status.State != "scheduled" || !status.LastStartedAt.Equal(first) || status.LastFinishedAt.Before(first) || !status.NextRun.Equal(first.Add(time.Second)) {
			t.Fatalf("first run status: %+v", status)
		}
		// Reports are snapshots; callers cannot mutate live scheduling state.
		snapshot := e.Status()
		snapshot.Modules[0].Tasks[0].State = "changed"
		time.Sleep(time.Second)
		synctest.Wait()
		count, err = e.options.Runtime.data.read(t.Context(), "count")
		if err != nil || count != "2" || cronStatus(t, e, 0).Runs != 2 {
			t.Fatalf("cron state or shared store was lost: count=%v, error=%v", count, err)
		}
		if err := host.Close(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		stopped := cronStatus(t, e, 0)
		if stopped.State != "stopped" || !stopped.NextRun.IsZero() || stopped.Runs != 2 || len(e.slots) != 0 {
			t.Fatalf("cron did not stop with host: %+v", stopped)
		}
	})
}

func TestCronSkipsOverlapAndCancelsRunningRequests(t *testing.T) {
	runtimeFakeClockTest(t, func(t *testing.T) {
		m := cronModule(t, `[Script]
slow=type=cron,cronexp="* * * * * *",timeout=10,script-path=slow.js`)
		e := cronTestEngine(t, m, map[string]string{"slow": `$httpClient.get("https://cron.test/", (error) => { if(error) throw Error(error); $done(); });`}, 1)
		entered, stopped := make(chan struct{}, 1), make(chan struct{}, 1)
		client := &http.Client{Transport: runtimeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			entered <- struct{}{}
			<-req.Context().Done()
			stopped <- struct{}{}
			return nil, req.Context().Err()
		})}
		host := startCronTestHost(t, e, client)
		first := cronStatus(t, e, 0).NextRun
		time.Sleep(time.Until(first) + 2500*time.Millisecond)
		synctest.Wait()
		status := cronStatus(t, e, 0)
		if len(entered) != 1 || status.Runs != 1 || status.Skipped != 2 || status.State != "running" {
			t.Fatalf("overlapping cron execution: %+v", status)
		}
		if err := host.Close(); err != nil {
			t.Fatal(err)
		}
		status = cronStatus(t, e, 0)
		if len(stopped) != 1 || status.State != "stopped" || status.LastError != "canceled" || len(e.slots) != 0 || e.options.BodyMemory.Status().Used != 0 {
			t.Fatalf("cron cleanup did not join HTTP request: %+v", status)
		}
	})
}

func TestCronTimeoutIncludesSharedSlotWait(t *testing.T) {
	runtimeFakeClockTest(t, func(t *testing.T) {
		m := cronModule(t, `[Script]
a=type=cron,cronexp="*/10 * * * * *",timeout=1.5,script-path=a.js
b=type=cron,cronexp="*/10 * * * * *",timeout=1.5,script-path=b.js`)
		e := cronTestEngine(t, m, map[string]string{"a": `$done();`, "b": `$done();`}, 1)
		e.slots <- struct{}{} // An existing HTTP/DNS script holds the shared slot.
		host := startCronTestHost(t, e, http.DefaultClient)
		first := cronStatus(t, e, 0).NextRun
		time.Sleep(time.Until(first) + 100*time.Millisecond)
		synctest.Wait()
		for i := range 2 {
			if status := cronStatus(t, e, i); status.State != "waiting" || status.Runs != 1 {
				t.Fatalf("cron bypassed slot admission: %+v", status)
			}
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		for i := range 2 {
			status := cronStatus(t, e, i)
			if status.LastError != "timeout" || status.Failures != 1 || status.LastDurationMS != 1500 {
				t.Fatalf("waiting cron ignored timeout: %+v", status)
			}
		}
		<-e.slots
		time.Sleep(time.Until(cronStatus(t, e, 0).NextRun) + time.Millisecond)
		synctest.Wait()
		for i := range 2 {
			if status := cronStatus(t, e, i); status.LastResult != "success" || status.Runs != 2 || status.Failures != 1 {
				t.Fatalf("cron failed to recover after slot timeout: %+v", status)
			}
		}
		_ = host.Close()
	})
}

func TestCronFailureStatusDoesNotExposeScriptData(t *testing.T) {
	for _, test := range []struct{ name, source, reason string }{
		{"exception", `throw Error("SECRET cookie or response");`, "error"},
		{"missing-done", `42;`, "timeout"},
		{"timeout", `setTimeout(() => $done(), 10000);`, "timeout"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtimeFakeClockTest(t, func(t *testing.T) {
				m := cronModule(t, `[Script]
job=type=cron,cronexp="*/10 * * * * *",timeout=0.1,script-path=job.js`)
				e := cronTestEngine(t, m, map[string]string{"job": test.source}, 1)
				host := startCronTestHost(t, e, http.DefaultClient)
				time.Sleep(time.Until(cronStatus(t, e, 0).NextRun) + time.Second)
				synctest.Wait()
				status := cronStatus(t, e, 0)
				if status.LastResult != "failed" || status.LastError != test.reason || status.Failures != 1 || status.Runs != 1 || status.State != "scheduled" {
					t.Fatalf("failure status: %+v", status)
				}
				encoded, err := json.Marshal(e.Report())
				if err != nil || strings.Contains(string(encoded), "SECRET") {
					t.Fatalf("unsafe report: %s (%v)", encoded, err)
				}
				_ = host.Close()
			})
		})
	}
}

func TestCronRequiresBackgroundClientAndHandlesImpossibleDates(t *testing.T) {
	m := cronModule(t, "[Script]\nx=type=cron,cronexp=0 0 31 2 *,script-path=x.js")
	e := cronTestEngine(t, m, map[string]string{"x": "$done();"}, 1)
	if err := e.Run(t.Context(), nil); err == nil || cronStatus(t, e, 0).LastError != "http_client_unavailable" {
		t.Fatalf("missing routed client silently used default transport: %v", err)
	}
	runtimeFakeClockTest(t, func(t *testing.T) {
		e := cronTestEngine(t, m, map[string]string{"x": "$done();"}, 1)
		host := startCronTestHost(t, e, http.DefaultClient)
		if status := cronStatus(t, e, 0); status.State != "unscheduled" || !status.NextRun.IsZero() {
			t.Fatalf("impossible schedule has a next run: %+v", status)
		}
		if err := e.Run(t.Context(), http.DefaultClient); err == nil {
			t.Fatal("started a second scheduler")
		}
		_ = host.Close()
	})
}

func TestTasksDoNotChangeExistingHTTPPlan(t *testing.T) {
	base := "[MITM]\nhostname=target.example:8443\n[Host]\n192.0.2.1=198.51.100.1\n"
	plain := cronTestEngine(t, cronModule(t, base), nil, 1)
	withTasks := cronTestEngine(t, cronModule(t, base+"[Script]\nx=type=cron,cronexp=5 9 * * *,script-path=x.js\ny=type=generic,script-path=x.js"), map[string]string{"x": "$done();", "y": "$done();"}, 1)
	if !reflect.DeepEqual(plain.Plan(), withTasks.Plan()) {
		t.Fatalf("tasks changed the HTTP or destination routing plan: %+v -> %+v", plain.Plan(), withTasks.Plan())
	}
}

// Set DAE_SURGE_YOUPIN_FIXTURES to the pinned upstream directory to verify the
// unchanged script's capture -> persistent store -> scheduled sign-in flow.
func TestYoupinCronCompatibility(t *testing.T) {
	dir := os.Getenv("DAE_SURGE_YOUPIN_FIXTURES")
	if dir == "" {
		t.Skip("set DAE_SURGE_YOUPIN_FIXTURES to a directory containing README.md and youpin.js")
	}
	readme, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(dir, "youpin.js"))
	if err != nil {
		t.Fatal(err)
	}
	_, section, _ := strings.Cut(string(readme), "## Surge")
	_, section, _ = strings.Cut(section, "```ini\n")
	section, _, _ = strings.Cut(section, "```")
	for _, encoding := range []string{"gzip", "deflate", "br"} {
		for _, mode := range []string{"scheduled", "manual"} {
			t.Run(encoding+"/"+mode, func(t *testing.T) {
				// regexp2 owns a process-wide real-time clock. Keep capture outside
				// the virtual-time bubble so it cannot leave a timer in that bubble.
				m := cronModule(t, section)
				if len(m.Scripts) != 1 || len(m.TaskScripts) != 1 {
					t.Fatalf("original module lost a script: %+v", m)
				}
				e := cronTestEngine(t, m, map[string]string{m.Scripts[0].Name: string(source), m.TaskScripts[0].Name: string(source)}, 1)
				var messages []string
				e.options.Runtime.opts.Logger = testSurgeLogger(func(entry *log.Entry) { messages = append(messages, entry.Message) })
				query := encodeRuntimeHTTPBody(t, []byte(`{"code":0,"data":{"signUserInfo":{"sign":false}}}`), encoding)
				signed := encodeRuntimeHTTPBody(t, []byte(`{"code":0,"data":{"amount":"0.15","msg":"签到成功！"}}`), encoding)
				var requests atomic.Int32
				client := &http.Client{Transport: runtimeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					n := requests.Add(1)
					path, response := "/mtop/act/redPacketSign/getActInfo", query
					if n == 2 {
						path, response = "/mtop/act/redPacketSign/clickSign", signed
					}
					if n > 2 || req.Method != "POST" || req.URL.Host != "m.xiaomiyoupin.com" || req.URL.Path != path || !strings.Contains(req.Header.Get("Cookie"), "serviceToken=fixture-token") {
						return nil, fmt.Errorf("unexpected scheduled request: %s %s", req.Method, req.URL)
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": {encoding}}, Body: io.NopCloser(strings.NewReader(string(response)))}, nil
				})}
				req := httptest.NewRequest("POST", "https://m.xiaomiyoupin.com/mtop/act/redPacketSign/getActInfo", nil)
				req.Header["Cookie"] = []string{"mjclient=YouPin", "serviceToken=fixture-token", "youpin_sessionid=fixture-session"}
				chain := e.Wrap(plugin.Flow{Host: "m.xiaomiyoupin.com", Port: 443}, func(exchange *plugin.Exchange) (*http.Response, error) {
					return &http.Response{StatusCode: 204, Request: exchange.Request, Header: make(http.Header), Body: http.NoBody}, nil
				})
				response, err := chain(&plugin.Exchange{Request: req, Client: client})
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if data, err := e.options.Runtime.data.read(t.Context(), "youpin_data"); err != nil || data == nil {
					t.Fatalf("capture did not populate persistent store: %v", err)
				}
				runtimeFakeClockTest(t, func(t *testing.T) {
					host, err := mitm.New(mitm.Options{Authority: &mitmca.Authority{}, HTTPClient: client}, mitm.Instance{ID: "youpin", Type: "surge", Plugin: e})
					if err != nil {
						t.Fatal(err)
					}
					defer host.Close()
					if err := host.Start(t.Context()); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					if mode == "manual" {
						if _, err := host.TriggerScript("youpin", api.ScriptRunRequest{Script: m.TaskScripts[0].Name}); err != nil {
							t.Fatal(err)
						}
					} else {
						time.Sleep(time.Until(cronStatus(t, e, 0).NextRun) + time.Second)
					}
					synctest.Wait()
					status := cronStatus(t, e, 0)
					if requests.Load() != 2 || status.Runs != 1 || status.LastResult != "success" || !strings.Contains(strings.Join(messages, "\n"), "✅ 签到成功") {
						t.Fatalf("scheduled Youpin sign-in failed: requests=%d status=%+v logs=%v", requests.Load(), status, messages)
					}
				})
			})
		}
	}
}

func TestCronCanceledBeforeActivation(t *testing.T) {
	m := cronModule(t, "[Script]\nx=type=cron,cronexp=* * * * * *,script-path=x.js")
	e := cronTestEngine(t, m, map[string]string{"x": "$done();"}, 1)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := e.Run(ctx, http.DefaultClient); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if status := cronStatus(t, e, 0); status.State != "stopped" || status.Runs != 0 {
		t.Fatalf("canceled activation ran a script: %+v", status)
	}
}
