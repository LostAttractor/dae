// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"unicode/utf8"

	"github.com/daeuniverse/dae/api"
	localca "github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/plugin"
	surgeapi "github.com/daeuniverse/dae/plugins/surge/api"
	dns "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

func TestRuntimeNotificationsSurviveScriptFailureAndLogFiltering(t *testing.T) {
	var logs strings.Builder
	logger := log.New()
	logger.SetOutput(&logs)
	logger.SetLevel(log.ErrorLevel)
	runtime := testRuntime(t, RuntimeOptions{Logger: log.NewEntry(logger)})
	_, err := runtime.Run(t.Context(), `
console.log("ordinary log");
$script.name = "spoofed";
$notification.post("签到成功", "账户一", "余额 1.2\n明日继续", {url:"https://example.test/"});
throw Error("after notification");`, Invocation{Scope: ScriptScope{Kind: ScriptScopeLocal}, ModuleName: "account", ScriptName: "sign", ScriptType: "cron"})
	if err == nil || logs.Len() != 0 {
		t.Fatalf("script failure/log filtering changed: %v logs=%s", err, &logs)
	}
	recent := runtime.notifications.snapshot()
	if len(recent) != 1 {
		t.Fatalf("notification was lost or console log became a notification: %+v", recent)
	}
	notification := recent[0]
	if notification.Scope != "local" || notification.MAC != "" || notification.ID != 1 || notification.CreatedAt.IsZero() || notification.Module != "account" || notification.Script != "sign" || notification.ScriptType != "cron" || notification.Title != "签到成功" || notification.Subtitle != "账户一" || notification.Body != "余额 1.2\n明日继续" || notification.Truncated {
		t.Fatalf("lost notification fields or trusted script-modified metadata: %+v", notification)
	}
	recent[0].Body = "mutated report"
	if runtime.notifications.snapshot()[0].Body != notification.Body {
		t.Fatal("snapshot shares mutable entries with runtime")
	}
}

func TestRuntimeNotificationsBoundedAndUTF8(t *testing.T) {
	runtime := testRuntime(t, RuntimeOptions{})
	_, err := runtime.Run(t.Context(), fmt.Sprintf(`
for (let i = 0; i < %d; i++) $notification.post(String(i), "", "body");
$notification.post("中".repeat(1000), "文".repeat(1000), "🙂".repeat(2000));
$done();`, maxScriptNotifications+5), Invocation{ScriptName: "bounded", ScriptType: "cron"})
	if err != nil {
		t.Fatal(err)
	}
	recent := runtime.notifications.snapshot()
	if len(recent) != maxScriptNotifications || recent[0].ID != maxScriptNotifications+6 || recent[len(recent)-1].ID != 7 || recent[1].Title != fmt.Sprint(maxScriptNotifications+4) {
		t.Fatalf("history not bounded/newest-first: %+v", recent)
	}
	first := recent[0]
	if !first.Truncated || !utf8.ValidString(first.Title+first.Subtitle+first.Body) || len(first.Title) > maxNotificationText || len(first.Subtitle) > maxNotificationText || len(first.Body) != maxNotificationBody {
		t.Fatalf("invalid text truncation: title=%d subtitle=%d body=%d truncated=%v", len(first.Title), len(first.Subtitle), len(first.Body), first.Truncated)
	}
	for i := 1; i < len(recent); i++ {
		if recent[i].ID+1 != recent[i-1].ID || recent[i].CreatedAt.After(recent[i-1].CreatedAt) {
			t.Fatal("history reordered arrivals")
		}
	}
}

func TestRuntimeNotificationsConcurrentSnapshots(t *testing.T) {
	runtime := testRuntime(t, RuntimeOptions{})
	var workers sync.WaitGroup
	for i := range 8 {
		workers.Go(func() {
			_, err := runtime.Run(t.Context(), `for(let i=0;i<20;i++) $notification.post("title", "", "body"); $done();`, Invocation{ModuleName: fmt.Sprint(i % 2), ScriptName: "parallel", ScriptType: "cron"})
			if err != nil {
				t.Error(err)
			}
		})
	}
	workers.Go(func() {
		for range 100 {
			for _, item := range runtime.notifications.snapshot() {
				if item.ID == 0 || item.Body != "body" || item.Script != "parallel" {
					t.Errorf("partial notification snapshot: %+v", item)
				}
			}
		}
	})
	workers.Wait()
	recent := runtime.notifications.snapshot()
	if len(recent) != 2*maxScriptNotifications || recent[0].ID != 160 {
		t.Fatalf("concurrent notifications lost: %+v", recent)
	}
	counts := make(map[string]int)
	for _, item := range recent {
		counts[item.Module]++
	}
	if counts["0"] != maxScriptNotifications || counts["1"] != maxScriptNotifications {
		t.Fatalf("one script consumed another script's history: %v", counts)
	}
}

func TestRuntimeNotificationRetentionIsPerScript(t *testing.T) {
	runtime := testRuntime(t, RuntimeOptions{})
	quiet := []Invocation{
		{ModuleName: "account", ScriptName: "other", ScriptType: "cron"},
		{ModuleName: "other", ScriptName: "busy", ScriptType: "cron"},
		{ModuleName: "account", ScriptName: "busy", ScriptType: "http-request"},
	}
	for _, invocation := range quiet {
		if _, err := runtime.Run(t.Context(), `$notification.post("quiet", "", "keep me"); $done();`, invocation); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := runtime.Run(t.Context(), fmt.Sprintf(`for(let i=0;i<%d;i++) $notification.post(String(i), "", "busy"); $done();`, maxScriptNotifications+10),
		Invocation{ModuleName: "account", ScriptName: "busy", ScriptType: "cron"}); err != nil {
		t.Fatal(err)
	}
	recent := runtime.notifications.snapshot()
	if len(recent) != maxScriptNotifications+len(quiet) {
		t.Fatalf("high-volume script evicted other scripts: %d notifications", len(recent))
	}
	for i, item := range recent {
		if i > 0 && item.ID >= recent[i-1].ID {
			t.Fatal("merged histories lost newest-first arrival order")
		}
		if i < maxScriptNotifications {
			if item.Body != "busy" || item.Title != fmt.Sprint(maxScriptNotifications+9-i) {
				t.Fatalf("per-script ring retained wrong entries: %+v", item)
			}
		} else {
			invocation := quiet[len(recent)-1-i]
			if item.Body != "keep me" || item.Module != invocation.ModuleName || item.Script != invocation.ScriptName || item.ScriptType != invocation.ScriptType {
				t.Fatalf("another script's notification was lost: %+v", item)
			}
		}
	}
}

func TestNotificationHistorySeparatesScopes(t *testing.T) {
	var history notificationHistory
	identities := []surgeapi.SurgeNotification{
		{Scope: "local"},
		{Scope: "unknown"},
		{Scope: "device", MAC: "02:00:00:00:00:50"},
		{Scope: "device", MAC: "02:00:00:00:00:51"},
	}
	for _, identity := range identities {
		for i := range maxScriptNotifications + 5 {
			identity.Module, identity.Script, identity.ScriptType, identity.Title = "account", "job", "generic", fmt.Sprint(i)
			history.add(identity)
		}
	}
	counts := make(map[[2]string]int)
	for _, n := range history.snapshot() {
		counts[[2]string{n.Scope, n.MAC}]++
		if n.Title == "0" {
			t.Fatal("scope history retained an expired entry")
		}
	}
	for _, identity := range identities {
		if counts[[2]string{identity.Scope, identity.MAC}] != maxScriptNotifications {
			t.Fatalf("scope histories evicted each other: %v", counts)
		}
		if notificationBytes(identity)-notificationBytes(surgeapi.SurgeNotification{}) != 6*(len(identity.Scope)+len(identity.MAC)) {
			t.Fatal("notification budget omitted scope or MAC bytes")
		}
	}
}

func TestNotificationInstanceBudgetKeepsStatusBounded(t *testing.T) {
	var history notificationHistory
	history.add(surgeapi.SurgeNotification{Scope: "local", Script: "quiet", Body: "keep me"})
	for i := range 180 {
		for range maxScriptNotifications {
			history.add(surgeapi.SurgeNotification{Scope: "device", MAC: fmt.Sprintf("02:00:00:00:00:%02x", i), Module: "module", Script: "job", ScriptType: "generic",
				Title: strings.Repeat("\x00", maxNotificationText), Body: strings.Repeat("\x00", maxNotificationBody)})
		}
	}
	notifications := history.snapshot()
	encoded, err := json.Marshal(surgeapi.SurgeStatus{Enabled: true, Notifications: notifications})
	if err != nil || len(encoded) > maxNotificationHistory {
		t.Fatalf("notification status exceeds instance budget: bytes=%d err=%v", len(encoded), err)
	}
	for i, n := range notifications {
		if i > 0 && n.ID >= notifications[i-1].ID {
			t.Fatal("budget eviction changed arrival order")
		}
	}
	// An instance with more single-entry histories than its byte budget may
	// evict quiet entries too; a busy script alone must not do so.
	var isolated notificationHistory
	isolated.add(surgeapi.SurgeNotification{Scope: "local", Script: "quiet", Body: "keep me"})
	for range maxScriptNotifications * 2 {
		isolated.add(surgeapi.SurgeNotification{Scope: "local", Script: "busy", Body: strings.Repeat("x", maxNotificationBody)})
	}
	quiet := false
	for _, n := range isolated.snapshot() {
		quiet = quiet || n.Script == "quiet"
	}
	if !quiet {
		t.Fatal("busy script evicted a quieter script before trimming its own history")
	}
}

func TestSurgeNotificationsSharedAcrossHTTPDNSAndCron(t *testing.T) {
	module := cronModule(t, `[MITM]
hostname=notify.test
[Host]
notify.test=script:query
[Script]
request=type=http-request,pattern=.,script-path=request.js
response=type=http-response,pattern=.,script-path=response.js
query=type=dns,script-path=query.js
job=type=cron,cronexp="0 0 31 2 *",script-path=job.js`)
	if err := applyModuleIsolation(module, ModuleSource{IsolateLAN: true, IsolateLANSet: true, ScriptIsolation: map[string]bool{"response": false}}); err != nil {
		t.Fatal(err)
	}
	module.Name = "notices"
	sources := map[string]string{
		"request":  `$notification.post("request", "", ""); $done();`,
		"response": `$notification.post("response", "", ""); $done();`,
		"query":    `$notification.post("query", "", ""); $done({address:"192.0.2.1"});`,
		"job":      `$notification.post("job", "", ""); $done();`,
	}
	e := cronTestEngine(t, module, sources, 2)
	// Warm regexp2's process-wide real-time clock outside synctest.
	chain := e.Wrap(plugin.Flow{Host: "notify.test", Port: 443, SourceOrigin: plugin.SourceLAN, SourceMAC: testDeviceMAC}, func(exchange *plugin.Exchange) (*plugin.Response, error) {
		return exchange.NewResponse(&http.Response{StatusCode: 200, Request: exchange.Request.Head, Header: make(http.Header), Body: http.NoBody}), nil
	})
	response, err := chain(&plugin.Exchange{Request: plugin.NewRequest(httptest.NewRequestWithContext(t.Context(), "GET", "https://notify.test/", nil), e.options.BodyMemory)})
	if err != nil {
		t.Fatal(err)
	}
	response.Close()
	query := new(dns.Msg).SetQuestion("notify.test.", dns.TypeA)
	_, err = e.WrapDNS(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		t.Fatal("DNS script unexpectedly fell through")
		return nil, nil
	})(t.Context(), &plugin.DNSExchange{DNSRequest: plugin.DNSRequest{DNSPacket: plugin.DNSMessage(query), SourceOrigin: plugin.SourceLAN, SourceMAC: testDeviceMAC}})
	if err != nil {
		t.Fatal(err)
	}
	runtimeFakeClockTest(t, func(t *testing.T) {
		host, err := mitm.New(mitm.Options{Authority: &localca.Authority{}, HTTPClient: http.DefaultClient}, mitm.Instance{ID: "personal", Type: "surge", Plugin: e})
		if err != nil {
			t.Fatal(err)
		}
		defer host.Close()
		if err := host.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if _, err := host.TriggerScript(t.Context(), "personal", api.ScriptRunRequest{Script: "job"}); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		var status surgeapi.SurgeStatus
		if err := json.Unmarshal(host.Status().Plugins[0].Details, &status); err != nil {
			t.Fatal(err)
		}
		if len(status.Notifications) != 4 {
			t.Fatalf("host report lost notifications from scoped copies: %+v", status)
		}
		for i, phase := range []string{"cron", "dns", "http-response", "http-request"} {
			notification := status.Notifications[i]
			wantScope, wantMAC := "device", testDeviceName
			if phase == "cron" || phase == "http-response" {
				wantScope, wantMAC = "local", ""
			}
			if notification.Scope != wantScope || notification.MAC != wantMAC || notification.Module != "notices" || notification.ScriptType != phase || notification.Script != notification.Title {
				t.Errorf("wrong script provenance: %+v", notification)
			}
		}
	})
	if len(cronTestEngine(t, module, sources, 2).Status().Notifications) != 0 {
		t.Fatal("new instance inherited notification history")
	}
}

func TestRuntimeNotificationUsesEffectiveScope(t *testing.T) {
	runtime := testRuntime(t, RuntimeOptions{})
	for _, test := range []struct {
		scope     ScriptScope
		kind, mac string
	}{
		{scope: ScriptScope{Kind: ScriptScopeLocal}, kind: "local"},
		{scope: ScriptScope{Kind: ScriptScopeDevice, MAC: testDeviceMAC}, kind: "device", mac: testDeviceName},
		{scope: ScriptScope{}, kind: "unknown"},
	} {
		result, err := runtime.Runtime.Run(t.Context(), `$notification.post("scope", "", ""); $done();`, Invocation{Scope: test.scope, ScriptName: "scope", ScriptType: "generic", BodyMemory: runtime.budget, BodyLimit: 32 << 20})
		if err != nil {
			t.Fatal(err)
		}
		result.Close()
		n := runtime.notifications.snapshot()[0]
		if n.Scope != test.kind || n.MAC != test.mac {
			t.Fatalf("scope=%+v: notification=%+v", test.scope, n)
		}
	}
}
