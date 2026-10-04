// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
)

func TestSurgeStatusWireAndTable(t *testing.T) {
	for _, status := range []api.SurgeStatus{
		{},
		{Enabled: true},
		{Enabled: true, Modules: []api.ModuleStatus{
			{Name: "online", State: "loaded", Scripts: 2, Hostnames: 3},
			{Name: "offline", State: "cached", Error: "download failed", Warnings: []string{"refresh failed", "using cached module"}},
			{Name: "partial", State: "cached dependencies", Scripts: 1},
		}},
	} {
		details, err := json.Marshal(status)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Surge([]api.PluginInstanceStatus{{ID: "test", Type: "surge", Details: details}})
		if err != nil {
			t.Fatal(err)
		}
		output := RenderSurge(decoded, false)
		if strings.Contains(output, "\x1b") {
			t.Fatalf("table contains terminal escapes: %q", output)
		}
		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(line, "|") || strings.HasPrefix(line, "+-") || strings.TrimRight(line, " \t") != line {
				t.Fatalf("table contains borders or trailing spaces: %q", line)
			}
		}
		if !status.Enabled && !strings.Contains(output, "disabled") {
			t.Fatalf("disabled status: %s", output)
		}
		if status.Enabled && len(status.Modules) == 0 && !strings.Contains(output, "no modules configured") {
			t.Fatalf("empty status: %s", output)
		}
		for _, module := range status.Modules {
			if !strings.Contains(output, module.Name) || !strings.Contains(output, module.State) {
				t.Fatalf("missing module %s (%s):\n%s", module.Name, module.State, output)
			}
		}
		if len(status.Modules) > 0 {
			for _, want := range []string{
				"Surge modules:\nINSTANCE",
				"\n\nErrors:\ntest/offline: download failed",
				"\n\nWarnings:\ntest/offline: refresh failed\ntest/offline: using cached module",
			} {
				if !strings.Contains(output, want) {
					t.Fatalf("missing %q in status:\n%s", want, output)
				}
			}
			t.Log("\n" + output)
		}
	}
}

func TestSurgeStatusSelectsAndLabelsInstances(t *testing.T) {
	detail := jsonv1.RawMessage(`{"enabled":true,"modules":[{"name":"shared","state":"loaded","warnings":["unsupported rule"]}]}`)
	status, err := Surge([]api.PluginInstanceStatus{
		{ID: "native", Type: "example", Details: jsonv1.RawMessage(`{"pending":1}`)},
		{ID: "personal", Type: "surge", Details: detail},
		{ID: "work", Type: "surge", Details: detail},
	})
	if err != nil || len(status.Modules) != 2 || status.Modules[0].Instance != "personal" || status.Modules[1].Instance != "work" {
		t.Fatalf("mixed or mislabelled plugin reports: %+v, %v", status, err)
	}
	output := RenderSurge(status, false)
	for _, name := range []string{"INSTANCE", "personal", "work", "\n\nWarnings:\npersonal/shared: unsupported rule\nwork/shared: unsupported rule"} {
		if !strings.Contains(output, name) {
			t.Fatalf("missing %q in table: %s", name, output)
		}
	}
	for _, detail := range []jsonv1.RawMessage{nil, jsonv1.RawMessage(`null`), jsonv1.RawMessage(`{"enabled":"bad"}`)} {
		if _, err := Surge([]api.PluginInstanceStatus{{ID: "broken", Type: "surge", Details: detail}}); err == nil {
			t.Fatal("invalid plugin report was silently accepted")
		}
	}
}

func TestSurgeTaskStatusWireAndTable(t *testing.T) {
	next := time.Date(2026, time.September, 29, 9, 5, 0, 0, time.FixedZone("CST", 8*60*60))
	status := api.SurgeStatus{Enabled: true, Modules: []api.ModuleStatus{{Name: "youpin", State: "loaded", Scripts: 2, Tasks: []api.ScriptTaskStatus{{
		Name: "有品签到", Type: "cron", CronExp: "5 9 * * *", Timezone: "Asia/Shanghai", TimeoutSeconds: 60,
		State: "scheduled", NextRun: next, LastStartedAt: next.Add(-24 * time.Hour),
		LastFinishedAt: next.Add(-24*time.Hour + time.Minute), LastDurationMS: 60000,
		LastResult: "failed", LastError: "timeout", Runs: 3, Failures: 1, Skipped: 2,
	}}}}}
	detail, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Surge([]api.PluginInstanceStatus{{ID: "personal", Type: "surge", Details: detail}})
	if err != nil {
		t.Fatal(err)
	}
	job := report.Modules[0].Tasks[0]
	if job.Runs != 3 || job.Skipped != 2 || !job.NextRun.Equal(next) || job.LastError != "timeout" {
		t.Fatalf("cron state lost in wire roundtrip: %+v", job)
	}
	output := RenderSurge(report, false)
	for _, want := range []string{"Surge script tasks:", "Last script runs:", "personal", "youpin", "有品签到", "5 9 * * *", "Asia/Shanghai", "60s", "scheduled", "2026-09-29T09:05:00+08:00", "failed/timeout", "60000ms", "RUNS", "FAILED", "SKIPPED"} {
		if !strings.Contains(output, want) {
			t.Errorf("cron table missing %q:\n%s", want, output)
		}
	}
	status.Modules[0].Tasks = []api.ScriptTaskStatus{{Name: "manual", Type: "generic", State: "ready"}}
	detail, err = json.Marshal(status)
	if err != nil || strings.Contains(string(detail), "0001-") || strings.Contains(string(detail), "cronexp") || strings.Contains(string(detail), "timezone") {
		t.Fatalf("generic includes schedule fields: %s (%v)", detail, err)
	}
	output = RenderSurge(status, false)
	if !strings.Contains(output, "generic") || !strings.Contains(output, "ready") || strings.Contains(output, "0001-") {
		t.Fatalf("generic state missing or invalid timestamp shown: %s", output)
	}
}

func TestSurgeNotificationStatusWireAndDisplay(t *testing.T) {
	now := time.Date(2026, time.September, 29, 9, 5, 0, 0, time.UTC)
	var instances []api.PluginInstanceStatus
	for i, instance := range []string{"personal", "work"} {
		detail, err := json.Marshal(api.SurgeStatus{Enabled: true, Modules: []api.ModuleStatus{{Name: "account", State: "loaded"}}, Notifications: []api.SurgeNotification{{
			Instance: "untrusted", ID: 1, CreatedAt: now.Add(time.Duration(i) * time.Second), Module: "account", Script: "sign", ScriptType: "cron",
			Title: "签到成功", Subtitle: "账户一", Body: "余额 1.2\n\x1b[31m明日继续\x1b[0m\r\x00", Truncated: i == 1,
		}}})
		if err != nil {
			t.Fatal(err)
		}
		instances = append(instances, api.PluginInstanceStatus{ID: instance, Type: "surge", Details: detail})
	}
	report, err := Surge(instances)
	if err != nil || len(report.Notifications) != 2 || report.Notifications[0].Instance != "work" || report.Notifications[1].Instance != "personal" || !strings.Contains(report.Notifications[0].Body, "\x1b[31m") {
		t.Fatalf("notification identity/order/text lost: %+v %v", report, err)
	}
	output := RenderSurge(report, false)
	for _, want := range []string{"Recent Surge notifications:", "2026-09-29T09:05:01Z", "work/account/sign (#1, cron) [truncated]", "personal/account/sign", "Title: 签到成功", "Subtitle: 账户一", "Body: 余额 1.2\n    明日继续"} {
		if !strings.Contains(output, want) {
			t.Errorf("notification display missing %q:\n%s", want, output)
		}
	}
	if strings.ContainsAny(output, "\x1b\r\x00") || strings.Index(output, "work/account/sign") > strings.Index(output, "personal/account/sign") {
		t.Fatalf("unsafe or unordered notification display: %q", output)
	}
	empty, err := Surge([]api.PluginInstanceStatus{{ID: "empty", Type: "surge", Details: jsonv1.RawMessage(`{"enabled":true,"modules":[]}`)}})
	if err != nil || len(empty.Notifications) != 0 || strings.Contains(RenderSurge(empty, false), "notifications") {
		t.Fatalf("unexpected empty status: %+v %v", empty, err)
	}
}

func TestSurgeNotificationsDisplayLimitAndVerbose(t *testing.T) {
	scripts := []api.SurgeNotification{
		{Instance: "personal", Module: "account", Script: "sign", ScriptType: "cron"},
		{Instance: "work", Module: "account", Script: "sign", ScriptType: "cron"},
		{Instance: "personal", Module: "other", Script: "sign", ScriptType: "cron"},
		{Instance: "personal", Module: "account", Script: "other", ScriptType: "cron"},
		{Instance: "personal", Module: "account", Script: "sign", ScriptType: "http-request"},
	}
	report := api.SurgeStatus{Enabled: true}
	for revision := 4; revision >= 0; revision-- {
		for i, item := range scripts {
			item.Title = fmt.Sprintf("notice-%d-%d", i, revision)
			report.Notifications = append(report.Notifications, item)
		}
	}
	report.Notifications = append(report.Notifications, api.SurgeNotification{Instance: "personal", Module: "account", Script: "quiet", ScriptType: "cron", Title: "quiet-notice"})
	before := slices.Clone(report.Notifications)
	for _, verbose := range []bool{false, true} {
		output := RenderSurge(report, verbose)
		for revision := range 5 {
			for i := range scripts {
				name := fmt.Sprintf("notice-%d-%d", i, revision)
				if strings.Contains(output, name) != (verbose || revision >= 2) {
					t.Errorf("verbose=%t: wrong per-script selection for %s:\n%s", verbose, name, output)
				}
			}
		}
		if !strings.Contains(output, "quiet-notice") || strings.Contains(output, "10 older notifications hidden. Use --verbose") == verbose {
			t.Fatalf("verbose=%t: quiet notification or hidden-count hint lost:\n%s", verbose, output)
		}
	}
	if !slices.Equal(report.Notifications, before) {
		t.Fatal("text rendering modified the full notification report")
	}
}
