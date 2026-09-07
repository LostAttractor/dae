// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These four filters are from the user's Bilijump module:
// https://github.com/qingmeng1/bilijump-ai/blob/main/script/bilijump.sgmodule
var bilijumpBodyRewriteCases = []struct {
	name, line, url, input, want string
}{
	{
		name:  "tracker websocket domains",
		line:  `http-response-jq ^https:\/\/api\.live\.bilibili\.com\/xlive\/open-interface\/v2\/tracker\/conf\? '.data.domains=["wss://tracker.chat.bilibili.com"]'`,
		url:   "https://api.live.bilibili.com/xlive/open-interface/v2/tracker/conf?platform=ios",
		input: `{"data":{"domains":["wss://old.example"],"keep":1}}`,
		want:  `{"data":{"domains":["wss://tracker.chat.bilibili.com"],"keep":1}}`,
	},
	{
		name:  "STUN addresses with optional iteration",
		line:  `http-response-jq ^https:\/\/api\.bilibili\.com\/x\/pd-proxy\/tracker\? '.data[][]?="stun.chat.bilibili.com:3478"'`,
		url:   "https://api.bilibili.com/x/pd-proxy/tracker?platform=ios",
		input: `{"data":{"primary":["old:1","old:2"],"secondary":["old:3"],"missing":null}}`,
		want:  `{"data":{"primary":["stun.chat.bilibili.com:3478","stun.chat.bilibili.com:3478"],"secondary":["stun.chat.bilibili.com:3478"],"missing":null}}`,
	},
	{
		name:  "remove payment without losing large numeric IDs",
		line:  `http-response-jq ^https:\/\/api\.bilibili\.com\/pgc\/view\/v2\/app\/season\? 'del(.data.payment)'`,
		url:   "https://api.bilibili.com/pgc/view/v2/app/season?season_id=1",
		input: `{"code":0,"data":{"payment":{"price":100},"title":"测试","aid":9007199254740993}}`,
		want:  `{"code":0,"data":{"title":"测试","aid":9007199254740993}}`,
	},
	{
		name:  "remove TIP and selected BANNER items",
		line:  `http-response-jq ^https:\/\/api\.bilibili\.com\/pgc\/page\/channel\? '.data.modules |= map(select(.type != "TIP") | if .type == "BANNER" then .module_data.items |= map(select(.url | startswith("https://www.bilibili.com/blackboard/era/") | not)) else . end)'`,
		url:   "https://api.bilibili.com/pgc/page/channel?channel_id=1",
		input: `{"data":{"modules":[{"type":"TIP"},{"type":"BANNER","module_data":{"items":[{"url":"https://www.bilibili.com/blackboard/era/ad"},{"url":"https://www.bilibili.com/video/BV1"}]}},{"type":"NORMAL","module_data":{"items":[{"url":"https://www.bilibili.com/blackboard/era/keep"}]}}]}}`,
		want:  `{"data":{"modules":[{"type":"BANNER","module_data":{"items":[{"url":"https://www.bilibili.com/video/BV1"}]}},{"type":"NORMAL","module_data":{"items":[{"url":"https://www.bilibili.com/blackboard/era/keep"}]}}]}}`,
	},
}

func testBodyRewrite(t *testing.T, expression string) BodyRewrite {
	t.Helper()
	var warnings []string
	rule, err := parseBodyRewrite(fmt.Sprintf("http-response-jq . '%s'", expression), &warnings)
	if err != nil || rule == nil || len(warnings) != 0 {
		t.Fatalf("parse body rewrite %q: rule=%v err=%v warnings=%v", expression, rule, err, warnings)
	}
	return *rule
}

func assertBodyRewriteJSON(t *testing.T, got []byte, want string) {
	t.Helper()
	decode := func(data []byte) any {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			t.Fatalf("invalid JSON %q: %v", data, err)
		}
		return value
	}
	if !reflect.DeepEqual(decode(got), decode([]byte(want))) {
		t.Fatalf("body rewrite returned %s; want %s", got, want)
	}
}

func TestBodyRewriteBilijumpFilters(t *testing.T) {
	var lines []string
	for _, test := range bilijumpBodyRewriteCases {
		lines = append(lines, test.line)
	}
	module, err := Parse("[Body Rewrite]\n"+strings.Join(lines, "\n"), nil)
	if err != nil || len(module.BodyRewrites) != 4 || len(module.Warnings) != 0 {
		t.Fatalf("Bilijump body section: module=%+v err=%v", module, err)
	}
	for i, test := range bilijumpBodyRewriteCases {
		t.Run(test.name, func(t *testing.T) {
			rule := module.BodyRewrites[i]
			if !rule.Match(test.url) || rule.Match("https://unrelated.example/") {
				t.Fatal("Bilijump URL pattern did not retain its scope")
			}
			body, err := rule.Apply(context.Background(), []byte(test.input), 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			assertBodyRewriteJSON(t, body, test.want)
		})
	}
}

func TestBodyRewriteWarnsForUnsupportedAndInvalidFilters(t *testing.T) {
	for _, line := range []string{
		`http-request-jq . '.x=1'`,
		`http-response . regex replacement`,
		`http-request . regex replacement`,
		`http-response-jq . '.data = '`,
		`http-response-jq . 'include "filesystem-module"; .'`,
		`http-response-jq . 'input'`,
	} {
		var warnings []string
		rule, err := parseBodyRewrite(line, &warnings)
		if err != nil || rule != nil || len(warnings) != 1 {
			t.Errorf("rule %q should be skipped with one warning: rule=%v err=%v warnings=%v", line, rule, err, warnings)
		}
	}
	t.Setenv("DAE_BODY_REWRITE_SECRET", "must not be exposed")
	rule := testBodyRewrite(t, "env")
	body, err := rule.Apply(context.Background(), []byte(`{}`), 1024)
	if err != nil {
		t.Fatal(err)
	}
	assertBodyRewriteJSON(t, body, `{}`)
}

func TestBodyRewriteExecutionLimitsAndEmptyOutput(t *testing.T) {
	for _, test := range []struct {
		expression, input string
		limit             int64
		wantError         bool
	}{
		{"empty", `{"keep":1}`, 64, false},
		{".", `{}`, 2, false},
		{`"x" * 100`, `{}`, 64, true},
		{"range(1000000000)", `{}`, 64, true},
		{".", `{"long":1}`, 2, true},
		{".", `{}`, 1, true},
	} {
		t.Run(test.expression+test.input, func(t *testing.T) {
			rule := testBodyRewrite(t, test.expression)
			output, err := rule.Apply(context.Background(), []byte(test.input), test.limit)
			if test.wantError != errors.Is(err, errBodyTooLarge) {
				t.Fatalf("size limit: output=%q err=%v", output, err)
			}
			if test.expression == "empty" && output != nil {
				t.Fatalf("empty filter returned a replacement: %q", output)
			}
		})
	}
	rule := testBodyRewrite(t, "def forever: forever; forever")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := rule.Apply(ctx, []byte(`{}`), 1024)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("jq execution exceeded deadline: %v in %v", err, time.Since(start))
	}
}
