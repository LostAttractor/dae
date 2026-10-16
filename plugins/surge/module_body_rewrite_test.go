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

	"github.com/daeuniverse/dae/pkg/membuffer"
)

// Minimal fixtures exercise jq language features independently of third-party modules.
var bodyRewriteCases = []struct {
	name, line, url, input, want string
}{
	{"assignment", `http-response-jq ^https://example.test/a '.value += 1'`, "https://example.test/a", `{"value":2,"keep":true}`, `{"value":3,"keep":true}`},
	{"optional iteration", `http-response-jq ^https://example.test/b '.items[][]? = 3'`, "https://example.test/b", `{"items":{"a":[1,2],"b":null}}`, `{"items":{"a":[3,3],"b":null}}`},
	{"delete and exact number", `http-response-jq ^https://example.test/c 'del(.remove)'`, "https://example.test/c", `{"remove":true,"id":9007199254740993}`, `{"id":9007199254740993}`},
}

func testBodyRewrite(t *testing.T, expression string) BodyRewrite {
	t.Helper()
	var warnings []string
	rule, err := parseBodyRewrite(fmt.Sprintf("http-response-jq . '%s'", expression), &warnings)
	if err != nil || rule == nil || len(warnings) != 0 {
		t.Fatalf("parse body rewrite %q: rule=%v err=%v warnings=%v", expression, rule, err, warnings)
	}
	rule.jq = testJQPool(t)
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

func TestBodyRewriteMinimalFilters(t *testing.T) {
	var lines []string
	for _, test := range bodyRewriteCases {
		lines = append(lines, test.line)
	}
	module, err := Parse("[Body Rewrite]\n"+strings.Join(lines, "\n"), nil)
	if err != nil || len(module.BodyRewrites) != len(bodyRewriteCases) || len(module.Warnings) != 0 {
		t.Fatalf("body section: module=%+v err=%v", module, err)
	}
	for i, test := range bodyRewriteCases {
		t.Run(test.name, func(t *testing.T) {
			rule := module.BodyRewrites[i]
			rule.jq = testJQPool(t)
			if !rule.Match(t.Context(), test.url) || rule.Match(t.Context(), "https://unrelated.example/") {
				t.Fatal("URL pattern did not retain its scope")
			}
			body, err := rule.Apply(context.Background(), []byte(test.input), 1<<20, testBodyMemory)
			if err != nil {
				t.Fatal(err)
			}
			defer body.Close()
			assertBodyRewriteJSON(t, body.Bytes(), test.want)
		})
	}
}

func TestBodyRewriteWarnsForUnsupportedAndInvalidFilters(t *testing.T) {
	for _, line := range []string{
		`unknown . regex replacement`,
		`http-response-jq . '.data = '`,
		`http-response-jq . 'include "filesystem-module"; .'`,
		`http-response-jq . 'input'`,
	} {
		module, err := Parse("[Body Rewrite]\n"+line, nil)
		if err != nil {
			t.Fatal(err)
		}
		engine := newTestEngine(t, EngineOptions{Modules: []*Module{module}})
		prepared := engine.options.Modules[0]
		if len(prepared.BodyRewrites) != 0 || len(prepared.Warnings) != 1 {
			t.Errorf("rule %q should be skipped with one warning: %+v", line, prepared)
		}
	}

	t.Setenv("DAE_BODY_REWRITE_SECRET", "must not be exposed")
	rule := testBodyRewrite(t, "env")
	body, err := rule.Apply(context.Background(), []byte(`{}`), 1024, testBodyMemory)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	assertBodyRewriteJSON(t, body.Bytes(), `{}`)
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
			output, err := rule.Apply(context.Background(), []byte(test.input), test.limit, testBodyMemory)
			defer output.Close()
			if test.wantError != errors.Is(err, membuffer.ErrTooLarge) {
				t.Fatalf("size limit: output=%v err=%v", output, err)
			}
			if test.expression == "empty" && output != nil {
				t.Fatalf("empty filter returned a replacement: %v", output)
			}
		})
	}
	rule := testBodyRewrite(t, "def forever: forever; forever")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := rule.Apply(ctx, []byte(`{}`), 1024, testBodyMemory)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("jq execution exceeded deadline: %v in %v", err, time.Since(start))
	}
}
