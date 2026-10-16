// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

func TestRegexReplacementSemantics(t *testing.T) {
	for _, test := range []struct{ pattern, value, replacement string }{
		{`(a)(b)`, "ab ab", `$2$1 $$ $& $` + "`" + ` $' $_ $+`},
		{`(?<word>猫)(?<10>狗)`, "猫狗猫狗", `${word}-${10}-$1`},
		{`(?=a)`, "aa", "x"},
		{`(a)`, "aa", "$12"},
	} {
		re, err := compilePattern(test.pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, count := range []int{1, -1} {
			want, err := re.Replace(test.value, test.replacement, -1, count)
			if err != nil {
				t.Fatal(err)
			}
			got, err := replacePattern(t.Context(), re, test.value, test.replacement, count)
			if err != nil || got != want {
				t.Fatalf("%q %q: got %q, want %q, err=%v", test.pattern, test.replacement, got, want, err)
			}
		}
	}
}

func TestRegexBudgetStopsReplacementLoop(t *testing.T) {
	re, err := compilePattern("a")
	if err != nil {
		t.Fatal(err)
	}
	_, err = replacePattern(t.Context(), re, strings.Repeat("a", regexOperationLimit+1), "b", -1)
	if !errors.Is(err, errRegexBudget) {
		t.Fatalf("unbounded replacement: %v", err)
	}
}

func TestRegexBudgetAcrossHTTPDirections(t *testing.T) {
	e := testProxyEngine(t, "[Header Rewrite]\nhttp-request . header-add X-Request yes\nhttp-response . header-add X-Response yes", "")
	e.slots = make(chan struct{}, 1)
	r := httptest.NewRequestWithContext(t.Context(), "GET", "https://example.test/", nil)
	if _, err := e.processRequest(&plugin.Exchange{Request: r}); err != nil {
		t.Fatal(err)
	}
	b := r.Context().Value(regexBudgetKey{}).(*regexBudget)
	if b.operations != 1 {
		t.Fatal("request did not consume shared budget", b.operations)
	}
	if len(e.slots) != 0 || r.Context().Value(executionSlotKey{}) != nil {
		t.Fatal("request retained its execution slot while waiting for upstream")
	}
	b.spent = regexWorkLimit
	response := &http.Response{Request: r, StatusCode: 200, Header: make(http.Header), Body: http.NoBody}
	if err := e.processResponse(response, nil); !errors.Is(err, errRegexBudget) || response.Header.Get("X-Response") != "" {
		t.Fatalf("response reset request budget: %v %v", err, response.Header)
	}
	if len(e.slots) != 0 || r.Context().Value(executionSlotKey{}) != nil {
		t.Fatal("failed response did not release its execution slot")
	}
}

func TestRegexAdmissionPrecedesMatching(t *testing.T) {
	e := testProxyEngine(t, "[Header Rewrite]\nhttp-request . header-add X-Rewrite yes", "")
	e.slots = make(chan struct{}, 1)
	e.slots <- struct{}{}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	r := httptest.NewRequestWithContext(ctx, "GET", "https://example.test/", nil)
	if _, err := e.processRequest(&plugin.Exchange{Request: r}); !errors.Is(err, context.DeadlineExceeded) || r.Header.Get("X-Rewrite") != "" {
		t.Fatalf("rules ran before admission: %v %v", err, r.Header)
	}
}

func TestRegexAggregateCPUIsBounded(t *testing.T) {
	text := "[MITM]\nhostname = example.test\n[Header Rewrite]\n" + strings.Repeat("http-request (a+)+b header-add X-Rewrite yes\n", 100)
	e := testProxyEngine(t, text, "")
	url := "https://example.test/" + strings.Repeat("a", 60)
	r := httptest.NewRequestWithContext(t.Context(), "GET", url, nil)
	start := time.Now()
	_, err := e.processRequest(&plugin.Exchange{Request: r})
	if !errors.Is(err, errRegexBudget) || time.Since(start) > 2*time.Second {
		t.Fatalf("unbounded HTTP rule work: %v (%v)", err, time.Since(start))
	}
	start = time.Now()
	result := e.Explain(t.Context(), api.ExplainRequest{Flow: api.DiagnosticFlow{Destination: api.DiagnosticTarget{Port: 443}, HTTP: &api.DiagnosticHTTP{URL: url}}})
	if result.Complete || time.Since(start) > 2*time.Second {
		t.Fatalf("unbounded diagnostic work: complete=%v (%v)", result.Complete, time.Since(start))
	}
	if result.Steps[len(result.Steps)-1].Reason != "regex_budget" {
		t.Fatalf("budget exhaustion reported as a rule miss: %+v", result.Steps)
	}
}

func TestModuleRegexRuleLimit(t *testing.T) {
	_, err := Parse("[Header Rewrite]\n"+strings.Repeat("http-request . header-add X-Rewrite yes\n", maxModuleRegexRules+1), nil)
	if err == nil {
		t.Fatal("module accepted an unbounded number of regex rules")
	}
}
