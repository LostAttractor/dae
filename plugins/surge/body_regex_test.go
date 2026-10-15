// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"errors"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

func TestBodyRegex(t *testing.T) {
	for _, test := range []struct{ rule, input, want string }{
		{`http-response . '^值=(\d+)$' '数=$1' '数' '值'`, "值=1\n值=20", "值=1\n值=20"},
		{`http-request . '(?<word>猫)(狗)?' '${word}:$1:$$:$&:$22'`, "猫", "猫::$:猫:猫2"},
		{`http-response . '.' ''`, "删除", ""},
		{`http-request . '^$' '{}'`, "", "{}"},
		{`http-response . '(?<=前)旧(?=后)' '新'`, "前旧后", "前新后"},
		{`http-response . '^' '>'`, "a\nb", ">a\n>b"},
	} {
		t.Run(test.rule, func(t *testing.T) {
			var warnings []string
			rule, err := parseBodyRewrite(test.rule, &warnings)
			if err != nil || len(warnings) != 0 {
				t.Fatalf("parse: %v, %v", err, warnings)
			}
			body, err := rule.Apply(t.Context(), []byte(test.input), 1024, testBodyMemory)
			defer body.Close()
			if err != nil || body == nil {
				t.Fatalf("replacement=%v error=%v", body, err)
			}
			if string(body.Bytes()) != test.want {
				t.Fatalf("replacement=%q, want %q", body.Bytes(), test.want)
			}
		})
	}
}

func TestBodyRegexLimits(t *testing.T) {
	var warnings []string
	rule, err := parseBodyRewrite(`http-response . '^' '`+strings.Repeat("x", 1024)+`'`, &warnings)
	if err != nil {
		t.Fatal(err)
	}
	output, err := rule.Apply(t.Context(), []byte("original"), 128, testBodyMemory)
	if output != nil || !errors.Is(err, membuffer.ErrTooLarge) {
		t.Fatalf("oversized replacement: %v %v", output, err)
	}
	if output, err = rule.Apply(t.Context(), []byte{0xff}, 2048, testBodyMemory); output != nil || err == nil {
		t.Fatalf("invalid UTF-8 was rewritten: %v %v", output, err)
	}
}
