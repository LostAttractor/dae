// SPDX-License-Identifier: AGPL-3.0-only

package terminaltext

import (
	"strings"
	"testing"
	"unicode"
)

func TestPlainRemovesTerminalControls(t *testing.T) {
	for _, input := range []string{
		"before\x1b[2Jafter", "before\x1b]52;c;YWJj\aafter",
		"before\x1b]52;c;YWJj\x1b\\after", "before\x1b[after",
		"before\u009b2J\u009d52;c;YWJj\u009cafter", "before\x9b2Jafter",
		"before\r\b\x00\x7fafter",
	} {
		got := Plain(input)
		for _, r := range got {
			if unicode.IsControl(r) {
				t.Fatalf("input=%q retained terminal control in %q", input, got)
			}
		}
		if !strings.Contains(got, "before") {
			t.Fatalf("lost surrounding text: %q", got)
		}
	}
	if got := Plain("标题\n\t正文"); got != "标题\n\t正文" {
		t.Fatalf("lost ordinary text formatting: %q", got)
	}
	if got := Line("标题\n\t正文"); got != "标题  正文" {
		t.Fatalf("identifier spans lines: %q", got)
	}
}

func TestPlainPreservesTextAndRepairsUTF8(t *testing.T) {
	for _, test := range []struct{ input, plain, line string }{
		{"", "", ""},
		{"proxy.example:443", "proxy.example:443", "proxy.example:443"},
		{"标题 🙂 e\u0301", "标题 🙂 e\u0301", "标题 🙂 e\u0301"},
		{"line\n\ttext", "line\n\ttext", "line  text"},
		{"a\x00\a\b\r\x7fb", "ab", "ab"},
		{"a\u0080\u009b\u009fb", "ab", "ab"},
		{"a\xff\x9bb", "a\ufffd\ufffdb", "a\ufffd\ufffdb"},
		{"a\xe2\x82b", "a\ufffd\ufffdb", "a\ufffd\ufffdb"},
		{"a\ufffdb", "a\ufffdb", "a\ufffdb"},
		{"a\x1b[31mb\x1b[0mc", "abc", "abc"},
		{"a\x1b[", "a", "a"},
	} {
		if got := Plain(test.input); got != test.plain {
			t.Errorf("Plain(%q) = %q, want %q", test.input, got, test.plain)
		}
		if got := Line(test.input); got != test.line {
			t.Errorf("Line(%q) = %q, want %q", test.input, got, test.line)
		}
	}
	// Exercise every standalone byte, including invalid UTF-8 and ESC, which
	// starts an incomplete ANSI sequence and consumes the remaining suffix.
	for value := range 256 {
		input := "a" + string([]byte{byte(value)}) + "b"
		want := input
		switch {
		case value == 0x1b:
			want = "a"
		case value < 0x20 && value != '\n' && value != '\t', value == 0x7f:
			want = "ab"
		case value >= 0x80:
			want = "a\ufffdb"
		}
		if got := Plain(input); got != want {
			t.Errorf("Plain(%q) = %q, want %q", input, got, want)
		}
	}
}
