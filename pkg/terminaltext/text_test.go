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
