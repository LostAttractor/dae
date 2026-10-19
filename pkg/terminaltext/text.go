// SPDX-License-Identifier: AGPL-3.0-only

// Package terminaltext renders external text without terminal control sequences.
package terminaltext

import (
	"strings"
	"unicode"

	"github.com/jedib0t/go-pretty/v6/text"
)

// Plain removes ANSI sequences and remaining C0/C1 controls, including bare or
// incomplete escapes. Newlines and tabs remain available for text formatting.
// Apply this at display boundaries; structured data retains the original text.
func Plain(value string) string {
	// StripEscape rebuilds even ordinary text. Keep the control/UTF-8 pass,
	// but only run the ANSI parser when an escape sequence can be present.
	if strings.ContainsRune(value, '\x1b') {
		value = text.StripEscape(value)
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, value)
}

// Line keeps an external identifier or message on one display line.
func Line(value string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		return r
	}, Plain(value))
}
