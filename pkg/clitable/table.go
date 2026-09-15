// SPDX-License-Identifier: AGPL-3.0-only

// Package clitable provides the shared table style for dae commands and logs.
package clitable

import (
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

// New returns a borderless table with two spaces between columns and no trailing
// spaces. Text aligns left and numbers align right by default. Header casing is
// preserved. Callers can configure column widths and alignment as needed.
// For composite metrics, pass headers and data together through AlignRows before
// calling AppendHeader and AppendRows.
func New() table.Writer {
	writer := table.NewWriter()
	style := table.StyleDefault
	style.Options.DrawBorder = false
	style.Options.SeparateHeader = false
	style.Options.SeparateFooter = false
	style.Options.SeparateColumns = false
	style.Box.PaddingLeft = ""
	style.Box.PaddingRight = "  "
	style.Format.Header = text.FormatDefault
	writer.SetStyle(style)
	writer.SuppressTrailingSpaces()
	return writer
}
