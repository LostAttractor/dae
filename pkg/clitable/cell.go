// SPDX-License-Identifier: AGPL-3.0-only

package clitable

import (
	"slices"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

// Cell holds single-line fields aligned independently within a table column.
// Fields keep the same order across rows, with padding after each value.
// Plain table strings, including multiline text, are handled by the table writer.
type Cell struct {
	parts    []string
	decorate func(string) string
}

// Parts creates a composite cell without adding separators. Include separators
// explicitly and keep units with their values: Parts("800", "/", "10Mbps").
// String returns the compact form for summaries outside a table.
func Parts(values ...string) Cell { return Cell{parts: slices.Clone(values)} }

// Decorate sets the cell's ANSI styling function, replacing any previous one.
// It must preserve visible text and width. The original cell is unchanged.
func (cell Cell) Decorate(fn func(string) string) Cell {
	cell.decorate = fn
	return cell
}

func (cell Cell) String() string { return cell.styled(strings.Join(cell.parts, "")) }

func (cell Cell) styled(value string) string {
	if cell.decorate == nil {
		return value
	}
	// Keep padding outside the ANSI reset so the table can trim trailing spaces.
	content := strings.TrimRight(value, " ")
	return cell.decorate(content) + value[len(content):]
}

func (cell Cell) aligned(widths []int) string {
	var out strings.Builder
	for i, value := range cell.parts {
		out.WriteString(value)
		out.WriteString(strings.Repeat(" ", widths[i]-text.StringWidthWithoutEscSequences(value)))
	}
	return cell.styled(out.String())
}

// AlignRows returns a copy with composite cells padded to their column's shared
// field widths. Pass all data rows together before AppendRows. Headers, ordinary
// strings, numbers and placeholders are not interpreted or changed.
func AlignRows(rows []table.Row) []table.Row {
	widths := make(map[int][]int)
	for _, row := range rows {
		for column, value := range row {
			cell, ok := value.(Cell)
			if !ok {
				continue
			}
			for len(widths[column]) < len(cell.parts) {
				widths[column] = append(widths[column], 0)
			}
			for i, part := range cell.parts {
				widths[column][i] = max(widths[column][i], text.StringWidthWithoutEscSequences(part))
			}
		}
	}
	out := make([]table.Row, len(rows))
	for i, row := range rows {
		out[i] = slices.Clone(row)
		for column, value := range row {
			if cell, ok := value.(Cell); ok {
				out[i][column] = cell.aligned(widths[column])
			}
		}
	}
	return out
}
