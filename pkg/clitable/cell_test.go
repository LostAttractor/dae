// SPDX-License-Identifier: AGPL-3.0-only

package clitable

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

func TestAlignRowsCompositeParts(t *testing.T) {
	rows := []table.Row{
		{"日本节点", Parts("47", "/", "89296"), Parts("31s", "/", "0s"), 0},
		{"node", Parts("8", "/", "402"), Parts("1m25s", "/", "1m25s"), 100},
		{"/literal/\npath", "-", "-", nil},
	}
	out := AlignRows(rows)
	for i, want := range []string{"47/89296", "8 /402  "} {
		if got := out[i][1]; got != want {
			t.Fatalf("connections[%d]=%q want %q", i, got, want)
		}
	}
	for i, want := range []string{"31s  /0s   ", "1m25s/1m25s"} {
		if got := out[i][2]; got != want {
			t.Fatalf("failure[%d]=%q want %q", i, got, want)
		}
	}
	if out[0][3] != 0 || out[1][3] != 100 || out[2][3] != nil || out[2][0] != "/literal/\npath" || out[2][1] != "-" {
		t.Fatal("plain data changed")
	}
	if got := fmt.Sprint(rows[1][1]); got != "8/402" {
		t.Fatalf("input padded: %q", got)
	}
	out[0][0] = "changed"
	if rows[0][0] != "日本节点" {
		t.Fatal("row slices were not copied")
	}
}

func TestCompositeUnicodeANSI(t *testing.T) {
	red := func(value string) string { return "\x1b[31m" + value + "\x1b[0m" }
	original := Parts("界", "/", "2")
	rows := []table.Row{
		{original.Decorate(red)},
		{Parts("中文", "/", "300")},
		{Parts(red("e\u0301"), "/", "40")},
	}
	out := AlignRows(rows)
	for i, want := range []string{"界  /2  ", "中文/300", "e\u0301   /40 "} {
		if got := text.StripEscape(fmt.Sprint(out[i][0])); got != want {
			t.Fatalf("row %d: %q want %q", i, got, want)
		}
	}
	if !strings.Contains(fmt.Sprint(out[0][0]), "\x1b[31m") || strings.Contains(original.String(), "\x1b") {
		t.Fatal("decoration lost or original mutated")
	}
	writer := New()
	writer.AppendRows(AlignRows([]table.Row{
		{Parts("1", "").Decorate(red)},
		{Parts("20", " (optional)").Decorate(red)},
	}))
	for line := range strings.SplitSeq(text.StripEscape(writer.Render()), "\n") {
		if strings.HasSuffix(line, " ") {
			t.Fatalf("colored padding escaped trailing-space suppression: %q", line)
		}
	}
}

func TestCompositeHeadersShareFieldWidths(t *testing.T) {
	rows := []table.Row{
		{"PATH/NAME", Parts("UP", "/", "24H"), Parts("ACTIVE", " / ", "FB")},
		{"日本节点", Parts("100.0", "/", "100.0%"), Parts("1", " / ", "2000")},
		{"node", Parts("99.5", "/", "99.5%"), Parts("1234567", " / ", "0")},
		{"idle", "-", Parts("0", " / ", "0")},
	}
	out := AlignRows(rows)
	for i, want := range []string{"UP   /24H   ", "100.0/100.0%", "99.5 /99.5% ", "-"} {
		if got := out[i][1]; got != want {
			t.Fatalf("availability row %d: got %q, want %q", i, got, want)
		}
	}
	for i, want := range []string{"ACTIVE  / FB  ", "1       / 2000", "1234567 / 0   ", "0       / 0   "} {
		if got := out[i][2]; got != want {
			t.Fatalf("counter row %d: got %q, want %q", i, got, want)
		}
	}
	if out[0][0] != "PATH/NAME" || fmt.Sprint(rows[0][1]) != "UP/24H" {
		t.Fatal("ordinary title or original header was modified")
	}
}

func TestCompositeOwnsParts(t *testing.T) {
	parts := []string{"12", "/", "345"}
	cell := Parts(parts...)
	parts[0] = "changed"
	if cell.String() != "12/345" {
		t.Fatalf("caller mutation changed stored cell: %q", cell.String())
	}
}

func TestCompositeRaggedRows(t *testing.T) {
	rows := []table.Row{
		nil,
		{"short", Parts("L", "/", "R")},
		{"long", Parts("100", "/", "2"), "plain", Parts("界", "/", "30")},
		{"other", Parts("4", "/", "500"), "plain", Parts("中文", "/", "1")},
	}
	out := AlignRows(rows)
	if len(out[0]) != 0 || out[1][1] != "L  /R  " || out[2][3] != "界  /30" || out[3][3] != "中文/1 " {
		t.Fatalf("ragged rows lost alignment: %v", out)
	}
	if fmt.Sprint(rows[1][1]) != "L/R" {
		t.Fatal("input cell was padded")
	}
}
