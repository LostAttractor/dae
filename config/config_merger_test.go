/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeConfigFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestMergerSyntaxErrorPreservesLocationWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "config.dae")
	child := filepath.Join(dir, "nodes.dae")
	writeConfigFile(t, entry, "include { nodes.dae }\n")
	writeConfigFile(t, child, "node {\n 'trojan://password-secret@example.com:443' (\n}\n")
	_, _, err := NewMerger(entry).Merge()
	if err == nil || !strings.Contains(err.Error(), child) || !strings.Contains(err.Error(), "line 3:") {
		t.Fatalf("merger error lost file or line location: %v", err)
	}
	if strings.Contains(err.Error(), "password-secret") || strings.Contains(err.Error(), "trojan://") {
		t.Fatalf("merger error leaked configuration: %v", err)
	}
}

func TestMergerInvalidIncludeDoesNotEchoConfiguration(t *testing.T) {
	entry := filepath.Join(t.TempDir(), "config.dae")
	writeConfigFile(t, entry, "include { nested { api_key: 'password-secret' } }\n")
	_, _, err := NewMerger(entry).Merge()
	if err == nil || !strings.Contains(err.Error(), entry) || !strings.Contains(err.Error(), "expected a configuration file path or glob pattern") {
		t.Fatalf("invalid include error lost its source or guidance: %v", err)
	}
	if strings.Contains(err.Error(), "password-secret") || strings.Contains(err.Error(), "api_key") {
		t.Fatalf("invalid include error exposed configuration: %v", err)
	}
}

func TestMergerSupportsAbsoluteIncludeWithinEntryDirectory(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "config.d", "global.dae")
	entry := filepath.Join(dir, "config.dae")
	writeConfigFile(t, child, "global {}\n")
	writeConfigFile(t, entry, fmt.Sprintf("include {\n%s\n}\nrouting { fallback: direct }\n", child))
	t.Chdir(dir)

	merger := NewMerger(filepath.Join(".", "config.dae"))
	if !filepath.IsAbs(merger.entry) || merger.entry != filepath.Clean(merger.entry) || merger.entryDir != filepath.Clean(dir) {
		t.Fatalf("merger paths were not normalized: entry=%q entryDir=%q", merger.entry, merger.entryDir)
	}
	sections, entries, err := merger.Merge()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !filepath.IsAbs(entry) || entry != filepath.Clean(entry) {
			t.Fatalf("entry path was not normalized: %q", entry)
		}
	}
	if _, err := New(sections); err != nil {
		t.Fatal(err)
	}
}

func TestMergerRejectsAbsoluteIncludeOutsideEntryDirectory(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.dae")
	entry := filepath.Join(dir, "config.dae")
	writeConfigFile(t, outside, "global {}\n")
	writeConfigFile(t, entry, fmt.Sprintf("include {\n%s\n}\nrouting { fallback: direct }\n", outside))

	if _, _, err := NewMerger(entry).Merge(); err == nil {
		t.Fatal("include outside the entry directory was accepted")
	}
}

func TestMergerRejectsRelativeParentInclude(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "config")
	entry := filepath.Join(dir, "config.dae")
	writeConfigFile(t, filepath.Join(base, "outside.dae"), "global {}\n")
	writeConfigFile(t, entry, "include { ../outside.dae }\nrouting { fallback: direct }\n")

	if _, _, err := NewMerger(entry).Merge(); err == nil {
		t.Fatal("relative parent include was accepted")
	}
}

func TestMergerPreservesRelativeIncludes(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "config.dae")
	writeConfigFile(t, filepath.Join(dir, "config.d", "global.dae"), "global {}\n")
	writeConfigFile(t, entry, "include { config.d/*.dae }\nrouting { fallback: direct }\n")

	sections, _, err := NewMerger(entry).Merge()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(sections); err != nil {
		t.Fatal(err)
	}
}

func TestMergerAllowsDotDotPrefixedPathComponent(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "config.dae")
	writeConfigFile(t, filepath.Join(dir, "..foo", "global.dae"), "global {}\n")
	writeConfigFile(t, entry, "include { ..foo/*.dae }\nrouting { fallback: direct }\n")

	sections, _, err := NewMerger(entry).Merge()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(sections); err != nil {
		t.Fatal(err)
	}
}

func TestMergerRejectsSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	entry := filepath.Join(dir, "config.dae")
	writeConfigFile(t, filepath.Join(outside, "global.dae"), "global {}\n")
	if err := os.Symlink(outside, filepath.Join(dir, "config.d")); err != nil {
		t.Fatal(err)
	}
	writeConfigFile(t, entry, "include { config.d/*.dae }\nrouting { fallback: direct }\n")

	if _, _, err := NewMerger(entry).Merge(); err == nil {
		t.Fatal("include through a symlink outside the entry directory was accepted")
	}
}

func TestMergerAllowsSymlinkWithinEntryDirectory(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "config.dae")
	writeConfigFile(t, filepath.Join(dir, "config.d", "global.dae"), "global {}\n")
	if err := os.Symlink(filepath.Join("config.d", "global.dae"), filepath.Join(dir, "global.dae")); err != nil {
		t.Fatal(err)
	}
	writeConfigFile(t, entry, "include { global.dae }\nrouting { fallback: direct }\n")

	sections, _, err := NewMerger(entry).Merge()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(sections); err != nil {
		t.Fatal(err)
	}
}

func TestMergerAllowsAbsoluteSymlinkWithinEntryDirectory(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "config.dae")
	child := filepath.Join(dir, "config.d", "global.dae")
	writeConfigFile(t, child, "global {}\n")
	if err := os.Symlink(child, filepath.Join(dir, "global.dae")); err != nil {
		t.Fatal(err)
	}
	writeConfigFile(t, entry, "include { global.dae }\nrouting { fallback: direct }\n")

	sections, _, err := NewMerger(entry).Merge()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(sections); err != nil {
		t.Fatal(err)
	}
}

func TestMergerAllowsEntrySymlinkOutsideEntryDirectory(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "generated.dae")
	writeConfigFile(t, filepath.Join(dir, "global.dae"), "global {}\n")
	writeConfigFile(t, target, "include { global.dae }\nrouting { fallback: direct }\n")
	entry := filepath.Join(dir, "config.dae")
	if err := os.Symlink(target, entry); err != nil {
		t.Fatal(err)
	}

	sections, _, err := NewMerger(entry).Merge()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(sections); err != nil {
		t.Fatal(err)
	}
}

func TestMergerIncludesEachFileOnce(t *testing.T) {
	for _, test := range []struct {
		name, includes string
		want           []string
		files          int
	}{
		{name: "duplicate", includes: "shared.dae shared.dae", want: []string{"root", "shared"}, files: 2},
		{name: "normalized duplicate", includes: "shared.dae ./shared.dae", want: []string{"root", "shared"}, files: 2},
		{name: "normalized duplicate glob", includes: "s*.dae ./s*.dae s*.dae", want: []string{"root", "shared"}, files: 2},
		{name: "overlapping glob", includes: "shared.dae s*.dae", want: []string{"root", "shared"}, files: 2},
		{name: "diamond", includes: "left.dae right.dae", want: []string{"root", "left", "shared", "right"}, files: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			entry := filepath.Join(dir, "config.dae")
			writeConfigFile(t, entry, "include { "+test.includes+" }\nglobal { lan_interface: root }\nrouting { fallback: direct }\n")
			writeConfigFile(t, filepath.Join(dir, "shared.dae"), "global { lan_interface: shared }\n")
			writeConfigFile(t, filepath.Join(dir, "left.dae"), "include { shared.dae }\nglobal { lan_interface: left }\n")
			writeConfigFile(t, filepath.Join(dir, "right.dae"), "include { shared.dae }\nglobal { lan_interface: right }\n")
			merger := NewMerger(entry)
			for range 2 {
				sections, entries, err := merger.Merge()
				if err != nil {
					t.Fatal(err)
				}
				conf, err := New(sections)
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(conf.Global.LanInterface, test.want) || len(entries) != test.files {
					t.Fatalf("interfaces = %v, files = %v; want %v in %d files", conf.Global.LanInterface, entries, test.want, test.files)
				}
			}
		})
	}
}

func TestMergerPreservesCircularIncludeDetection(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "config.dae")
	writeConfigFile(t, filepath.Join(dir, "config.d", "child.dae"), "include { config.dae ./config.dae }\n")
	writeConfigFile(t, entry, "include { config.d/child.dae ./config.d/*.dae config.d/*.dae }\nglobal {}\nrouting { fallback: direct }\n")

	if _, _, err := NewMerger(entry).Merge(); !errors.Is(err, ErrCircularInclude) {
		t.Fatalf("error = %v, want ErrCircularInclude", err)
	}
}

func TestMergerCountsDistinctFilesAtLimit(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "config.dae")
	writeConfigFile(t, entry, "include { parts/*.dae parts/0000.dae }\nrouting { fallback: direct }\n")
	for i := range maxConfigFiles - 1 {
		content := ""
		if i == 0 {
			content = "global {}\n"
		} else if i == maxConfigFiles-2 {
			content = "include { parts/0000.dae }\n"
		}
		writeConfigFile(t, filepath.Join(dir, "parts", fmt.Sprintf("%04d.dae", i)), content)
	}
	if _, entries, err := Load(entry); err != nil || len(entries) != maxConfigFiles {
		t.Fatalf("Load at file limit: %d entries, %v", len(entries), err)
	}
	writeConfigFile(t, filepath.Join(dir, "parts", "extra.dae"), "")
	if _, _, err := Load(entry); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("Load over file limit error = %v, want file limit", err)
	}
}

func TestMergerRejectsExcessiveIncludeDepth(t *testing.T) {
	dir := t.TempDir()
	for depth := 0; depth <= maxIncludeDepth+1; depth++ {
		path := filepath.Join(dir, fmt.Sprintf("%d.dae", depth))
		content := "global {}\n"
		if depth <= maxIncludeDepth {
			content = fmt.Sprintf("include { %d.dae }\n", depth+1)
		}
		writeConfigFile(t, path, content)
	}
	if _, _, err := NewMerger(filepath.Join(dir, "0.dae")).Merge(); err == nil || !strings.Contains(err.Error(), "depth exceeds") {
		t.Fatalf("Merge deep include error = %v, want depth limit", err)
	}
}

func TestUnsqueezeEntriesEnforcesFileLimit(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, filepath.Join(dir, "a.dae"), "global {}\n")
	writeConfigFile(t, filepath.Join(dir, "b.dae"), "global {}\n")
	if _, err := unsqueezeEntries([]string{filepath.Join(dir, "*.dae")}, 1); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("unsqueezeEntries error = %v, want file limit", err)
	}
}

func TestUnsqueezeEntriesPreservesGlobOrderingWithoutDuplicates(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.dae")
	b := filepath.Join(dir, "nested", "b.dae")
	writeConfigFile(t, a, "global {}\n")
	writeConfigFile(t, b, "global {}\n")
	writeConfigFile(t, filepath.Join(dir, "nested", "ignored.txt"), "ignored\n")

	nestedPattern := filepath.Join(dir, "*", "*.dae")
	got, err := unsqueezeEntries([]string{b, nestedPattern, filepath.Join(dir, "*.dae"), nestedPattern}, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{b, a}
	if !slices.Equal(got, want) {
		t.Fatalf("unsqueezeEntries = %v, want %v", got, want)
	}
}

func BenchmarkUnsqueezeEntriesRepeatedPatterns(b *testing.B) {
	dir := b.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.dae"), nil, 0600); err != nil {
		b.Fatal(err)
	}
	for _, count := range []int{1, 100} {
		b.Run(fmt.Sprintf("patterns=%d", count), func(b *testing.B) {
			patterns := make([]string, count)
			for i := range patterns {
				patterns[i] = filepath.Join(dir, "*.dae")
			}
			for b.Loop() {
				entries, err := unsqueezeEntries(patterns, 1)
				if err != nil || len(entries) != 1 {
					b.Fatalf("unsqueezeEntries = %v, %v; want one file", entries, err)
				}
			}
		})
	}
}

func TestUnsqueezeEntriesAllowsExactFileLimit(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, filepath.Join(dir, "b.dae"), "global {}\n")
	writeConfigFile(t, filepath.Join(dir, "a.dae"), "global {}\n")
	got, err := unsqueezeEntries([]string{filepath.Join(dir, "*.dae")}, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(dir, "a.dae"), filepath.Join(dir, "b.dae")}
	if !slices.Equal(got, want) {
		t.Fatalf("unsqueezeEntries = %v, want %v", got, want)
	}
}
