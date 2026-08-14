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

func TestMergerPreservesCircularIncludeDetection(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "config.dae")
	writeConfigFile(t, filepath.Join(dir, "config.d", "child.dae"), "include { config.dae }\n")
	writeConfigFile(t, entry, "include { config.d/child.dae }\nglobal {}\nrouting { fallback: direct }\n")

	if _, _, err := NewMerger(entry).Merge(); !errors.Is(err, ErrCircularInclude) {
		t.Fatalf("error = %v, want ErrCircularInclude", err)
	}
}
