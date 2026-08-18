/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMarshal(t *testing.T) {
	abs, err := filepath.Abs("../example.dae")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	tmpInput := filepath.Join(tmpDir, "example.dae")
	if err = os.WriteFile(tmpInput, raw, 0600); err != nil {
		t.Fatal(err)
	}
	merger := NewMerger(tmpInput)
	sections, _, err := merger.Merge()
	if err != nil {
		t.Fatal(err)
	}
	conf1, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	b, err := conf1.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(b))
	// Read it again.
	tmpOutput := filepath.Join(tmpDir, "test.dae")
	if err = os.WriteFile(tmpOutput, b, 0600); err != nil {
		t.Fatal(err)
	}
	sections, _, err = NewMerger(tmpOutput).Merge()
	if err != nil {
		t.Fatal(err)
	}
	conf2, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(conf1, conf2) {
		t.Fatal("not equal")
	}
}

func TestMarshalPreservesOmittedSoMark(t *testing.T) {
	conf := parseConfig(t, `
global {}
routing { fallback: direct }
`)
	b, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "so_mark_from_dae") {
		t.Fatalf("marshal added an omitted so_mark_from_dae: %s", b)
	}
	reparsed := parseConfig(t, string(b))
	if reparsed.Global.SoMarkFromDaeSet {
		t.Fatal("omitted so_mark_from_dae became explicit after marshal round trip")
	}
}
