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

	"github.com/daeuniverse/dae/pkg/config_parser"
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

func TestMarshalPolicylessGroupAndQuotedTargets(t *testing.T) {
	conf1 := parseConfig(t, `
global {}
node {
	relay: 'socks5://127.0.0.1:1080'
	'socks5://127.0.0.1:1081#香港 01'
}
group {
	entry {
		filter: name(relay)
	}
	exit {
		group(entry) -> node('香港 01') [priority: 1]
		policy: fixed(0)
	}
	typed {
		node(relay) -> group(entry)
		policy: fixed(0)
	}
}

routing {
	domain(full: example.com) -> '香港 01'(skip_while_noalive)
	fallback: '香港 01'(mark: 0x800)
}
`)
	raw, err := conf1.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	marshaled := string(raw)
	if strings.Contains(marshaled[strings.Index(marshaled, "entry {"):strings.Index(marshaled, "exit {")], "policy:") {
		t.Fatalf("policyless group gained a policy:\n%s", marshaled)
	}
	if !strings.Contains(marshaled, `->"香港 01"("skip_while_noalive")`) {
		t.Fatalf("quoted routing target was not preserved:\n%s", marshaled)
	}
	if !strings.Contains(marshaled, `fallback:"香港 01"(mark:"0x800")`) {
		t.Fatalf("quoted fallback was not preserved:\n%s", marshaled)
	}
	if !strings.Contains(marshaled, `group("entry")->node("香港 01") [priority:"1"]`) {
		t.Fatalf("proxy path was not preserved:\n%s", marshaled)
	}
	if !strings.Contains(marshaled, `node("relay")->group("entry")`) {
		t.Fatalf("typed proxy path was not preserved:\n%s", marshaled)
	}
	sections, err := config_parser.Parse(marshaled)
	if err != nil {
		t.Fatal(err)
	}
	conf2, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(conf1, conf2) {
		t.Fatalf("round trip differs:\nfirst: %#v\nsecond: %#v", conf1, conf2)
	}
}

func TestMarshalPreservesQuotedMustPrefixTargets(t *testing.T) {
	conf1 := parseConfig(t, `
global {}
routing {
	domain(full: example.com) -> 'must_edge'
	fallback: 'must_fallback'
}
`)
	raw, err := conf1.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	marshaled := string(raw)
	if !strings.Contains(marshaled, `->"must_edge"`) || !strings.Contains(marshaled, `fallback:"must_fallback"`) {
		t.Fatalf("quoted must targets were not preserved:\n%s", marshaled)
	}
	sections, err := config_parser.Parse(marshaled)
	if err != nil {
		t.Fatal(err)
	}
	conf2, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(conf1, conf2) {
		t.Fatalf("round trip differs:\nfirst: %#v\nsecond: %#v", conf1, conf2)
	}
}
