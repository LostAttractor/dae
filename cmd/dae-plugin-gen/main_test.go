// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestConfigSelection(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, config := range []string{
		"# types\nsurge:github.com/daeuniverse/dae/plugins/surge\n demo : example.com/dae-mitm-demo # comment\n",
		"# empty selection\n",
	} {
		if err := os.WriteFile(configFile, []byte(config), 0644); err != nil {
			t.Fatal(err)
		}
		if err := run(configFile); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(outputFile)
		if err != nil {
			t.Fatal(err)
		}
		code := string(data)
		if strings.Contains(config, "demo") {
			for _, want := range []string{"package compiledplugins", "func Definitions()", `"surge": plugin1.Plugin`, `"demo":  plugin2.Plugin`, `"example.com/dae-mitm-demo"`} {
				if !strings.Contains(code, want) {
					t.Fatalf("missing %q in %s", want, code)
				}
			}
		} else if strings.Contains(code, "example.com") || !strings.Contains(code, "map[string]plugin.Definition{}") {
			t.Fatalf("stale selection: %s", code)
		}
	}
}

func TestLocalSelectionAndExampleDefault(t *testing.T) {
	t.Chdir(t.TempDir())
	example := []byte("default:example.com/default\n")
	if err := os.WriteFile(exampleFile, example, 0644); err != nil {
		t.Fatal(err)
	}
	if err := run(configFile); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(configFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("generation wrote local configuration: %v", err)
	}
	for _, selection := range [][]byte{nil, []byte("local:example.com/local\n"), {}} {
		input := example
		if selection != nil {
			input = selection
			if err := os.WriteFile(configFile, input, 0644); err != nil {
				t.Fatal(err)
			}
		}
		if err := run(configFile); err != nil {
			t.Fatal(err)
		}
		want, err := generate(input)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(outputFile)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("wrong selection for %q: %s (%v)", selection, got, err)
		}
		if selection != nil {
			got, err := os.ReadFile(configFile)
			if err != nil || !bytes.Equal(got, selection) {
				t.Fatalf("local configuration changed: %q (%v)", got, err)
			}
		}
	}
	before, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"bad", "local:example.com/a\nlocal:example.com/b"} {
		if err := os.WriteFile(configFile, []byte(invalid), 0644); err != nil {
			t.Fatal(err)
		}
		if err := run(configFile); err == nil || !strings.Contains(err.Error(), configFile+": line") {
			t.Fatalf("invalid local selection fell back to example: %v", err)
		}
		after, err := os.ReadFile(outputFile)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("invalid selection replaced the registry: %v", err)
		}
	}
}

func TestMalformedConfig(t *testing.T) {
	for _, input := range []string{"surge", ":example.com/p", "surge:", "ca:example.com/p", "status:example.com/p", "help:example.com/p", "bad/name:example.com/p"} {
		if _, err := generate([]byte(input)); err == nil || !strings.Contains(err.Error(), "line 1:") {
			t.Fatalf("expected line-numbered syntax error for %q, got %v", input, err)
		}
	}
}

func TestExplicitSelection(t *testing.T) {
	t.Chdir(t.TempDir())
	for name, contents := range map[string]string{
		configFile:   "local:example.com/local\n",
		exampleFile:  "default:example.com/default\n",
		"custom.cfg": "selected:example.com/selected\n",
	} {
		if err := os.WriteFile(name, []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := run("custom.cfg"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(outputFile)
	if err != nil || !bytes.Contains(before, []byte(`"example.com/selected"`)) || bytes.Contains(before, []byte(`"example.com/local"`)) {
		t.Fatalf("explicit selection did not override local configuration: %s (%v)", before, err)
	}
	if err := run("missing.cfg"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing explicit selection did not fail: %v", err)
	}
	after, err := os.ReadFile(outputFile)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("missing explicit selection changed the registry: %v", err)
	}
	local, err := os.ReadFile(configFile)
	if err != nil || string(local) != "local:example.com/local\n" {
		t.Fatalf("explicit selection changed local configuration: %q (%v)", local, err)
	}
}
