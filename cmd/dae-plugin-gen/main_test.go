// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"strings"
	"testing"
)

func TestConfigSelection(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir("cmd", 0755); err != nil {
		t.Fatal(err)
	}
	for _, config := range []string{
		"# types\nsurge:github.com/daeuniverse/dae/component/mitm/surge\n demo : example.com/dae-mitm-demo # comment\n",
		"# empty selection\n",
	} {
		if err := os.WriteFile(configFile, []byte(config), 0644); err != nil {
			t.Fatal(err)
		}
		if err := run(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(outputFile)
		if err != nil {
			t.Fatal(err)
		}
		code := string(data)
		if strings.Contains(config, "demo") {
			for _, want := range []string{"package cmd", `"surge": plugin1.Plugin`, `"demo":  plugin2.Plugin`, `"example.com/dae-mitm-demo"`} {
				if !strings.Contains(code, want) {
					t.Fatalf("missing %q in %s", want, code)
				}
			}
		} else if strings.Contains(code, "example.com") || !strings.Contains(code, "map[string]plugin.Definition{}") {
			t.Fatalf("stale selection: %s", code)
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
