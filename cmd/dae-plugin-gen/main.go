// SPDX-License-Identifier: AGPL-3.0-only

// dae-plugin-gen reads the root mitm_plugins.cfg and generates cmd's setup table.
package main

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"regexp"
	"strings"
)

const (
	configFile = "mitm_plugins.cfg"
	outputFile = "cmd/mitm_plugins_generated.go"
)

// Go checks import paths, Plugin definitions and duplicate map keys at compile time.
func generate(data []byte) ([]byte, error) {
	var out, setups bytes.Buffer
	fmt.Fprintln(&out, "// Code generated from mitm_plugins.cfg; DO NOT EDIT.")
	fmt.Fprintln(&out, "//go:build linux\n\npackage cmd")
	fmt.Fprintln(&out, "\nimport (\n\"github.com/daeuniverse/dae/component/mitm/plugin\"")
	for line, text := range strings.Split(string(data), "\n") {
		value, _, _ := strings.Cut(text, "#")
		if strings.TrimSpace(value) == "" {
			continue
		}
		name, path, ok := strings.Cut(value, ":")
		name, path = strings.TrimSpace(name), strings.TrimSpace(path)
		if !ok || name == "" || path == "" {
			return nil, fmt.Errorf("line %d: expected <type>:<Go import path>", line+1)
		}
		if !regexp.MustCompile(`^[a-z][a-z0-9_-]*$`).MatchString(name) || name == "ca" || name == "status" || name == "help" {
			return nil, fmt.Errorf("line %d: invalid or reserved MITM command name %q", line+1, name)
		}
		fmt.Fprintf(&out, "plugin%d %q\n", line, path)
		fmt.Fprintf(&setups, "%q: plugin%d.Plugin,\n", name, line)
	}
	fmt.Fprintln(&out, ")\n\nfunc compiledMITMPlugins() map[string]plugin.Definition {\nreturn map[string]plugin.Definition{")
	out.Write(setups.Bytes())
	fmt.Fprintln(&out, "}\n}")
	return format.Source(out.Bytes())
}

func run() error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}
	data, err = generate(data)
	if err != nil {
		return fmt.Errorf("%s: %w", configFile, err)
	}
	return os.WriteFile(outputFile, data, 0644)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dae-plugin-gen:", err)
		os.Exit(1)
	}
}
