// SPDX-License-Identifier: AGPL-3.0-only

// dae-routing-abi exports bpf2go's numeric enums without its platform-specific
// loaders, keeping common packages independent of the control plane and eBPF.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

func extract(source []byte) ([]byte, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", source, 0)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString("// Code generated from routing_abi.h via bpf2go; DO NOT EDIT.\n\npackage routingabi\n\nconst (\n")
	count := 0
	for _, decl := range f.Decls {
		g, ok := decl.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, spec := range g.Specs {
			v := spec.(*ast.ValueSpec)
			// bpf2go also emits untyped strings naming maps and variables.
			if len(v.Values) == 1 && v.Type == nil {
				if value, ok := v.Values[0].(*ast.BasicLit); ok && value.Kind == token.STRING {
					continue
				}
			}
			typ, ok := v.Type.(*ast.Ident)
			if !ok || len(v.Names) != 1 || len(v.Values) != 1 {
				return nil, fmt.Errorf("unsupported bpf2go constant declaration")
			}
			name, ok := strings.CutPrefix(v.Names[0].Name, typ.Name)
			if !ok || !ast.IsExported(name) {
				return nil, fmt.Errorf("unsupported bpf2go enum name %q", v.Names[0].Name)
			}
			fmt.Fprintf(&out, "%s = ", name)
			if err := format.Node(&out, fset, v.Values[0]); err != nil {
				return nil, err
			}
			out.WriteByte('\n')
			count++
		}
	}
	if count == 0 {
		return nil, fmt.Errorf("no bpf2go enum constants found")
	}
	out.WriteString(")\n")
	return format.Source(out.Bytes())
}

func run(output string, patterns []string) error {
	var result []byte
	for _, pattern := range patterns {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			return err
		}
		for _, path := range paths {
			source, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			generated, err := extract(source)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			if result != nil && !bytes.Equal(result, generated) {
				return fmt.Errorf("routing ABI differs across BPF targets: %s", path)
			}
			result = generated
		}
	}
	if result == nil || output == "" {
		return fmt.Errorf("usage: dae-routing-abi -output <file> <bpf2go source patterns>")
	}
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return err
	}
	return os.WriteFile(output, result, 0644)
}

func main() {
	output := flag.String("output", "", "generated Go constants file")
	flag.Parse()
	if err := run(*output, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "dae-routing-abi:", err)
		os.Exit(1)
	}
}
