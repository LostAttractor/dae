/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestParseFunctionOrString(t *testing.T) {
	want := &config_parser.Function{Name: "direct"}
	tests := []struct {
		name    string
		value   FunctionOrString
		want    *config_parser.Function
		wantErr bool
	}{
		{name: "string", value: "direct", want: want},
		{name: "function", value: want, want: want},
		{name: "single function list", value: []*config_parser.Function{want}, want: want},
		{name: "nil function", value: (*config_parser.Function)(nil), wantErr: true},
		{name: "nil function list", value: ([]*config_parser.Function)(nil), wantErr: true},
		{name: "nil function list element", value: []*config_parser.Function{nil}, wantErr: true},
		{name: "multiple functions", value: []*config_parser.Function{want, {Name: "proxy"}}, wantErr: true},
		{name: "unsupported type", value: 1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFunctionOrString(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got.Name != tt.want.Name {
				t.Fatalf("Name = %q, want %q", got.Name, tt.want.Name)
			}
		})
	}
}

func TestParseFunctionListOrString(t *testing.T) {
	want := &config_parser.Function{Name: "random"}
	valid := []struct {
		value   FunctionListOrString
		wantLen int
	}{
		{value: "random", wantLen: 1},
		{value: want, wantLen: 1},
		{value: []*config_parser.Function{}, wantLen: 0},
		{value: []*config_parser.Function{want}, wantLen: 1},
	}
	for _, tt := range valid {
		got, err := ParseFunctionListOrString(tt.value)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != tt.wantLen || len(got) == 1 && got[0].Name != want.Name {
			t.Fatalf("unexpected functions: %#v", got)
		}
	}
	for _, value := range []FunctionListOrString{
		(*config_parser.Function)(nil),
		([]*config_parser.Function)(nil),
		[]*config_parser.Function{want, nil},
		true,
	} {
		if _, err := ParseFunctionListOrString(value); err == nil {
			t.Errorf("invalid value %#v was accepted", value)
		}
	}
}

func TestNewRejectsMultipleRoutingFallbacks(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing { fallback: direct(test) && block(test) }
`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(sections); err == nil {
		t.Fatal("multiple routing fallbacks were accepted")
	}
}

func TestNewRejectsRemovedDNSSection(t *testing.T) {
	tests := []struct {
		name string
		dns  string
		path string
	}{
		{
			name: "request",
			dns:  `request { fallback: asis(test) && block(test) }`,
			path: "unknown section: dns",
		},
		{
			name: "response",
			dns:  `response { fallback: accept(test) && block(test) }`,
			path: "unknown section: dns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sections, err := config_parser.Parse(`
global {}
routing { fallback: direct }
dns { routing { ` + tt.dns + ` } }
`)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New(sections); err == nil {
				t.Fatal("removed core DNS section was accepted")
			} else if !strings.Contains(err.Error(), tt.path) {
				t.Fatalf("error %q does not identify %s", err, tt.path)
			}
		})
	}
}
