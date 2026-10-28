/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestParseFunctionParam(t *testing.T) {
	function := &config_parser.Function{Name: "direct", Params: []*config_parser.Param{{Key: "mark", Val: "1"}}}
	for _, test := range []struct {
		name  string
		param *config_parser.Param
		want  *config_parser.Function
	}{
		{name: "literal", param: &config_parser.Param{Val: "direct", ValueList: []string{"direct"}}, want: &config_parser.Function{Name: "direct"}},
		{name: "quoted reserved name", param: &config_parser.Param{Val: "must", ValueList: []string{"must"}, Quoted: true}, want: &config_parser.Function{Name: "must", Quoted: true}},
		{name: "quoted comma", param: &config_parser.Param{Val: "a,b", ValueList: []string{"a,b"}, Quoted: true}, want: &config_parser.Function{Name: "a,b", Quoted: true}},
		{name: "quoted empty name", param: &config_parser.Param{ValueList: []string{""}, Quoted: true}, want: &config_parser.Function{Quoted: true}},
		{name: "function", param: &config_parser.Param{AndFunctions: []*config_parser.Function{function}}, want: function},
		{name: "nil parameter"},
		{name: "missing value", param: &config_parser.Param{}},
		{name: "empty literals", param: &config_parser.Param{ValueList: []string{}}},
		{name: "multiple literals", param: &config_parser.Param{Val: "a,b", ValueList: []string{"a", "b"}}},
		{name: "empty functions", param: &config_parser.Param{AndFunctions: []*config_parser.Function{}}},
		{name: "nil function", param: &config_parser.Param{AndFunctions: []*config_parser.Function{nil}}},
		{name: "multiple functions", param: &config_parser.Param{AndFunctions: []*config_parser.Function{function, function}}},
		{name: "annotation", param: &config_parser.Param{ValueList: []string{"direct"}, Annotation: []*config_parser.Param{{Val: "x"}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseFunctionParam(test.param)
			if test.want == nil {
				if err == nil {
					t.Fatalf("invalid parameter accepted: %+v", test.param)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("function = %+v, %v; want %+v", got, err, test.want)
			}
		})
	}
}

func TestParamParserFunctions(t *testing.T) {
	for _, value := range []string{"random", `"must"`, `"a,b"`, `""`, "fixed(0)", "fixed(0) && fixed(1)", "random,min"} {
		t.Run(value, func(t *testing.T) {
			sections, err := config_parser.Parse("group { policy: " + value + " }")
			if err != nil {
				t.Fatal(err)
			}
			var list struct {
				Functions []*config_parser.Function `mapstructure:"policy"`
			}
			if err := ParamParser(reflect.ValueOf(&list), sections[0]); err != nil {
				t.Fatal(err)
			}
			param := sections[0].Items[0].Value.(*config_parser.Param)
			if param.AndFunctions != nil {
				if !slices.Equal(list.Functions, param.AndFunctions) {
					t.Fatalf("functions not retained: %+v", list.Functions)
				}
			} else {
				if len(list.Functions) != len(param.ValueList) {
					t.Fatalf("literal boundaries lost: %+v", list.Functions)
				}
				for i, function := range list.Functions {
					if function.Name != param.ValueList[i] || function.Quoted != param.Quoted {
						t.Fatalf("literal changed: %+v", function)
					}
				}
			}

			var group Group
			err = ParamParser(reflect.ValueOf(&group), sections[0])
			if (err == nil) != (len(list.Functions) == 1) {
				t.Fatalf("single-value cardinality check: %v", err)
			}
			if err == nil && !reflect.DeepEqual(group.Policy, list.Functions[0]) {
				t.Fatalf("single function changed: %+v", group.Policy)
			}
		})
	}
}

func TestParamParserPreservesFieldSemantics(t *testing.T) {
	type settings struct {
		Present map[string]bool `mapstructure:"_"`
		Names   []string        `mapstructure:"names" default:"default,values"`
		Enabled bool            `mapstructure:"enabled" default:"true" required:""`
		Count   uint16          `mapstructure:"count" default:"0x100"`
	}
	for _, test := range []struct {
		input string
		want  []string
	}{
		{"settings { enabled: false }", []string{"default", "values"}},
		{"settings { enabled: false\nnames: a,b\nnames: c }", []string{"a", "b", "c"}},
	} {
		sections, err := config_parser.Parse(test.input)
		if err != nil {
			t.Fatal(err)
		}
		var got settings
		if err := ParamParser(reflect.ValueOf(&got), sections[0]); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got.Names, test.want) || got.Enabled || got.Count != 0x100 || !got.Present["enabled"] || got.Present["count"] {
			t.Fatalf("field semantics changed: %+v", got)
		}
	}
	for _, input := range []string{"settings {}", "settings { enabled: false\nunknown: value }", "settings { enabled: false\nnames: name(test) }"} {
		sections, err := config_parser.Parse(input)
		if err != nil {
			t.Fatal(err)
		}
		var got settings
		if err := ParamParser(reflect.ValueOf(&got), sections[0]); err == nil {
			t.Fatalf("invalid settings accepted: %s", input)
		}
	}
}

func TestNewRejectsMultipleGroupPolicies(t *testing.T) {
	for _, policy := range []string{"fixed(0) && fixed(1)", "random,min"} {
		sections, err := config_parser.Parse("global {}\ngroup { proxy { policy: " + policy + " } }\nrouting { fallback: direct }")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := New(sections); err == nil || !strings.Contains(err.Error(), "expected exactly 1 function") {
			t.Fatalf("multiple group policies error = %v; policy: %s", err, policy)
		}
	}
}

func TestNewRejectsMultipleRoutingFallbacks(t *testing.T) {
	for _, fallback := range []string{"direct(test) && block(test)", "direct,block"} {
		sections, err := config_parser.Parse("global {}\nrouting { fallback: " + fallback + " }")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := New(sections); err == nil {
			t.Fatalf("multiple routing fallbacks accepted: %s", fallback)
		}
	}
}

func TestNewRejectsRemovedDNSSection(t *testing.T) {
	for _, direction := range []string{"request", "response"} {
		sections, err := config_parser.Parse("global {}\nrouting { fallback: direct }\ndns { routing { " + direction + " { fallback: direct } } }")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := New(sections); err == nil || !strings.Contains(err.Error(), "unknown section: dns") {
			t.Fatalf("removed core DNS section error = %v", err)
		}
	}
}
