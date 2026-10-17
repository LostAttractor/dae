// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestDecodeSettingsDefaultsAndOverrides(t *testing.T) {
	type settings struct {
		Enabled bool           `mapstructure:"enabled" default:"true"`
		Limit   int            `mapstructure:"limit" default:"7"`
		Timeout time.Duration  `mapstructure:"timeout" default:"3s"`
		Name    string         `mapstructure:"name" default:"fixture"`
		Labels  []string       `mapstructure:"labels" default:"first,second"`
		Custom  map[string]int `mapstructure:"_"`
	}
	for _, tc := range []struct {
		name, source string
		want         settings
	}{
		{"defaults", "", settings{Enabled: true, Limit: 7, Timeout: 3 * time.Second, Name: "fixture", Labels: []string{"first", "second"}}},
		{"explicit zero values", "enabled:false limit:0 timeout:0s name:'' labels:third", settings{Labels: []string{"third"}}},
		{"overrides", "limit:9 timeout:5s name:custom labels:'third,fourth'", settings{Enabled: true, Limit: 9, Timeout: 5 * time.Second, Name: "custom", Labels: []string{"third", "fourth"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := "fixture { " + tc.source + " }"
			sections, err := config_parser.Parse(source)
			if err != nil {
				t.Fatal(err)
			}
			original, err := config_parser.Parse(source)
			if err != nil {
				t.Fatal(err)
			}
			got := settings{Custom: map[string]int{"module": 1}}
			if err := DecodeSettings(sections[0], &got); err != nil {
				t.Fatal(err)
			}
			tc.want.Custom = map[string]int{"module": 1}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("decoded %+v, want %+v", got, tc.want)
			}
			if !reflect.DeepEqual(sections, original) {
				t.Fatal("decoding changed the input section")
			}
		})
	}
}

func TestDecodeSettingsRejectsInvalidInputWithoutValues(t *testing.T) {
	for _, source := range []string{
		"enabled:true enabled:false",
		"unknown:'private-value'",
		"enabled:'private-value'",
		"enabled:source(private-value)",
		"enabled:true [name:'private-value']",
		"nested { token:'private-value' }",
		"'private-value'",
	} {
		t.Run(source, func(t *testing.T) {
			sections, err := config_parser.Parse("fixture { " + source + " }")
			if err != nil {
				t.Fatal(err)
			}
			var target struct {
				Enabled bool `mapstructure:"enabled"`
			}
			if err := DecodeSettings(sections[0], &target); err == nil || strings.Contains(err.Error(), "private-value") {
				t.Fatalf("invalid or unsafe diagnostic: %v", err)
			}
		})
	}
}

func TestDecodeSettingsRejectsInvalidDefinitions(t *testing.T) {
	var nilTarget *struct{}
	for _, target := range []any{
		nil,
		nilTarget,
		struct{}{},
		new(1),
		&struct{ Untagged bool }{},
		&struct {
			hidden bool `mapstructure:"enabled"`
		}{},
		&struct {
			First  bool `mapstructure:"enabled"`
			Second bool `mapstructure:"enabled"`
		}{},
		&struct {
			Enabled bool `mapstructure:"enabled" default:"private-value"`
		}{},
	} {
		if err := DecodeSettings(&config_parser.Section{}, target); err == nil || strings.Contains(err.Error(), "private-value") {
			t.Fatalf("invalid target %T: %v", target, err)
		}
	}
	if err := DecodeSettings(nil, &struct{}{}); err == nil {
		t.Fatal("accepted a missing configuration section")
	}
}
