/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestRejectReservedGroupNames(t *testing.T) {
	for _, name := range []string{
		"rules",
		"direct",
		"block",
		"must_rules",
		"bump",
	} {
		t.Run(name, func(t *testing.T) {
			sections, err := config_parser.Parse("global {}\ngroup { " + name + " { policy: fixed(0) } }\nrouting { fallback: direct }")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New(sections); err == nil || !strings.Contains(err.Error(), "group name") {
				t.Fatalf("error = %v, want reserved group name error", err)
			}
		})
	}
}

func TestRejectInternalLogicalGroupNames(t *testing.T) {
	for _, name := range []string{"<OR>", "<AND>"} {
		if err := validateGroupNames(&Config{Group: []Group{{Name: name}}}); err == nil {
			t.Fatalf("group name %q was accepted", name)
		}
	}
}

func TestAllowUnambiguousGroupName(t *testing.T) {
	sections, err := config_parser.Parse("global {}\ngroup { rules_proxy { policy: fixed(0) } }\nrouting { fallback: direct }")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(sections); err != nil {
		t.Fatal(err)
	}
}

func TestMarshalRejectsAmbiguousGroupName(t *testing.T) {
	_, err := (&Config{Group: []Group{{Name: "rules"}}}).Marshal(2)
	if err == nil || !strings.Contains(err.Error(), `group name "rules"`) {
		t.Fatalf("error = %v, want ambiguous group name error", err)
	}
}

func TestAllowQuotedMustGroupName(t *testing.T) {
	conf := parseConfig(t, `global {}
 group {must_edge {policy:fixed(0)}}
 routing {fallback:"must_edge"}`)
	if conf.Routing.Policies[0].Fallback.Name != "must_edge" {
		t.Fatal("literal group name changed")
	}
}
