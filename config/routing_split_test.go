// SPDX-License-Identifier: AGPL-3.0-only
package config

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestRoutingRuleSetsSplitAcrossIncludes(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "config.dae")
	writeConfigFile(t, entry, `global {}
 include { config.d/*.dae }
 routing { use: base, proxy_rules
 fallback: proxy }
 `)
	writeConfigFile(t, filepath.Join(dir, "config.d/10-base.dae"), `routing { rule_set { base { dip(192.168.0.0/16) -> direct } } }`)
	writeConfigFile(t, filepath.Join(dir, "config.d/20-proxy.dae"), `routing { rule_set { proxy_rules { domain(full: example.com) -> proxy } } }`)
	writeConfigFile(t, filepath.Join(dir, "config.d/30-interfaces.dae"), `routing { policy { lan { use: base
 fallback: direct } }
 interface { br-lan: lan } }`)
	sections, entries, err := NewMerger(entry).Merge()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("included files = %v", entries)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	var uses []string
	for _, s := range conf.Routing.Policies[0].Statements {
		uses = append(uses, s.Use)
	}
	if !slices.Equal(uses, []string{"base", "proxy_rules"}) {
		t.Fatalf("use order = %v", uses)
	}
	encoded, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	sections, err = config_parser.Parse(string(encoded))
	if err != nil {
		t.Fatal(err)
	}
	again, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if !sameConfiguration(conf.Routing, again.Routing) {
		t.Fatalf("routing changed on round trip:\n%s", encoded)
	}
}

func TestStructuredRoutingRejectsUnsafeAndExcessiveAST(t *testing.T) {
	fallback := &config_parser.Function{Name: "direct"}
	base := func() *Routing {
		return &Routing{Policies: []RoutingPolicy{{Fallback: fallback}}}
	}
	tests := []struct {
		name   string
		mutate func(*Routing)
	}{
		{"invalid section name", func(r *Routing) { r.RuleSets = []RoutingRuleSet{{Name: "123"}} }},
		{"nil rule", func(r *Routing) {
			r.Policies[0].Statements = append(r.Policies[0].Statements, RoutingStatement{Kind: RoutingStatementRule})
		}},
		{"unknown statement", func(r *Routing) {
			r.Policies[0].Statements = append(r.Policies[0].Statements, RoutingStatement{Kind: 99})
		}},
		{"invalid interface", func(r *Routing) {
			r.Interfaces = []RoutingInterface{{Name: "bad/name", Policy: "lan"}}
		}},
		{"too many statements", func(r *Routing) { r.Policies[0].Statements = make([]RoutingStatement, maxRoutingStatements+1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := base()
			test.mutate(r)
			if err := r.Validate(); err == nil {
				t.Fatal("accepted invalid AST")
			}
			if _, err := (&Config{Routing: *r}).Marshal(2); err == nil {
				t.Fatal("serialized invalid AST")
			}
		})
	}
	// Both declaration orders must enforce depth, including already memoized sets.
	for _, reverse := range []bool{false, true} {
		r := base()
		r.RuleSets = []RoutingRuleSet{{Name: "set0"}}
		for i := 1; i <= maxRoutingReferenceDepth; i++ {
			r.RuleSets = append(r.RuleSets, RoutingRuleSet{Name: fmt.Sprintf("set%d", i), Statements: []RoutingStatement{{Kind: RoutingStatementUse, Use: fmt.Sprintf("set%d", i-1)}}})
		}
		if reverse {
			slices.Reverse(r.RuleSets)
		}
		if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "reference depth") {
			t.Fatalf("reverse=%v error=%v", reverse, err)
		}
	}
}

func TestRoutingDeclarationsCannotBeAppendedAcrossFiles(t *testing.T) {
	for _, kind := range []string{"rule_set", "policy"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			entry := filepath.Join(dir, "config.dae")
			body := "dport(80) -> direct"
			if kind == "policy" {
				body += "\nfallback: direct"
			}
			writeConfigFile(t, entry, "global {}\ninclude { child.dae }\nrouting { fallback: direct\n"+kind+" { a { "+body+" } } }")
			writeConfigFile(t, filepath.Join(dir, "child.dae"), "routing { "+kind+" { a { "+body+" } } }")
			sections, _, err := NewMerger(entry).Merge()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New(sections); err == nil || !strings.Contains(err.Error(), "duplicate routing "+kind) {
				t.Fatalf("duplicate declaration accepted: %v", err)
			}
		})
	}
}
