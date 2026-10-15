// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func parseGroupFilterConfig(t *testing.T, groups string) *config.Config {
	t.Helper()
	sections, err := config_parser.Parse("global {}\ngroup {\n" + groups + "\n}\nrouting { fallback: filtered }")
	if err != nil {
		t.Fatal(err)
	}
	conf, err := config.New(sections)
	if err != nil {
		t.Fatal(err)
	}
	return conf
}

func TestGroupFilterMatchesCompletePaths(t *testing.T) {
	set := &DialerSet{nodeInfos: []*NodeInfo{
		testNode("A", "entry"), testNode("B", "exit"), testNode("C", "other"), testNode("source", "unrelated"),
	}}
	for _, policy := range []string{"", "policy: min_moving_avg", "policy: selector"} {
		t.Run(policy, func(t *testing.T) {
			for _, tc := range []struct {
				expression string
				want       []string
			}{
				{"group(source)", []string{"A -> B", "B", "C", "B"}},
				{"group(source) && name('A -> B')", []string{"A -> B"}},
				{"group(source) && name(B)", []string{"B", "B"}},
				{"group(source) && name(A)", nil},
				{"group(source) && name('A->B')", nil},
				{"group(source) && name(keyword: B)", []string{"A -> B", "B", "B"}},
				{"name(regex: '^A -> B$') && group(source)", []string{"A -> B"}},
				{"group(source) && !name(B)", []string{"A -> B", "C"}},
				{"group(source) && !name(keyword: B)", []string{"C"}},
				{"group(source) && subtag(exit) && name(keyword: B)", []string{"A -> B", "B", "B"}},
				{"group(source) && subtag(entry)", nil},
				{"group(source) && protocol('test -> test')", []string{"A -> B"}},
				{"group(source) && protocol(test)", []string{"B", "C", "B"}},
				{"group(source) && link('test://entry/A -> test://exit/B')", []string{"A -> B"}},
				{"group(source) && link(keyword: 'entry/A')", []string{"A -> B"}},
			} {
				t.Run(tc.expression, func(t *testing.T) {
					conf := parseGroupFilterConfig(t, `
filtered { filter: `+tc.expression+`
           policy: random }
source {
 node(A) -> node(B)
 node(B) [interface: cu]
 node(C)
 node(B)
 `+policy+`
}`)
					compiler, err := NewGroupCompiler(set, conf.Group, []string{"filtered"})
					if err != nil {
						t.Fatal(err)
					}
					if got := expandedNames(t, compiler, &conf.Group[0]); !slices.Equal(got, tc.want) {
						t.Fatalf("paths = %v, want %v", got, tc.want)
					}
				})
			}
		})
	}
}

func TestGroupFilterPreservesPathsAndAnnotations(t *testing.T) {
	conf := parseGroupFilterConfig(t, `
filtered {
 filter: group(narrowed) [priority: 4, add_latency: 5ms] -> node(C)
 policy: min_moving_avg
}
narrowed {
 filter: group(source) && name(keyword: B) [priority: 2]
 policy: selector
}
source {
 node(A) [interface: cu, mark: 32, priority: 3, add_latency: 10ms] -> node(B)
 node(B) [interface: cu, priority: 1]
 node(C)
 policy: random
}`)
	a, b, c := testNode("A", "entry"), testNode("B", "exit"), testNode("C", "other")
	compiler, err := NewGroupCompiler(&DialerSet{nodeInfos: []*NodeInfo{a, b, c}}, conf.Group, []string{"filtered"})
	if err != nil {
		t.Fatal(err)
	}
	paths, err := compiler.ExpandRoutable(&conf.Group[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || !slices.Equal(paths[0].Nodes, []*NodeInfo{a, b, c}) || !slices.Equal(paths[1].Nodes, []*NodeInfo{b, c}) {
		t.Fatalf("unexpected expanded paths: %+v", paths)
	}
	if paths[0].Annotation.Priority != 9 || paths[0].Annotation.AddLatency != 15*time.Millisecond ||
		paths[1].Annotation.Priority != 7 || paths[1].Annotation.AddLatency != 5*time.Millisecond {
		t.Fatalf("annotations = %+v, %+v", paths[0].Annotation, paths[1].Annotation)
	}
	if paths[0].Entry.Interface != "cu" || paths[0].Entry.Mark == nil || *paths[0].Entry.Mark != 32 ||
		paths[1].Entry.Interface != "cu" || paths[1].Entry.Mark != nil {
		t.Fatalf("entry options = %+v, %+v", paths[0].Entry, paths[1].Entry)
	}
	source, err := compiler.ExpandRoutable(&conf.Group[2])
	if err != nil {
		t.Fatal(err)
	}
	if len(source) != 3 || len(source[0].Nodes) != 2 || source[0].Annotation.Priority != 3 || source[0].Annotation.AddLatency != 10*time.Millisecond {
		t.Fatalf("filtering changed the source group: %+v", source)
	}
}

func TestGroupFilterValidation(t *testing.T) {
	for _, tc := range []struct{ name, groups, want string }{
		{"missing", "filtered { filter: name(absent) && group(missing) }", "group not found"},
		{"self cycle", "filtered { filter: group(filtered) && name(absent) }", "filtered -> filtered"},
		{"filter cycle", "filtered { filter: group(other) } other { filter: group(filtered) }", "filtered -> other -> filtered"},
		{"mixed cycle", "filtered { filter: group(other) } other { group(filtered) }", "filtered -> other -> filtered"},
		{"blank name", "filtered { filter: group(' ') }", "group filter requires"},
		{"multiple names", "filtered { filter: group(a, b) }", "group filter requires"},
		{"keyword", "filtered { filter: group(keyword: a) }", "group filter requires"},
		{"negation", "filtered { filter: !group(a) }", "group filter requires"},
		{"multiple sources", "filtered { filter: group(a) && group(a) } a {}", "only one group"},
		{"bad secondary filter", "filtered { filter: group(empty) && name(regex: '[') } empty { filter: name(absent) }", "bad regexp"},
		{"inherited later entry", "filtered { node(A) -> filter: group(source) } source { node(B) [interface: cu] }", "entry stage"},
		{"entry after empty prefix", "filtered { filter: name(absent) -> filter: group(source) } source { node(B) [interface: cu] }", "entry stage"},
		{"conflicting entry", "filtered { filter: group(source) [interface: ct] } source { node(B) [interface: cu] }", "conflicting entry interface"},
		{"policyless multiple paths", "filtered { filter: group(source) } source { node(A) node(B) policy: random }", "expands to 2 paths"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := parseGroupFilterConfig(t, tc.groups)
			set := &DialerSet{nodeInfos: []*NodeInfo{testNode("A", "entry"), testNode("B", "exit")}}
			compiler, err := NewGroupCompiler(set, conf.Group, []string{"filtered"})
			if err == nil {
				_, err = compiler.ExpandRoutable(&conf.Group[0])
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestGroupFilterEntryAddressFamilies(t *testing.T) {
	for _, tc := range []struct {
		filter, source string
		want           []string
	}{
		{"ipversion(4)", "node(v4) -> node(v6)", []string{"v4 -> v6"}},
		{"ipversion(6)", "node(v4) -> node(v6)", nil},
		{"ipversion(6)", "filter: name(dual) && ipversion(4)", nil},
		{"ipversion(4)", "filter: name(dual) && ipversion(4)", []string{"dual"}},
	} {
		t.Run(tc.filter+"/"+tc.source, func(t *testing.T) {
			conf := parseGroupFilterConfig(t, "filtered { filter: group(source) && "+tc.filter+" } source { "+tc.source+" }")
			v4, v6, dual := testNode("v4", ""), testNode("v6", ""), testNode("dual", "")
			v4.Property.Address, v6.Property.Address, dual.Property.Address = "192.0.2.1:1080", "[2001:db8::1]:1080", "proxy.test:1080"
			compiler, err := NewGroupCompiler(&DialerSet{nodeInfos: []*NodeInfo{v4, v6, dual}}, conf.Group, []string{"filtered"})
			if err != nil {
				t.Fatal(err)
			}
			if got := expandedNames(t, compiler, &conf.Group[0]); !slices.Equal(got, tc.want) {
				t.Fatalf("paths = %v, want %v", got, tc.want)
			}
		})
	}
}
