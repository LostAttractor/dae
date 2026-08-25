/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	D "github.com/daeuniverse/outbound/dialer"
)

func testNode(name, subtag string) *NodeInfo {
	link := fmt.Sprintf("test://%s/%s", subtag, name)
	return &NodeInfo{
		Link: link,
		Property: &dialer.Property{
			Property:        D.Property{Name: name, Protocol: "test", Address: name, Link: link},
			SubscriptionTag: subtag,
		},
	}
}

func pathNames(nodes []*NodeInfo) []string {
	names := make([]string, 0, len(nodes))
	for _, node := range nodes {
		names = append(names, node.Property.Name)
	}
	return names
}

func filterFunction(name string, params ...*config_parser.Param) *config_parser.Function {
	return &config_parser.Function{Name: name, Params: params}
}

func filterStage(filters []*config_parser.Function, annotations ...*config_parser.Param) *config_parser.Param {
	return &config_parser.Param{
		Key:          "filter",
		AndFunctions: filters,
		Annotation:   annotations,
	}
}

func subtagStage(subtag string, annotations ...*config_parser.Param) *config_parser.Param {
	return filterStage([]*config_parser.Function{filterFunction(FilterInput_SubscriptionTag, &config_parser.Param{Val: subtag})}, annotations...)
}

func nameStage(name string, annotations ...*config_parser.Param) *config_parser.Param {
	return filterStage([]*config_parser.Function{filterFunction(FilterInput_Name, &config_parser.Param{Val: name})}, annotations...)
}

func referenceStage(kind, name string, annotations ...*config_parser.Param) *config_parser.Param {
	return &config_parser.Param{
		AndFunctions: []*config_parser.Function{{Name: kind, Params: []*config_parser.Param{{Val: name}}}},
		Annotation:   annotations,
	}
}

func proxyPath(stages ...*config_parser.Param) *config_parser.ProxyPath {
	return &config_parser.ProxyPath{Stages: stages}
}

func randomPolicy() config.FunctionListOrString {
	return "random"
}

func annotation(key, value string) *config_parser.Param {
	return &config_parser.Param{Key: key, Val: value}
}

func expandedNames(t *testing.T, compiler *GroupCompiler, group *config.Group) []string {
	t.Helper()
	paths, err := compiler.ExpandRoutable(group)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(paths))
	for _, path := range paths {
		names = append(names, strings.Join(pathNames(path.Nodes), " -> "))
	}
	return names
}

func TestGroupCompilerExpandsPathExpressionsInStableOrder(t *testing.T) {
	set := &DialerSet{nodeInfos: []*NodeInfo{
		testNode("entry-1", "entry"),
		testNode("entry-2", "entry"),
		testNode("exit-1", "exit"),
		testNode("exit-2", "exit"),
	}}
	groups := []config.Group{
		{Name: "entries", Paths: []*config_parser.ProxyPath{proxyPath(subtagStage("entry"))}},
		{
			Name: "proxy_jp",
			Paths: []*config_parser.ProxyPath{
				proxyPath(nameStage("entry-1", annotation(dialer.AnnotationKey_Priority, "1"))),
				proxyPath(
					subtagStage("entry", annotation(dialer.AnnotationKey_AddLatency, "10ms")),
					subtagStage("exit", annotation(dialer.AnnotationKey_AddLatency, "20ms"), annotation(dialer.AnnotationKey_Priority, "2")),
				),
			},
			Policy: &config_parser.Function{Name: "fixed", Params: []*config_parser.Param{{Val: "2"}}},
		},
	}
	compiler, err := NewGroupCompiler(set, groups, []string{"proxy_jp"})
	if err != nil {
		t.Fatal(err)
	}
	paths, err := compiler.ExpandRoutable(compiler.SelectorGroups()[0])
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(paths))
	for _, path := range paths {
		got = append(got, strings.Join(pathNames(path.Nodes), " -> "))
	}
	want := []string{
		"entry-1",
		"entry-1 -> exit-1",
		"entry-2 -> exit-1",
		"entry-1 -> exit-2",
		"entry-2 -> exit-2",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
	if paths[0].Annotation.Priority != 1 {
		t.Fatalf("direct priority = %d", paths[0].Annotation.Priority)
	}
	for _, path := range paths[1:] {
		if path.Annotation.Priority != 2 || path.Annotation.AddLatency != 30*time.Millisecond {
			t.Fatalf("chain annotation = %#v", path.Annotation)
		}
	}
	policy, err := dialer.NewDialerSelectionPolicyFromGroupParam(compiler.SelectorGroups()[0])
	if err != nil {
		t.Fatal(err)
	}
	if got[policy.FixedIndex] != "entry-2 -> exit-1" {
		t.Fatalf("fixed(2) selected %q", got[policy.FixedIndex])
	}
}

func TestGroupCompilerExpandsTypedReferences(t *testing.T) {
	set := &DialerSet{nodeInfos: []*NodeInfo{
		testNode("relay", "node-relay"),
		testNode("group-hop", "group-relay"),
		testNode("group-hop-2", "group-relay"),
		testNode("exit", "exit"),
	}}
	groups := []config.Group{
		{
			Name: "outer",
			Paths: []*config_parser.ProxyPath{
				proxyPath(referenceStage("node", "relay"), referenceStage("node", "exit")),
				proxyPath(referenceStage("group", "relay"), nameStage("exit")),
			},
			Policy: randomPolicy(),
		},
		{Name: "relay", Paths: []*config_parser.ProxyPath{proxyPath(subtagStage("group-relay"))}},
	}
	compiler, err := NewGroupCompiler(set, groups, []string{"outer"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"relay -> exit", "group-hop -> exit", "group-hop-2 -> exit"}
	if got := expandedNames(t, compiler, compiler.SelectorGroups()[0]); !reflect.DeepEqual(got, want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
}

func TestGroupCompilerKeepsIndependentPathDeclarations(t *testing.T) {
	set := &DialerSet{nodeInfos: []*NodeInfo{testNode("node", "all")}}
	group := config.Group{
		Name: "target",
		Paths: []*config_parser.ProxyPath{
			proxyPath(nameStage("node", annotation(dialer.AnnotationKey_Priority, "1"))),
			proxyPath(nameStage("node", annotation(dialer.AnnotationKey_Priority, "2"))),
		},
		Policy: randomPolicy(),
	}
	compiler, err := NewGroupCompiler(set, []config.Group{group}, []string{"target"})
	if err != nil {
		t.Fatal(err)
	}
	paths, err := compiler.ExpandRoutable(compiler.SelectorGroups()[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0].Annotation.Priority != 1 || paths[1].Annotation.Priority != 2 {
		t.Fatalf("independent declarations were collapsed: %#v", paths)
	}
}

func TestGroupCompilerEmptyGroupSelectsAllNodes(t *testing.T) {
	set := &DialerSet{nodeInfos: []*NodeInfo{testNode("one", "all"), testNode("two", "all")}}
	group := config.Group{Name: "all", Policy: randomPolicy()}
	compiler, err := NewGroupCompiler(set, []config.Group{group}, []string{"all"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"one", "two"}
	if got := expandedNames(t, compiler, compiler.SelectorGroups()[0]); !reflect.DeepEqual(got, want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
}

func TestGroupCompilerPolicylessRoutingTargetMustBeSingleton(t *testing.T) {
	set := &DialerSet{nodeInfos: []*NodeInfo{testNode("one", "single"), testNode("two", "many"), testNode("three", "many")}}
	groups := []config.Group{
		{Name: "single", Paths: []*config_parser.ProxyPath{proxyPath(subtagStage("single"))}},
		{Name: "many", Paths: []*config_parser.ProxyPath{proxyPath(subtagStage("many"))}},
		{Name: "empty", Paths: []*config_parser.ProxyPath{proxyPath(subtagStage("missing"))}},
	}
	compiler, err := NewGroupCompiler(set, groups, []string{"single", "many", "empty"})
	if err != nil {
		t.Fatal(err)
	}
	paths, err := compiler.ExpandRoutable(&groups[0])
	if err != nil || len(paths) != 1 {
		t.Fatalf("singleton paths = %d, err = %v", len(paths), err)
	}
	if _, err = compiler.ExpandRoutable(&groups[1]); err == nil || !strings.Contains(err.Error(), "expands to 2 paths") {
		t.Fatalf("multi-path error = %v", err)
	}
	if _, err = compiler.ExpandRoutable(&groups[2]); err == nil || !strings.Contains(err.Error(), "expands to 0 paths") {
		t.Fatalf("empty-path error = %v", err)
	}
}

func TestGroupCompilerReferenceValidation(t *testing.T) {
	t.Run("ambiguous routing node", func(t *testing.T) {
		set := &DialerSet{nodeInfos: []*NodeInfo{testNode("duplicate", "a"), testNode("duplicate", "b")}}
		compiler, err := NewGroupCompiler(set, nil, []string{"duplicate"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = compiler.ResolveRoutingTarget("duplicate"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
			t.Fatalf("ambiguity error = %v", err)
		}
	})

	t.Run("group and node collision", func(t *testing.T) {
		set := &DialerSet{nodeInfos: []*NodeInfo{testNode("target", "nodes")}}
		groups := []config.Group{{Name: "target", Paths: []*config_parser.ProxyPath{proxyPath(subtagStage("nodes"))}, Policy: randomPolicy()}}
		compiler, err := NewGroupCompiler(set, groups, []string{"target"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = compiler.ResolveRoutingTarget("target"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
			t.Fatalf("collision error = %v", err)
		}
	})

	t.Run("ambiguous typed node", func(t *testing.T) {
		set := &DialerSet{nodeInfos: []*NodeInfo{testNode("relay", "a"), testNode("relay", "b")}}
		group := config.Group{Name: "outer", Paths: []*config_parser.ProxyPath{proxyPath(referenceStage("node", "relay"))}, Policy: randomPolicy()}
		if _, err := NewGroupCompiler(set, []config.Group{group}, []string{"outer"}); err == nil || !strings.Contains(err.Error(), "node is ambiguous") {
			t.Fatalf("typed node error = %v", err)
		}
	})

	t.Run("selector group stage", func(t *testing.T) {
		set := &DialerSet{nodeInfos: []*NodeInfo{testNode("node", "all")}}
		groups := []config.Group{
			{Name: "selector", Paths: []*config_parser.ProxyPath{proxyPath(subtagStage("all"))}, Policy: randomPolicy()},
			{Name: "outer", Paths: []*config_parser.ProxyPath{proxyPath(referenceStage("group", "selector"))}, Policy: randomPolicy()},
		}
		if _, err := NewGroupCompiler(set, groups, []string{"outer"}); err == nil || !strings.Contains(err.Error(), "selector group") {
			t.Fatalf("selector stage error = %v", err)
		}
	})

	t.Run("reference after empty filter", func(t *testing.T) {
		group := config.Group{
			Name:   "outer",
			Paths:  []*config_parser.ProxyPath{proxyPath(subtagStage("missing"), referenceStage("group", "missing"))},
			Policy: randomPolicy(),
		}
		if _, err := NewGroupCompiler(&DialerSet{}, []config.Group{group}, []string{"outer"}); err == nil || !strings.Contains(err.Error(), "group not found") {
			t.Fatalf("dead-branch reference error = %v", err)
		}
	})
}

func TestGroupCompilerRejectsPathCycles(t *testing.T) {
	groups := []config.Group{
		{Name: "a", Paths: []*config_parser.ProxyPath{proxyPath(referenceStage("group", "b"))}},
		{Name: "b", Paths: []*config_parser.ProxyPath{proxyPath(referenceStage("group", "c"))}},
		{Name: "c", Paths: []*config_parser.ProxyPath{proxyPath(referenceStage("group", "a"))}},
	}
	if _, err := NewGroupCompiler(&DialerSet{}, groups, nil); err == nil || !strings.Contains(err.Error(), "a -> b -> c -> a") {
		t.Fatalf("cycle error = %v", err)
	}
}

func TestGroupCompilerMergesAnnotationsAcrossTemplates(t *testing.T) {
	set := &DialerSet{nodeInfos: []*NodeInfo{testNode("entry", "entry"), testNode("exit", "exit")}}
	groups := []config.Group{
		{
			Name: "entry",
			Paths: []*config_parser.ProxyPath{proxyPath(subtagStage("entry",
				annotation(dialer.AnnotationKey_AddLatency, "20ms"),
				annotation(dialer.AnnotationKey_Priority, "1; 4(100ms,)"),
			))},
		},
		{
			Name: "exit",
			Paths: []*config_parser.ProxyPath{proxyPath(
				referenceStage("group", "entry", annotation(dialer.AnnotationKey_AddLatency, "10ms")),
				subtagStage("exit", annotation(dialer.AnnotationKey_AddLatency, "30ms"), annotation(dialer.AnnotationKey_Priority, "2; 8(,200ms)")),
			)},
			Policy: randomPolicy(),
		},
	}
	compiler, err := NewGroupCompiler(set, groups, []string{"entry", "exit"})
	if err != nil {
		t.Fatal(err)
	}
	paths, err := compiler.ExpandRoutable(compiler.SelectorGroups()[0])
	if err != nil {
		t.Fatal(err)
	}
	got := paths[0].Annotation
	if got.AddLatency != 60*time.Millisecond {
		t.Fatalf("annotation = %#v", got)
	}
	if priority := got.PriorityAt(150 * time.Millisecond); priority != 12 {
		t.Fatalf("priority at 150ms = %d, want 12", priority)
	}
}

func TestGroupCompilerRejectsLogicalRuntimeOptions(t *testing.T) {
	set := &DialerSet{nodeInfos: []*NodeInfo{testNode("node", "all")}}
	group := config.Group{
		Name:  "logical",
		Paths: []*config_parser.ProxyPath{proxyPath(subtagStage("all"))},
	}
	group.CheckInterval = time.Second
	if _, err := NewGroupCompiler(set, []config.Group{group}, nil); err == nil || !strings.Contains(err.Error(), "connectivity-check options") {
		t.Fatalf("logical runtime option error = %v", err)
	}
}

func TestGroupCompilerRejectsCheckAsyncPathAnnotation(t *testing.T) {
	set := &DialerSet{nodeInfos: []*NodeInfo{testNode("node", "all")}}
	group := config.Group{
		Name: "target",
		Paths: []*config_parser.ProxyPath{proxyPath(subtagStage("all",
			annotation("check_async", "true"),
		))},
		Policy: randomPolicy(),
	}
	if _, err := NewGroupCompiler(set, []config.Group{group}, []string{"target"}); err == nil || !strings.Contains(err.Error(), "unknown path-stage annotation: check_async") {
		t.Fatalf("path check_async error = %v", err)
	}
}

func TestGroupCompilerExpansionLimits(t *testing.T) {
	t.Run("maximum physical depth", func(t *testing.T) {
		node := testNode("hop", "all")
		stages := make([]*config_parser.Param, MaxProxyPathDepth)
		for i := range stages {
			stages[i] = referenceStage("node", "hop")
		}
		group := config.Group{Name: "deep", Paths: []*config_parser.ProxyPath{proxyPath(stages...)}, Policy: randomPolicy()}
		compiler, err := NewGroupCompiler(&DialerSet{nodeInfos: []*NodeInfo{node}}, []config.Group{group}, []string{"deep"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = compiler.ExpandRoutable(compiler.SelectorGroups()[0]); err != nil {
			t.Fatalf("maximum physical depth was rejected: %v", err)
		}

		group.Paths[0].Stages = append(group.Paths[0].Stages, referenceStage("node", "hop"))
		compiler, err = NewGroupCompiler(&DialerSet{nodeInfos: []*NodeInfo{node}}, []config.Group{group}, []string{"deep"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = compiler.ExpandRoutable(compiler.SelectorGroups()[0]); err == nil || !strings.Contains(err.Error(), "depth") {
			t.Fatalf("depth error = %v", err)
		}
	})

	t.Run("template nesting does not count as physical depth", func(t *testing.T) {
		groups := []config.Group{{
			Name:  "template-0",
			Paths: []*config_parser.ProxyPath{proxyPath(referenceStage("node", "hop"))},
		}}
		for i := 1; i <= MaxProxyPathDepth+1; i++ {
			groups = append(groups, config.Group{
				Name:  fmt.Sprintf("template-%d", i),
				Paths: []*config_parser.ProxyPath{proxyPath(referenceStage("group", fmt.Sprintf("template-%d", i-1)))},
			})
		}
		groups[len(groups)-1].Policy = randomPolicy()
		name := groups[len(groups)-1].Name
		compiler, err := NewGroupCompiler(
			&DialerSet{nodeInfos: []*NodeInfo{testNode("hop", "all")}},
			groups,
			[]string{name},
		)
		if err != nil {
			t.Fatal(err)
		}
		paths, err := compiler.ExpandRoutable(compiler.SelectorGroups()[0])
		if err != nil {
			t.Fatal(err)
		}
		if len(paths) != 1 || len(paths[0].Nodes) != 1 {
			t.Fatalf("paths = %#v", paths)
		}
	})

	t.Run("cartesian count", func(t *testing.T) {
		var nodes []*NodeInfo
		for i := 0; i < 65; i++ {
			nodes = append(nodes, testNode(fmt.Sprintf("entry-%d", i), "entry"), testNode(fmt.Sprintf("exit-%d", i), "exit"))
		}
		group := config.Group{
			Name:   "wide",
			Paths:  []*config_parser.ProxyPath{proxyPath(subtagStage("entry"), subtagStage("exit"))},
			Policy: randomPolicy(),
		}
		compiler, err := NewGroupCompiler(&DialerSet{nodeInfos: nodes}, []config.Group{group}, []string{"wide"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = compiler.ExpandRoutable(compiler.SelectorGroups()[0]); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
			t.Fatalf("expansion error = %v", err)
		}
	})

	t.Run("annotation overflow", func(t *testing.T) {
		node := testNode("hop", "all")
		maxPriority := strconv.Itoa(math.MaxInt)
		group := config.Group{
			Name: "overflow",
			Paths: []*config_parser.ProxyPath{proxyPath(
				nameStage("hop", annotation(dialer.AnnotationKey_Priority, maxPriority)),
				nameStage("hop", annotation(dialer.AnnotationKey_Priority, "1")),
			)},
			Policy: randomPolicy(),
		}
		compiler, err := NewGroupCompiler(&DialerSet{nodeInfos: []*NodeInfo{node}}, []config.Group{group}, []string{"overflow"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = compiler.ExpandRoutable(compiler.SelectorGroups()[0]); err == nil || !strings.Contains(err.Error(), "priority overflow") {
			t.Fatalf("annotation overflow error = %v", err)
		}
	})
}
