// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func outboundUsageConfig(t *testing.T, text string) *config.Config {
	t.Helper()
	sections, err := config_parser.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := config.New(sections)
	if err != nil {
		t.Fatal(err)
	}
	return conf
}

func outboundUsageNodes(conf *config.Config) []outbound.NodeDescriptor {
	var nodes []outbound.NodeDescriptor
	for _, node := range conf.Node {
		nodes = append(nodes, outbound.NodeDescriptor{Name: node.Name, Link: node.Link, Required: true})
	}
	return nodes
}

func outboundUsagePlane(t *testing.T, conf *config.Config, store *settings.Store, load func(*http.Client) (PreparedMITM, error)) *ControlPlane {
	t.Helper()
	if store == nil {
		var err error
		store, err = settings.Open(filepath.Join(t.TempDir(), "runtime-state.json"))
		if err != nil {
			t.Fatal(err)
		}
	}
	preparation := &ControlPlanePreparation{
		bpf:      &BPFState{bpfObjects: new(bpfObjects), Runtime: NewRuntime()},
		rules:    preparedRules{routing: &conf.Routing},
		isReload: true,
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	plane, err := NewControlPlane(ctx, preparation, outboundUsageNodes(conf), conf, store, load)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plane.Close() })
	return plane
}

func TestOutboundUsageFollowsActivePoliciesAndTemplates(t *testing.T) {
	conf := outboundUsageConfig(t, `
global {}
node {
 entry: 'socks5://127.0.0.1:1'
 exit: 'socks5://127.0.0.1:2'
 unused_node: 'socks5://127.0.0.1:3'
}
group {
 unused_selector { policy: random }
 unused_target { policy: selector }
 template { node(entry) }
 chain { group(template) -> node(exit)
         policy: random }
}
routing {
 rule_set {
  shared { dport(80) -> chain(skip_while_noalive) }
  nested { use: shared }
  unused { dport(90) -> unused_node }
 }
 policy {
  main { use: nested
         fallback: direct }
  bound { use: shared
          dport(81) -> exit(skip_while_noalive)
          fallback: entry }
  inactive { dport(82) -> chain
             use: unused
             fallback: unused_target }
 }
 default: main
 interface { eth0: bound }
}`)
	plane := outboundUsagePlane(t, conf, nil, nil)
	want := map[string]bool{"direct": false, "block": false, "chain": true, "exit": true, "entry": false}
	if len(plane.outbounds) != len(want) {
		t.Fatalf("materialized %d targets, want %d", len(plane.outbounds), len(want))
	}
	for _, group := range plane.outbounds {
		async, ok := want[group.Name]
		if !ok || group.CheckAsync != async {
			t.Errorf("target %q: async=%v, expected active=%v async=%v", group.Name, group.CheckAsync, ok, async)
		}
		if group.Name == "chain" && (len(group.Dialers) != 1 || group.Dialers[0].Name != "entry -> exit") {
			t.Fatalf("template chain was not materialized correctly: %+v", group.Dialers)
		}
	}
	if selectors := plane.Selectors(); len(selectors) != 0 {
		t.Fatalf("unused selector exposed in API: %+v", selectors)
	}
	for _, group := range plane.StatusSnapshot("test").Groups {
		if _, ok := want[group.Name]; !ok {
			t.Errorf("unused target exposed in status: %q", group.Name)
		}
	}
}

func TestUnusedOutboundsDoNotConsumeRuntimeCapacity(t *testing.T) {
	// Empty selectors would fail at transport construction. More validation-only
	// targets than the runtime ID space must still compile without wrapping IDs.
	var groups, rules strings.Builder
	for i := range int(consts.OutboundUserDefinedMax) + 10 {
		fmt.Fprintf(&groups, " unused_%d { policy: random }\n", i)
		fmt.Fprintf(&rules, " dport(80) -> unused_%d\n", i)
	}
	conf := outboundUsageConfig(t, "global {}\ngroup {\n"+groups.String()+"}\nrouting {\nrule_set { unused {\n"+rules.String()+"} }\nfallback: direct\n}")
	plane := outboundUsagePlane(t, conf, nil, nil)
	if len(plane.outbounds) != 2 || len(plane.routingMatcherBuilder.outboundName2Id) != 2 {
		t.Fatalf("unused groups consumed runtime IDs: %+v", plane.routingMatcherBuilder.outboundName2Id)
	}
	if len(plane.core.pendingOutboundConnectivity) != 0 {
		t.Fatal("unused groups registered connectivity checks")
	}
}

func TestUnusedOutboundDefinitionsStillValidated(t *testing.T) {
	for _, tc := range []struct{ name, groups, rule, want string }{
		{"missing target", "", "dport(80) -> missing", "target not found"},
		{"invalid parameter", "", "dport(80) -> direct(unknown)", "unknown"},
		{"builtin skip", "", "dport(80) -> direct(skip_while_noalive)", "skip_while_noalive cannot be used"},
		{"invalid predicate", "", "domain(regex: '(') -> direct", "regex"},
		{"missing dependency", "unused { group(missing) }", "", "group not found"},
		{"cycle", "a { group(b) }\nb { group(a) }", "", "cycle"},
		{"invalid policy", "unused { policy: unknown }", "", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := outboundUsageConfig(t, "global {}\ngroup {\n"+tc.groups+"\n}\nrouting {\nfallback: direct\npolicy { inactive {\n"+tc.rule+"\nfallback: direct\n} }\n}")
			built, err := new(controlPlaneCore).buildOutbounds(t.Context(), nil, conf.Group, &conf.Routing, &conf.Global, consts.OutboundDirect)
			if err == nil {
				defer closeDialerGroups(built.outbounds)
				_, err = compileTestRouting(preparedRules{routing: &conf.Routing, validationOutbounds: built.validationOutbounds}, built.nameToID, nil, nil)
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestOutboundUsageReloadRestoresSavedSelector(t *testing.T) {
	conf := outboundUsageConfig(t, `
global {}
node {
 first: 'socks5://127.0.0.1:1'
 second: 'socks5://127.0.0.1:2'
}
group { selected { policy: selector } }
routing {
 policy {
  enabled { dport(80) -> selected(skip_while_noalive)
            fallback: direct }
  disabled { fallback: direct }
 }
 default: enabled
}`)
	first := outboundUsagePlane(t, conf, nil, nil)
	selector := first.Selectors()[0]
	saved := selector.Nodes[1].ID
	if _, err := first.Select("selected", saved, "test"); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	conf.Routing.Default = "disabled"
	pruned := outboundUsagePlane(t, conf, first.settings, nil)
	if len(pruned.outbounds) != 2 || len(pruned.Selectors()) != 0 {
		t.Fatal("deactivated selector retained runtime state")
	}
	if err := pruned.restoreRuntimeSettings(true); err != nil {
		t.Fatal(err)
	}
	if err := pruned.Close(); err != nil {
		t.Fatal(err)
	}
	conf.Routing.Default = "enabled"
	restored := outboundUsagePlane(t, conf, first.settings, nil)
	if got := restored.Selectors()[0]; got.NodeID != saved || !got.Overridden {
		t.Fatalf("saved choice not restored after pruning: %+v", got)
	}
}

func TestPluginRoutingMaterializesOnlyItsTargets(t *testing.T) {
	conf := outboundUsageConfig(t, `
global {}
node { base: 'socks5://127.0.0.1:1' }
group {
 unused { policy: selector }
 plugin_only { policy: random }
 plugin_sync { policy: random }
}
routing { dport(80) -> base(skip_while_noalive)
          fallback: direct }
`)
	routes := planRulesForTest(t, "dport(81) -> plugin_only(skip_while_noalive)\ndport(82) -> plugin_sync\ndport(83) -> base")
	load := func(*http.Client) (PreparedMITM, error) {
		host, err := mitm.New(mitm.Options{}, mitm.Instance{ID: "test", Plugin: &controlTestPlugin{plan: plugin.Plan{Routes: routes}}})
		if err != nil {
			return PreparedMITM{}, err
		}
		return PrepareMITM(t.Context(), host, nil)
	}
	plane := outboundUsagePlane(t, conf, nil, load)
	if len(plane.outbounds) != 5 {
		t.Fatalf("plugin targets = %+v", plane.routingMatcherBuilder.outboundName2Id)
	}
	for _, group := range plane.outbounds {
		if group.Name == "unused" {
			t.Fatal("plugin loading instantiated an unused selector")
		}
		if group.CheckAsync != (group.Name == "plugin_only") {
			t.Errorf("%s: async=%v after plugin references", group.Name, group.CheckAsync)
		}
		if slices.Contains([]string{"base", "plugin_sync"}, group.Name) && !group.Dialers[0].ConnectivitySnapshot().InitialCheckDone {
			t.Errorf("%s: critical plugin target did not finish its check", group.Name)
		}
	}
}
