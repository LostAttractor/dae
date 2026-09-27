// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func dualStackEntry(context.Context, *PathSpec) (uint8, error) { return allFamilies, nil }

func TestEntryAnnotationsAndFamilyFilters(t *testing.T) {
	for _, test := range []struct {
		filter string
		want   []int
	}{
		{"name(entry)", []int{4, 6}},
		{"name(entry) && ipversion(4)", []int{4}},
		{"name(entry) && ipversion(6)", []int{6}},
		{"name(entry) && !ipversion(6)", []int{4}},
		{"name(entry) && ipversion(4, 6)", []int{4, 6}},
		{"name(entry) && ipversion(4) && ipversion(6)", nil},
	} {
		t.Run(test.filter, func(t *testing.T) {
			sections, err := config_parser.Parse(`global {}
group { proxy {
 filter: ` + test.filter + ` [mark: 0x20, interface: wan0, add_latency: 10ms]
 policy: random
} }
routing { fallback: direct }`)
			if err != nil {
				t.Fatal(err)
			}
			conf, err := config.New(sections)
			if err != nil {
				t.Fatal(err)
			}
			set, err := NewDialerSet([]NodeDescriptor{{Name: "entry", Link: "socks5://proxy.test:1080"}})
			if err != nil {
				t.Fatal(err)
			}
			compiler, err := NewGroupCompiler(set, conf.Group, nil)
			if err != nil {
				t.Fatal(err)
			}
			paths, err := compiler.ExpandRoutable(&conf.Group[0])
			if err != nil {
				t.Fatal(err)
			}
			variants, err := expandIPVariants(t.Context(), paths, dualStackEntry)
			if err != nil {
				t.Fatal(err)
			}
			var families []int
			ids := make(map[string]bool)
			for _, variant := range variants {
				families = append(families, variant.IPVersion)
				if variant.Entry.Mark == nil || *variant.Entry.Mark != 0x20 || variant.Entry.Interface != "wan0" || variant.Annotation.AddLatency.String() != "10ms" {
					t.Fatalf("lost annotations: %+v", variant)
				}
				if ids[variant.Identity()] {
					t.Fatal("family variants share one identity")
				}
				ids[variant.Identity()] = true
			}
			if !reflect.DeepEqual(families, test.want) {
				t.Fatalf("families = %v, want %v", families, test.want)
			}
			if len(set.NodesNamed("entry")) != 1 {
				t.Fatal("runtime variants changed logical name resolution")
			}
		})
	}
}

func TestEntryOptionValidation(t *testing.T) {
	for _, params := range [][]*config_parser.Param{
		{annotation("mark", "-1")}, {annotation("mark", "4294967296")},
		{annotation("mark", "0x8000000")}, {annotation("mark", "garbage")},
		{annotation("mark", "1"), annotation("mark", "2")},
		{annotation("interface", "")}, {annotation("interface", "abcdefghijklmnop")},
		{annotation("interface", "wan\x00ignored")}, {annotation("interface", "wan 0")},
		{annotation("interface", "wan:0")},
		{annotation("interface", "wan0"), annotation("interface", "wan1")},
	} {
		if _, _, err := parseStageAnnotations(params); err == nil {
			t.Fatalf("accepted invalid annotations: %v", params)
		}
	}
	for _, value := range []string{"0", "0xffffffff", "32", "0X20", "032"} {
		_, entry, err := parseStageAnnotations([]*config_parser.Param{annotation("mark", value)})
		if value == "0xffffffff" { // Contains the reserved TPROXY bit.
			if err == nil {
				t.Fatal("accepted reserved mark bits")
			}
			continue
		}
		if err != nil || entry.Mark == nil {
			t.Fatalf("mark %s: %v", value, err)
		}
		want := uint32(32)
		if value == "0" {
			want = 0
		}
		if *entry.Mark != want {
			t.Fatalf("mark %s = %d, want %d", value, *entry.Mark, want)
		}
	}
	for _, params := range [][]*config_parser.Param{nil, {{Val: "7"}}, {{Key: "regex", Val: "4"}}} {
		if _, _, err := splitEntryFilters([]*config_parser.Function{{Name: "ipversion", Params: params}}); err == nil {
			t.Fatalf("accepted invalid family filter: %v", params)
		}
	}
}

func TestEntryOptionsThroughTemplates(t *testing.T) {
	set, err := NewDialerSet([]NodeDescriptor{{Name: "entry", Link: "socks5://proxy.test:1080"}})
	if err != nil {
		t.Fatal(err)
	}
	template := config.Group{Name: "template", Paths: []*config_parser.ProxyPath{proxyPath(nameStage("entry", annotation("mark", "32")))}}
	for _, test := range []struct {
		name string
		path *config_parser.ProxyPath
		want string
	}{
		{"entry", proxyPath(referenceStage("group", "template", annotation("interface", "wan0")), referenceStage("node", "entry")), ""},
		{"conflict", proxyPath(referenceStage("group", "template", annotation("mark", "33"))), "conflicting"},
		{"later reference", proxyPath(referenceStage("node", "entry"), referenceStage("group", "template")), "entry stage"},
		{"later annotation", proxyPath(referenceStage("node", "entry"), nameStage("entry", annotation("interface", "wan0"))), "entry stage"},
		{"empty prefix", proxyPath(nameStage("absent"), referenceStage("group", "template")), "entry stage"},
		{"later family", proxyPath(referenceStage("node", "entry"), filterStage([]*config_parser.Function{{Name: "ipversion", Params: []*config_parser.Param{{Val: "4"}}}})), "entry stage"},
	} {
		t.Run(test.name, func(t *testing.T) {
			group := config.Group{Name: "proxy", Policy: randomPolicy(), Paths: []*config_parser.ProxyPath{test.path}}
			compiler, err := NewGroupCompiler(set, []config.Group{template, group}, nil)
			var paths []*PathSpec
			if err == nil {
				paths, err = compiler.ExpandRoutable(&group)
			}
			if test.want != "" {
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("error = %v, want %q", err, test.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(paths) != 1 || *paths[0].Entry.Mark != 32 || paths[0].Entry.Interface != "wan0" || len(paths[0].Nodes) != 2 {
				t.Fatalf("template lost entry options: %+v", paths)
			}
		})
	}
}

func TestLiteralVariantsAndEntryIdentity(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "[::1]", "[::ffff:127.0.0.1]"} {
		set, err := NewDialerSet([]NodeDescriptor{{Name: "node", Link: "socks5://" + host + ":1080"}})
		if err != nil {
			t.Fatal(err)
		}
		paths, err := expandIPVariants(t.Context(), []*PathSpec{NodePath(set.NodesNamed("node")[0])}, dualStackEntry)
		if err != nil || len(paths) != 1 {
			t.Fatalf("literal %s: %v, %v", host, paths, err)
		}
		want := 4
		if host == "[::1]" {
			want = 6
		}
		if paths[0].IPVersion != want {
			t.Fatalf("literal family = %d, want %d", paths[0].IPVersion, want)
		}
		base := paths[0]
		ids := make(map[string]bool)
		for _, entry := range []EntryOptions{{}, {Mark: new(uint32(0))}, {Mark: new(uint32(32))}, {Interface: "wan0"}, {Interface: "wan1"}} {
			variant := *base
			variant.Entry = entry
			d, err := set.BuildPath(&variant, &dialer.GlobalOption{SoMarkFromDae: 0x100}, t.Name())
			if err != nil {
				t.Fatal(err)
			}
			if ids[d.StatsID()] {
				t.Fatal("distinct physical paths shared a runtime identity")
			}
			ids[d.StatsID()] = true
			_ = d.Close()
		}
	}
}

func TestVariantsWithProtocolDefaultPort(t *testing.T) {
	for _, test := range []struct {
		host     string
		families []int
	}{
		{"entry.test", []int{4, 6}},
		{"127.0.0.1", []int{4}},
		{"[::1]", []int{6}},
	} {
		set, err := NewDialerSet([]NodeDescriptor{{Name: "entry", Link: "hysteria2://pass@" + test.host}})
		if err != nil {
			t.Fatal(err)
		}
		variants, err := expandIPVariants(t.Context(), []*PathSpec{NodePath(set.NodesNamed("entry")[0])}, dualStackEntry)
		if err != nil {
			t.Fatal(err)
		}
		var families []int
		for _, variant := range variants {
			families = append(families, variant.IPVersion)
		}
		if !reflect.DeepEqual(families, test.families) {
			t.Fatalf("%s families = %v, want %v", test.host, families, test.families)
		}
	}
}

func TestPolicylessFamilyFilterExcludesOtherLiteralStack(t *testing.T) {
	set, err := NewDialerSet([]NodeDescriptor{
		{Name: "v4", Link: "socks5://127.0.0.1:1080"},
		{Name: "v6", Link: "socks5://[::1]:1080"},
	})
	if err != nil {
		t.Fatal(err)
	}
	group := config.Group{Name: "only4", Paths: []*config_parser.ProxyPath{
		proxyPath(filterStage([]*config_parser.Function{{Name: "ipversion", Params: []*config_parser.Param{{Val: "4"}}}})),
	}}
	compiler, err := NewGroupCompiler(set, []config.Group{group}, nil)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := compiler.ExpandRoutable(&group)
	if err != nil || len(paths) != 1 || paths[0].Nodes[0].Property.Name != "v4" {
		t.Fatalf("IPv4-only logical paths = %v, %v", paths, err)
	}
}
