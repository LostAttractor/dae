// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"reflect"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/selector"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
)

func selectionSet(t *testing.T, nodes ...NodeDescriptor) *DialerSet {
	t.Helper()
	set, err := NewDialerSet(nodes)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func selectionMember(t *testing.T, set *DialerSet, path *PathSpec, option *dialer.GlobalOption, scope string) *dialer.Dialer {
	t.Helper()
	d, err := set.BuildPath(path, option, scope)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestSavedSelectionIgnoresRuntimeOptionsAndAnnotations(t *testing.T) {
	node := NodeDescriptor{Name: "chosen", SubscriptionTag: "airport", Link: "socks5://127.0.0.1:1080"}
	set := selectionSet(t, node)
	path := NodePath(set.nodeInfos[0])
	path.IPVersion = 4
	old := selectionMember(t, set, path, &dialer.GlobalOption{}, "proxy:0")
	saved := old.SelectionReference()
	node.Options.Multiplex = config.MultiplexModeSmux
	updated := selectionSet(t, NodeDescriptor{Name: "unrelated", Link: "socks5://127.0.0.1:1081"}, node)
	path = NodePath(updated.nodeInfos[1])
	path.IPVersion = 4
	path.Annotation = &dialer.Annotation{Priority: 9, AddLatency: -time.Second}
	option := &dialer.GlobalOption{AllowInsecure: true, Mptcp: true, SoMarkFromDae: 32, DNSResolver: "127.0.0.2:53", CheckInterval: time.Hour}
	current := selectionMember(t, updated, path, option, "proxy:7")
	if old.StatsID() == current.StatsID() || old.Dialer == current.Dialer {
		t.Fatal("changed transport reused runtime identity")
	}
	if !reflect.DeepEqual(saved, current.SelectionReference()) {
		t.Fatal("runtime defaults, annotations, multiplex or scope changed the saved path")
	}
	group := &DialerGroup{Dialers: []*dialer.Dialer{current}}
	if id, status := group.ResolveSelection(saved); id != current.StatsID() || status != "matched" {
		t.Fatalf("restored %s (%s), want current runtime", id, status)
	}
}

func TestSavedSelectionFollowsNamedUpdatesWithoutGuessingDuplicates(t *testing.T) {
	node := func(port string) NodeDescriptor {
		return NodeDescriptor{Name: "HK", SubscriptionTag: "airport", Link: "socks5://127.0.0.1:" + port}
	}
	build := func(nodes ...NodeDescriptor) *DialerGroup {
		set := selectionSet(t, nodes...)
		group := &DialerGroup{}
		for _, node := range set.nodeInfos {
			group.Dialers = append(group.Dialers, selectionMember(t, set, NodePath(node), &dialer.GlobalOption{}, "proxy"))
		}
		return group
	}
	old := build(node("1080"))
	saved := old.Dialers[0].SelectionReference()
	updated := build(node("2080"))
	if id, status := updated.ResolveSelection(saved); id != updated.Dialers[0].StatsID() || status != "matched" {
		t.Fatalf("named subscription update was lost: %s %s", id, status)
	}
	duplicates := build(node("1081"), node("1080"))
	if id, status := duplicates.ResolveSelection(saved); id != duplicates.Dialers[1].StatsID() || status != "matched" {
		t.Fatalf("fingerprint did not disambiguate reordered duplicates: %s %s", id, status)
	}
	pinned := duplicates.Dialers[1].SelectionReference()
	if !pinned.Nodes[0].Exact {
		t.Fatal("duplicate source names were not recorded")
	}
	remaining := build(node("1081"))
	if id, status := remaining.ResolveSelection(pinned); id != "" || status != "missing" {
		t.Fatalf("missing duplicate followed a different server: %s %s", id, status)
	}
	if id, status := duplicates.ResolveSelection(updated.Dialers[0].SelectionReference()); id != "" || status != "ambiguous" {
		t.Fatalf("ambiguous updated name was guessed: %s %s", id, status)
	}
	other := node("1080")
	other.SubscriptionTag = "different"
	if id, status := build(other).ResolveSelection(saved); id != "" || status != "missing" {
		t.Fatalf("selection crossed subscription sources: %s %s", id, status)
	}
	unnamed := node("1080")
	unnamed.Name = ""
	unnamedSaved := build(unnamed).Dialers[0].SelectionReference()
	if err := unnamedSaved.Validate(); err != nil || !unnamedSaved.Nodes[0].Exact {
		t.Fatalf("unnamed node could not be saved exactly: %+v, %v", unnamedSaved, err)
	}
	unnamed.Link = "socks5://127.0.0.1:2080"
	if id, status := build(unnamed).ResolveSelection(unnamedSaved); id != "" || status != "missing" {
		t.Fatalf("unnamed node followed a different link: %s %s", id, status)
	}
}

func TestSavedSelectionPreservesFullChainAndExplicitEntrance(t *testing.T) {
	set := selectionSet(t,
		NodeDescriptor{Name: "entry", Link: "socks5://127.0.0.1:1080", Required: true},
		NodeDescriptor{Name: "exit", Link: "socks5://127.0.0.1:1081", Required: true},
	)
	path := &PathSpec{Nodes: set.nodeInfos, IPVersion: 6, Entry: EntryOptions{Interface: "wan0", Mark: new(uint32(32))}}
	d := selectionMember(t, set, path, &dialer.GlobalOption{}, "proxy")
	saved := d.SelectionReference()
	for _, test := range []struct {
		name string
		edit func(*selector.Path)
	}{
		{"chain order", func(p *selector.Path) { p.Nodes[0], p.Nodes[1] = p.Nodes[1], p.Nodes[0] }},
		{"exit only", func(p *selector.Path) { p.Nodes = p.Nodes[1:] }},
		{"IPv4", func(p *selector.Path) { p.IPVersion = 4 }},
		{"interface", func(p *selector.Path) { p.Interface = "wan1" }},
		{"explicit zero", func(p *selector.Path) { p.Mark = new(uint32(0)) }},
		{"inherited mark", func(p *selector.Path) { p.Mark = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			other := saved.Clone()
			test.edit(other)
			if other.Matches(saved, false) {
				t.Fatal("different logical path matched the saved selection")
			}
		})
	}
	duplicate := selectionMember(t, set, path, &dialer.GlobalOption{}, "proxy:repeat")
	group := &DialerGroup{Dialers: []*dialer.Dialer{duplicate, d}}
	if _, status := group.ResolveSelection(saved); status != "matched" {
		t.Fatal("equivalent repeated paths became ambiguous")
	}
}
