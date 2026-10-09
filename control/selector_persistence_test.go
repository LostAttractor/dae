// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/daeuniverse/dae/api"

	"github.com/daeuniverse/dae/component/settings"
)

func TestSelectorRestoresAfterFilterAndTransportChanges(t *testing.T) {
	first := outboundUsagePlane(t, outboundUsageConfig(t, `
global {}
node { one: 'socks5://127.0.0.1:1080' two: 'socks5://127.0.0.1:1081' }
group { proxy { filter: name(one, two) policy: selector(0) check_async: true } }
routing { fallback: proxy }`), nil, nil)
	state := first.Selectors()[0]
	index := slices.IndexFunc(state.Nodes, func(node api.SelectorNode) bool { return node.Name == "two" })
	if index == -1 {
		t.Fatal("test node missing")
	}
	oldID := state.Nodes[index].ID
	if _, err := first.Select("proxy", oldID, "test"); err != nil {
		t.Fatal(err)
	}
	second := outboundUsagePlane(t, outboundUsageConfig(t, `
global { allow_insecure: true }
node {
 three: 'socks5://127.0.0.1:1082'
 two: 'socks5://127.0.0.1:2081'
 one: 'socks5://127.0.0.1:1080'
}
group { proxy { filter: name(one, two, three) [priority: 99] policy: selector(0) check_async: true } }
routing { fallback: proxy }`), first.settings, nil)
	state = second.Selectors()[0]
	index = slices.IndexFunc(state.Nodes, func(node api.SelectorNode) bool { return node.Name == "two" })
	if index == -1 || state.NodeID != state.Nodes[index].ID || state.NodeID == oldID || state.SavedSelection.Status != "matched" {
		t.Fatalf("config rebuild lost logical selection: %+v", state)
	}
	missing := outboundUsagePlane(t, outboundUsageConfig(t, `
global {}
node { one: 'socks5://127.0.0.1:1080' two: 'socks5://127.0.0.1:2081' }
group { proxy { filter: name(one) policy: selector(0) check_async: true } }
routing { fallback: proxy }`), first.settings, nil)
	if err := missing.restoreRuntimeSettings(true); err != nil {
		t.Fatal(err)
	}
	if state = missing.Selectors()[0]; state.SavedSelection.Status != "missing" || !state.Overridden {
		t.Fatalf("filter removal erased saved preference: %+v", state)
	}
	if err := second.restoreRuntimeSettings(true); err != nil {
		t.Fatal(err)
	}
	if state = second.Selectors()[0]; state.NodeID != state.Nodes[index].ID || state.SavedSelection.Status != "matched" {
		t.Fatalf("restored filter did not recover preference: %+v", state)
	}
}

func TestSelectorPreferenceSurvivesMissingPathAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := settings.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	active := newAPITestPlane(t, store)
	chosen := active.outbounds[0].Dialers[1]
	if _, err := active.Select("proxy", chosen.StatsID(), "test"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	missing := newAPITestPlane(t, store)
	// A filter or address-family discovery may omit a formerly selected path.
	missing.outbounds[0].Dialers = missing.outbounds[0].Dialers[:1]
	if err := missing.restoreRuntimeSettings(true); err != nil {
		t.Fatal(err)
	}
	state := missing.Selectors()[0]
	if !state.Overridden || state.SavedSelection == nil || state.SavedSelection.Status != "missing" || state.NodeID != state.DefaultNodeID {
		t.Fatalf("missing saved selection was hidden: %+v", state)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatal("temporary fallback rewrote persisted preferences", err)
	}
	store, err = settings.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	restored := newAPITestPlane(t, store)
	if err := restored.restoreRuntimeSettings(true); err != nil {
		t.Fatal(err)
	}
	state = restored.Selectors()[0]
	if state.NodeID != restored.outbounds[0].Dialers[1].StatsID() || state.SavedSelection.Status != "matched" {
		t.Fatalf("returning path did not restore after restart: %+v", state)
	}
	// Explicitly selecting the current fallback replaces the missing preference.
	if _, err := missing.Select("proxy", missing.outbounds[0].Dialers[0].StatsID(), "test"); err != nil {
		t.Fatal(err)
	}
	replaced := newAPITestPlane(t, missing.settings)
	if err := replaced.restoreRuntimeSettings(true); err != nil {
		t.Fatal(err)
	}
	if replaced.outbounds[0].Selection() != replaced.outbounds[0].Dialers[0].StatsID() {
		t.Fatal("superseded preference returned")
	}
}

func TestSelectorRestoreDoesNotRequireWritingPreferences(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := settings.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	active := newAPITestPlane(t, store)
	if _, err := active.Select("proxy", active.outbounds[0].Dialers[1].StatsID(), "test"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	missing := newAPITestPlane(t, store)
	missing.outbounds[0].Dialers = missing.outbounds[0].Dialers[:1]
	if err := missing.restoreRuntimeSettings(true); err != nil {
		t.Fatalf("read-only restore attempted to write preferences: %v", err)
	}
}
