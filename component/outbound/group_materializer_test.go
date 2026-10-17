// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"testing"
	"time"
)

func TestGroupOverrideOptionCheckIntervals(t *testing.T) {
	global := config.Global{
		CheckInterval:    30 * time.Second,
		CheckIntervalMax: time.Hour,
	}
	option := parseGroupOverrideOption(config.Group{
		CheckInterval:    45 * time.Second,
		CheckIntervalMax: 10 * time.Minute,
	}, global)
	if option.CheckInterval != 45*time.Second || option.CheckIntervalMax != 10*time.Minute {
		t.Fatalf("unexpected check intervals: %v, %v", option.CheckInterval, option.CheckIntervalMax)
	}
}

func TestGroupOverrideOptionExplicitZeroTolerance(t *testing.T) {
	option := parseGroupOverrideOption(config.Group{
		Present:        map[string]bool{"check_tolerance": true},
		CheckTolerance: 0,
	}, config.Global{CheckTolerance: time.Second})
	if option == nil || option.CheckTolerance != 0 {
		t.Fatalf("explicit zero tolerance option = %#v", option)
	}
}

func TestCandidateStatsScopeSeparatesIdenticalPaths(t *testing.T) {
	set, err := NewDialerSet([]NodeDescriptor{{
		Name:     "node",
		Link:     "socks5://127.0.0.1:1080",
		Required: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	path := NodePath(set.NodesNamed("node")[0])
	occurrences := make(map[string]int)
	first, err := set.BuildPath(path, new(dialer.GlobalOption), candidateStatsScope("target", path, occurrences))
	if err != nil {
		t.Fatal(err)
	}
	second, err := set.BuildPath(path, new(dialer.GlobalOption), candidateStatsScope("target", path, occurrences))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = first.Close()
		_ = second.Close()
	})
	if first.StatsKey() == second.StatsKey() || first.StatsID() == second.StatsID() {
		t.Fatal("identical path occurrences share stats identity")
	}
}

func TestCandidateStatsScopeIgnoresUnrelatedPaths(t *testing.T) {
	first := &PathSpec{Nodes: []*NodeInfo{{
		Property: &dialer.Property{Name: "first", Link: "first"},
	}}}
	second := &PathSpec{Nodes: []*NodeInfo{{
		Property: &dialer.Property{Name: "second", Link: "second"},
	}}}

	withoutInsertion := make(map[string]int)
	_ = candidateStatsScope("target", first, withoutInsertion)
	want := candidateStatsScope("target", second, withoutInsertion)

	withInsertion := make(map[string]int)
	_ = candidateStatsScope("target", &PathSpec{Nodes: []*NodeInfo{{
		Property: &dialer.Property{Name: "inserted", Link: "inserted"},
	}}}, withInsertion)
	if got := candidateStatsScope("target", second, withInsertion); got != want {
		t.Fatalf("scope after unrelated insertion = %q, want %q", got, want)
	}
}
