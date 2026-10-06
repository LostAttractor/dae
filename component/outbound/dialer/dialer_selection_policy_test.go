// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestSelectionPolicyConfiguration(t *testing.T) {
	for _, test := range []struct {
		name  string
		group config.Group
		valid bool
	}{
		{"failover", config.Group{Policy: "failover"}, true},
		{"settings", config.Group{Policy: "failover", FailureRecovery: time.Second, ProbeTimeout: time.Second, SelectionTimeout: 5 * time.Second}, true},
		{"zero recovery", config.Group{Policy: "failover", Present: map[string]bool{"failure_recovery": true}}, false},
		{"negative timeout", config.Group{Policy: "failover", ProbeTimeout: -time.Second}, false},
		{"backoff bounds", config.Group{Policy: "failover", UpgradeInterval: time.Hour, UpgradeIntervalMax: time.Minute}, false},
		{"manual settings", config.Group{Policy: "selector", ProbeTimeout: time.Second}, false},
		{"obsolete penalty", config.Group{Policy: &config_parser.Function{Name: "min", Params: []*config_parser.Param{{Val: "10m"}}}}, false},
		{"alpha", config.Group{Policy: &config_parser.Function{Name: "min_moving_avg", Params: []*config_parser.Param{{Key: "alpha", Val: "0.5"}}}}, true},
		{"NaN alpha", config.Group{Policy: &config_parser.Function{Name: "min_moving_avg", Params: []*config_parser.Param{{Key: "alpha", Val: "NaN"}}}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy, err := NewDialerSelectionPolicyFromGroupParam(&test.group)
			if (err == nil) != test.valid {
				t.Fatalf("policy=%+v err=%v", policy, err)
			}
			if err == nil && (policy.EmaAlpha <= 0 || policy.FailureRecovery <= 0 || policy.ProbeTimeout <= 0) {
				t.Fatal("policy omitted defaults")
			}
		})
	}
}

func TestIndexedSelectionPolicy(t *testing.T) {
	for _, input := range []config.FunctionListOrString{"selector", &config_parser.Function{Name: "selector"}} {
		policy, err := NewDialerSelectionPolicyFromGroupParam(&config.Group{Policy: input})
		if err != nil || policy.Policy != "selector" || policy.FixedIndex != 0 || policy.FixedIndexSet {
			t.Fatalf("selector without index = %+v, %v", policy, err)
		}
	}
	if _, err := NewDialerSelectionPolicyFromGroupParam(&config.Group{Policy: "fixed"}); err == nil {
		t.Fatal("fixed without an index was accepted")
	}
	for _, name := range []string{"fixed", "selector"} {
		for _, test := range []struct {
			index string
			want  int
		}{{"0", 0}, {"2", 2}, {"-1", -1}} {
			t.Run(name+"("+test.index+")", func(t *testing.T) {
				group := config.Group{Policy: &config_parser.Function{Name: name, Params: []*config_parser.Param{{Val: test.index}}}}
				policy, err := NewDialerSelectionPolicyFromGroupParam(&group)
				if test.want < 0 {
					if err == nil {
						t.Fatal("invalid index was accepted")
					}
				} else if err != nil || string(policy.Policy) != name || policy.FixedIndex != test.want || !policy.FixedIndexSet {
					t.Fatalf("policy = %+v, %v; want %s(%d)", policy, err, name, test.want)
				}
			})
		}
	}
}

func TestTrackAllRequiresSelector(t *testing.T) {
	for _, name := range []string{"selector", "random", "failover"} {
		for _, enabled := range []bool{false, true} {
			policy, err := NewDialerSelectionPolicyFromGroupParam(&config.Group{Policy: name, TrackAll: enabled, Present: map[string]bool{"track_all": true}})
			if name != "selector" {
				if err == nil {
					t.Fatal("non-selector accepted track_all")
				}
			} else if err != nil || policy.TrackAll != enabled || policy.FixedIndexSet {
				t.Fatalf("configured tracking = %+v, %v", policy, err)
			}
		}
	}
}
