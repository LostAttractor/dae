// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestDNATPortRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		target, ip string
		port       uint16
	}{
		{"198.51.100.53", "198.51.100.53", 0},
		{"198.51.100.53:1053", "198.51.100.53", 1053},
		{"[2001:db8::53]:1053", "2001:db8::53", 1053},
	} {
		t.Run(tc.target, func(t *testing.T) {
			conf := parseConfig(t, fmt.Sprintf("global {} rules { dport(53) -> dnat('%s') } routing { fallback: direct }", tc.target))
			wire, err := conf.Marshal(2)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range []*Config{conf, parseConfig(t, string(wire))} {
				rules, err := c.Rules.Destinations()
				if err != nil || len(rules) != 1 || len(rules[0].To) != 1 || rules[0].To[0].String() != tc.ip || rules[0].Port != tc.port {
					t.Fatalf("DNAT target: %+v %v", rules, err)
				}
			}
		})
	}
}

func TestRoutingControlsRequireRulesSection(t *testing.T) {
	for _, action := range []string{"must", "must_rules", "must_direct", "must_my_group", "direct(must)", "my_group(mark: 37, must)", "bump"} {
		for _, fallback := range []bool{false, true} {
			body := "dip(192.0.2.1) -> " + action + "\nfallback: direct"
			if fallback {
				body = "fallback: " + action
			}
			t.Run(body, func(t *testing.T) {
				sections, err := config_parser.Parse("global {}\nrouting {\n" + body + "\n}")
				if err != nil {
					t.Fatal(err)
				}
				_, err = New(sections)
				want := "flow controls belong in rules {}"
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("expected control validation %q, got %v", want, err)
				}
			})
		}
	}
}
