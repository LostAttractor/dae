// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestPolicyRulesRoundTripAndIncludes(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "config.dae")
	writeConfigFile(t, entry, `global {}
include { flow.dae }
routing {
 policy {
  main {
   fallback: direct
   rules {
    use: bypass
    client(direct) -> use(rewrite)
    dport(8443) -> bump
   }
  }
  tor { fallback: block }
 }
 default: main
 interface { tor0: tor }
}`)
	writeConfigFile(t, filepath.Join(dir, "flow.dae"), `routing {
 rule_set {
  bypass { pname(mosdns) -> must }
  rewrite { dport(53) -> dnat('127.0.0.54:53') }
  unused_flow { dport(443) -> bump }
 }
}`)
	sections, _, err := NewMerger(entry).Merge()
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Routing.Policies[0].Rules) != 3 || len(conf.Routing.Policies[1].Rules) != 0 {
		t.Fatalf("policy rules leaked or disappeared: %+v", conf.Routing.Policies)
	}
	kinds, err := conf.Routing.RuleSetKinds()
	if err != nil || kinds["rewrite"] != RoutingRuleSetFlow || kinds["unused_flow"] != RoutingRuleSetFlow {
		t.Fatalf("rule set kinds: %v, %v", kinds, err)
	}
	wire, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	again := parseConfig(t, string(wire))
	if !sameConfiguration(conf.Routing, again.Routing) {
		t.Fatalf("policy rules changed on round trip:\n%s", wire)
	}
}

func TestPolicyRulesValidateStageAndReferences(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"global rules", "rules { dport(53) -> must } routing { fallback: direct }", "unknown section: rules"},
		{"duplicate", "routing { rules {} rules {} fallback: direct }", "duplicate policy rules"},
		{"named default with inline rules", "routing { rules {} policy { main { fallback: direct } } default: main }", "cannot be combined"},
		{"nested fragment section", "routing { rule_set { bad { rules {} } } fallback: direct }", "unsupported routing item"},
		{"rules fallback", "routing { rules { fallback: direct } fallback: direct }", "cannot contain fallback"},
		{"undefined rules use", "routing { rules { use: missing } fallback: direct }", "undefined rule_set"},
		{"rules cycle", "routing { rule_set { a { use: b } b { use: a } } rules { use: a } fallback: direct }", "cycle"},
		{"outbound fragment in rules", "routing { rule_set { a { dport(53) -> direct } b { use: a } } rules { use: b } fallback: direct }", "outbounds belong in the policy body"},
		{"flow fragment in routing", "routing { rule_set { a { dport(53) -> must } b { use: a } } use: b fallback: direct }", "flow controls belong in rules"},
		{"mixed fragment", "routing { rule_set { a { dport(53) -> must dport(80) -> direct } } fallback: direct }", "mixes flow controls and outbounds"},
		{"mixed nested fragment", "routing { rule_set { a { dport(53) -> must } b { use: a dport(80) -> direct } } fallback: direct }", "mixes flow controls and outbounds"},
		{"invalid unused action", "routing { rule_set { unused { dport(53) -> dnat(example.com) } } fallback: direct }", "dnat target must be an IP"},
		{"invalid unused policy action", "routing { policy { unused { rules { dport(53) -> must(mark: 1) } fallback: direct } } fallback: direct }", "takes no arguments"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sections, err := config_parser.Parse("global {}\n" + tc.body)
			if err != nil {
				t.Fatal(err)
			}
			_, err = New(sections)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v; want %q", err, tc.want)
			}
		})
	}
	// Empty fragments have no action family, including through nested uses.
	parseConfig(t, `global {} routing {
 rule_set { empty {} nested { use: empty } }
 rules { sip(192.0.2.0/24) -> use(nested) }
 use: nested
 fallback: direct
}`)
}
