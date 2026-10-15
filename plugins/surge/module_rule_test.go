// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"strings"
	"testing"
)

func TestModuleRulesOrderedPolicyAndWarnings(t *testing.T) {
	module, err := Parse(`[Rule]
DOMAIN,api.example.test,DIRECT
DOMAIN,blocked.example.test,REJECT,pre-matching,extended-matching
AND,((DOMAIN-SUFFIX,media.example.test), (OR,((DOMAIN-KEYWORD,ad), (DOMAIN-KEYWORD,tracking)))),REJECT,pre-matching
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(module.Rules) != 3 || len(module.Warnings) != 3 {
		t.Fatalf("rules=%+v warnings=%v", module.Rules, module.Warnings)
	}
	if module.Rules[0].Policy != "DIRECT" || module.Rules[0].PreMatching {
		t.Fatal("direct rule changed")
	}
	for _, rule := range module.Rules[1:] {
		if rule.Policy != "REJECT" || !rule.PreMatching {
			t.Fatalf("reject rule changed: %+v", rule)
		}
	}
}

func TestModuleRulesUnsupportedAreExplicit(t *testing.T) {
	for _, line := range []string{
		"DOMAIN,api.example,ProxyGroup",
		"IP-CIDR,192.0.2.0/24,REJECT",
		"DOMAIN,api.example,DIRECT,unknown-option",
		"DOMAIN-WILDCARD,api[12].example,REJECT",
		"AND,((DOMAIN,api.example),(SRC-IP,192.0.2.1)),REJECT",
		"AND,((DOMAIN,api.example,pre-matching),(DOMAIN-SUFFIX,example)),REJECT",
	} {
		t.Run(line, func(t *testing.T) {
			var warnings []string
			rule, err := parseModuleRule(line, &warnings)
			if err != nil {
				t.Fatal(err)
			}
			if rule != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "entire rule is ignored") {
				t.Fatalf("unsupported rule not explicitly ignored: %+v, %v", rule, warnings)
			}
		})
	}
}

func TestModuleRulesRejectMalformedAndExplosiveExpressions(t *testing.T) {
	for _, line := range []string{
		"DOMAIN,api.example",
		"DOMAIN,api.example,DIRECT,pre-matching",
		"AND,((DOMAIN,api.example),REJECT",
		"NOT,((DOMAIN,a.example),(DOMAIN,b.example)),REJECT",
		"AND,(),REJECT",
	} {
		var warnings []string
		if _, err := parseModuleRule(line, &warnings); err == nil {
			t.Errorf("accepted malformed rule %q", line)
		}
	}
	deep := "DOMAIN,api.example"
	for range 11 {
		deep = "NOT,((" + deep + "))"
	}
	var warnings []string
	if _, err := parseModuleRule(deep+",REJECT", &warnings); err == nil {
		t.Fatal("accepted excessive logical nesting")
	}
	parts := make([]string, 8)
	for i := range parts {
		parts[i] = "(OR,((DOMAIN,a.example),(DOMAIN,b.example)))"
	}
	if _, err := parseModuleRule("AND,("+strings.Join(parts, ",")+"),REJECT", &warnings); err == nil {
		t.Fatal("accepted exponential rule expansion")
	}
}
