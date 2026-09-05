// SPDX-License-Identifier: AGPL-3.0-only

package surgemodule

import (
	"strings"
	"testing"
)

const bilijumpRuleFixture = `[Rule]
DOMAIN,api.cloudflare.com,DIRECT
DOMAIN,api.biliapi.com,REJECT,pre-matching,extended-matching
DOMAIN,app.biliapi.com,REJECT,pre-matching,extended-matching
DOMAIN,api.biliapi.net,REJECT,pre-matching,extended-matching
DOMAIN,app.biliapi.net,REJECT,pre-matching,extended-matching
AND,((DOMAIN-SUFFIX,chat.bilibili.com), (OR,((DOMAIN-KEYWORD,stun), (DOMAIN-KEYWORD,tracker), (DOMAIN-KEYWORD,p2p)))),REJECT,pre-matching
`

func TestModuleRulesBilijump(t *testing.T) {
	module, err := Parse(bilijumpRuleFixture, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(module.Rules) != 6 {
		t.Fatalf("got %d rules, want 6", len(module.Rules))
	}
	if len(module.Warnings) != 3 {
		t.Fatalf("want three deduplicated compatibility warnings, got %v", module.Warnings)
	}
	for i, rule := range module.Rules {
		if i == 0 {
			if rule.Policy != "DIRECT" || rule.PreMatching {
				t.Fatal("Cloudflare DIRECT rule changed")
			}
		} else if rule.Policy != "REJECT" || !rule.PreMatching {
			t.Fatalf("reject rule %d changed: %+v", i, rule)
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
