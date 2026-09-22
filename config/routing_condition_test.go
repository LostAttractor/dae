// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestConditionalUseRoundTrip(t *testing.T) {
	conf := parseConfig(t, `global {}
 routing {
  rule_set {
   local { dip(10.0.0.0/8) -> direct }
   office { !dport(22,80) && domain(regex: '^corp\\.example$') -> proxy }
   must { dport(443) -> direct }
   nested { l4proto(tcp) -> use(local, office, must) }
  }
  dport(22) -> direct
  sip(192.168.10.0/24) && !client(guests) -> use(nested, office)
  use: local
  dport(443) -> 'use'(mark: 7)
  dport(80) -> use
  fallback: direct
  policy { lan { interface(br-lan) -> use(office)
   fallback: direct } }
  interface { br-lan: lan }
 }`)
	statements := conf.Routing.Policies[0].Statements
	if len(statements) != 6 || statements[0].Kind != RoutingStatementRule ||
		statements[1].Use != "nested" || statements[2].Use != "office" ||
		len(statements[1].Condition) != 2 || !statements[1].Condition[1].Not ||
		!reflect.DeepEqual(statements[1].Condition, statements[2].Condition) ||
		statements[3].Use != "local" || len(statements[3].Condition) != 0 ||
		statements[4].Kind != RoutingStatementRule || statements[5].Kind != RoutingStatementRule {
		t.Fatalf("lost conditional use order or outbound identity: %+v", statements)
	}
	raw, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	got := parseConfig(t, string(raw))
	if !reflect.DeepEqual(conf.Routing, got.Routing) {
		t.Fatalf("conditional use changed after round trip:\n%s", raw)
	}
}

func TestConditionalUseValidation(t *testing.T) {
	for _, test := range []struct{ body, want string }{
		{`dport(80) -> use(missing)`, `undefined rule_set "missing"`},
		{`dport(80) -> use('')`, "nonempty positional"},
		{`dport(80) -> use(mark: 7)`, "nonempty positional"},
		{`dport(80) -> use(local, skip_while_noalive)`, `undefined rule_set "skip_while_noalive"`},
		{`dport(80) -> !use(local)`, "without negation"},
		{`rule_set { cyclic { dport(80) -> use(cyclic) } }`, "rule_set cycle"},
		{`rule_set { a { dport(80) -> use(b) } b { use: a } }`, "rule_set cycle"},
		{`policy { other { fallback: direct } } dport(80) -> use(other)`, "undefined rule_set"},
	} {
		t.Run(test.body, func(t *testing.T) {
			sections, err := config_parser.Parse("global {} routing { rule_set { local {} } " + test.body + "\nfallback: direct }")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New(sections); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
	sections, err := config_parser.Parse(`global {} routing { fallback: use(local) }`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(sections); err == nil || !strings.Contains(err.Error(), "cannot be a fallback") {
		t.Fatalf("error = %v, want conditional fallback rejection", err)
	}
}

func TestConditionalUseRejectsMalformedAST(t *testing.T) {
	for _, condition := range [][]*config_parser.Function{
		{nil},
		{{Name: "dport", Params: []*config_parser.Param{nil}}},
		{{Name: "dport", Params: []*config_parser.Param{{AndFunctions: []*config_parser.Function{{Name: "nested"}}}}}},
	} {
		conf := parseConfig(t, `global {} routing { rule_set { local {} } use: local
 fallback: direct }`)
		conf.Routing.Policies[0].Statements[0].Condition = condition
		if err := conf.Routing.Validate(); err == nil {
			t.Fatalf("accepted malformed condition: %+v", condition)
		}
	}
}
