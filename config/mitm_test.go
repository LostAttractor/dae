package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestMITMConfigRoundTrip(t *testing.T) {
	c := parseConfig(t, `global {}
mitm {
  buffer_memory_limit: 67108864
 enabled: true
 client_source_address: '192.0.2.0/24'
}
plugins {
 surge_work { type: surge
   module { work: 'file:work.sgmodule' }
   script_timeout: 9s
 }
 future { enabled: false
   credentials { key: 'opaque-value' }
 }
 surge { module { 'file:personal.sgmodule' } }
}
rules {
 pname(mosdns) -> must
 domain(full: api.example.com) && dport(443) -> dnat('2001:db8::20')
 domain(full: api.example.com) -> bump
 dip(192.0.2.1) -> dnat(198.51.100.2)
}
routing { fallback: direct }`)
	if c.MITM.BufferMemoryLimit != 67108864 {
		t.Fatal(c.MITM.BufferMemoryLimit)
	}
	if len(c.Plugins) != 3 || c.Plugins[0].Name != "surge_work" || c.Plugins[0].Type != "surge" || c.Plugins[1].Enabled || !c.Plugins[2].Enabled {
		t.Fatalf("wrong instances: %+v", c.MITM)
	}
	b, err := c.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	round := parseConfig(t, string(b))
	// The parser preserves literal quoting metadata; compare canonical output
	// and decoded behavior instead of the original lexical spelling.
	b2, err := round.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != string(b2) {
		t.Fatalf("unstable marshal:\n%s\n%s", b, b2)
	}
	if round.MITM.BufferMemoryLimit != c.MITM.BufferMemoryLimit {
		t.Fatal("memory limit changed")
	}
	for i, p := range round.Plugins {
		if p.Name != c.Plugins[i].Name || p.Type != c.Plugins[i].Type || p.Enabled != c.Plugins[i].Enabled {
			t.Fatal("instance order changed")
		}
	}
	a, _ := c.Rules.Destinations()
	z, _ := round.Rules.Destinations()
	if len(a) != 2 || !reflect.DeepEqual(a[0].To, z[0].To) || a[0].To[0].String() != "2001:db8::20" {
		t.Fatal("DNAT target changed")
	}
	plan, err := round.Rules.Plan()
	if err != nil || len(plan.Controls) != 2 || plan.Controls[0].Action != consts.MatchActionMust || plan.Controls[1].Action != consts.MatchActionBump {
		t.Fatalf("flow controls changed: %+v, %v", plan, err)
	}
	if round.Rules.Rules[0].Outbound.Name != "must" || strings.Contains(string(b), "must_rules") {
		t.Fatal("internal action name leaked into configuration")
	}
	if strings.Contains(string(b), "\nsurge {") {
		t.Fatal("legacy surge emitted alongside mitm")
	}
}

func TestMITMConfigRejectsInvalid(t *testing.T) {
	for _, body := range []string{
		`mitm { ca_cert: cert }`,
		`mitm { buffer_memory_limit: 0 }`,
		`mitm { buffer_memory_limit: -1 }`,
		`mitm { unknown: true }`,
		`mitm { surge {} surge {} }`,
		`mitm { ../escape {} }`,
		`mitm { x { enabled: perhaps } }`,
		`mitm { x { type: surge type: surge } }`,
		`mitm {} surge {}`,
		`rules { dip(192.0.2.1) -> direct }`,
		`rules { dip(192.0.2.1) -> must_rules }`,
		`rules { dip(192.0.2.1) -> must(mark: 37) }`,
		`rules { dip(192.0.2.1) -> bump(must) }`,
		`rules { dip(192.0.2.1) -> 'must' }`,
		`rules { dip(192.0.2.1) -> !bump }`,
		`rules { dip(192.0.2.1) -> dnat() }`,
		`rules { dip(192.0.2.1) -> dnat(192.0.2.2, 192.0.2.3) }`,
		`rules { dip(192.0.2.1) -> dnat(example.com) }`,
		`rules { dip(192.0.2.1) -> dnat('192.0.2.1:0') }`,
		`rules { dip(192.0.2.1) -> dnat('fe80::1%eth0') }`,
		`rules { dip(192.0.2.1) -> dnat(192.0.2.0/24) }`,
	} {
		t.Run(body, func(t *testing.T) {
			sections, err := config_parser.Parse("global {}\n" + body + "\nrouting { fallback: direct }")
			if err == nil {
				_, err = New(sections)
			}
			if err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}
