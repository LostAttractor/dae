package config

import (
	"reflect"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestMITMConfigRoundTrip(t *testing.T) {
	c := parseConfig(t, `global {}
mitm {
 enabled: true
 client_source_address: '192.0.2.0/24'
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
 domain(full: api.example.com) && dport(443) -> dnat('2001:db8::20')
 dip(192.0.2.1) -> dnat(198.51.100.2)
}
routing { fallback: direct }`)
	if len(c.MITM.Plugins) != 3 || c.MITM.Plugins[0].Name != "surge_work" || c.MITM.Plugins[0].Type != "surge" || c.MITM.Plugins[1].Enabled || !c.MITM.Plugins[2].Enabled {
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
	for i, p := range round.MITM.Plugins {
		if p.Name != c.MITM.Plugins[i].Name || p.Type != c.MITM.Plugins[i].Type || p.Enabled != c.MITM.Plugins[i].Enabled {
			t.Fatal("instance order changed")
		}
	}
	a, _ := c.Rules.Destinations()
	z, _ := round.Rules.Destinations()
	if len(a) != 2 || !reflect.DeepEqual(a[0].To, z[0].To) || a[0].To[0].String() != "2001:db8::20" {
		t.Fatal("DNAT target changed")
	}

}

func TestMITMConfigRejectsInvalid(t *testing.T) {
	for _, body := range []string{
		`mitm { ca_cert: cert }`,
		`mitm { unknown: true }`,
		`mitm { surge {} surge {} }`,
		`mitm { ../escape {} }`,
		`mitm { x { enabled: perhaps } }`,
		`mitm { x { type: surge type: surge } }`,
		`rules { dip(192.0.2.1) -> direct }`,
		`rules { dip(192.0.2.1) -> dnat() }`,
		`rules { dip(192.0.2.1) -> dnat(192.0.2.2, 192.0.2.3) }`,
		`rules { dip(192.0.2.1) -> dnat(example.com) }`,
		`rules { dip(192.0.2.1) -> dnat('192.0.2.1:80') }`,
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
