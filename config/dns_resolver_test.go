// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestDNSResolver(t *testing.T) {
	for _, value := range []string{"", "192.0.2.53", "192.0.2.53:1053", "2001:db8::53", "[2001:db8::53]:1053"} {
		t.Run(value, func(t *testing.T) {
			conf := parseConfig(t, "global { dns_resolver: '"+value+"' } routing { fallback: direct }")
			wire, err := conf.Marshal(2)
			if err != nil {
				t.Fatal(err)
			}
			if got := parseConfig(t, string(wire)).Global.DNSResolver; got != value {
				t.Fatalf("resolver changed in round trip: %q != %q", got, value)
			}
		})
	}
	for _, value := range []string{"dns.example", "https://dns.example/dns-query", "192.0.2.53:0", "192.0.2.53:65536", "0.0.0.0", "::", "[::ffff:0.0.0.0]:53", "[fe80::1%eth0]:53"} {
		t.Run("invalid/"+value, func(t *testing.T) {
			sections, err := config_parser.Parse("global { dns_resolver: '" + value + "' } routing { fallback: direct }")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New(sections); err == nil || !strings.Contains(err.Error(), "dns_resolver") {
				t.Fatalf("invalid resolver accepted: %v", err)
			}
		})
	}
}
