// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestGlobalAPIAndDynamicRoutingRoundTrip(t *testing.T) {
	conf := parseConfig(t, `global { lan_interface: dae-test-* }
api { listen: 9080 admin_key: 'test-key' }
group { proxy { filter: subtag(subscription) policy: selector } }
client {
 gaming {
   description: '游戏加速：加入后使用 "代理"，路径 C:\games'
   ipset: dae_gaming
   nftset: 'inet/filter/dae_gaming'
 }
 streaming {}
}
routing { client('游戏 加速') && l4proto(udp) -> proxy
 client(gaming) -> proxy
 fallback: direct }
`)
	if conf.API.Port() != 9080 || conf.API.AdminKey != "test-key" || conf.MITM.Enabled {
		t.Fatal("API configuration depends on Surge")
	}
	if len(conf.Client) != 2 || conf.Client[0].Description != `游戏加速：加入后使用 "代理"，路径 C:\games` {
		t.Fatalf("client descriptions = %#v", conf.Client)
	}
	if client := conf.Client[0]; client.IPSet != "dae_gaming" || client.NFTSet != "inet/filter/dae_gaming" {
		t.Fatalf("client export = %+v", client)
	}
	encoded, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	if restored := parseConfig(t, string(encoded)); !sameConfiguration(conf, restored) {
		t.Fatal("dynamic configuration changed after round trip")
	}
	for _, port := range []string{"-1", "65536"} {
		sections, err := config_parser.Parse("global {}\napi { listen: " + port + " }\nrouting { fallback: direct }")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := New(sections); err == nil {
			t.Fatalf("invalid API port %s accepted", port)
		}
	}
}

func TestGlobalResourceCacheRoundTrip(t *testing.T) {
	for _, setting := range []string{"", "resource_cache: true", "resource_cache: false"} {
		conf := parseConfig(t, "global { "+setting+" }\nrouting { fallback: direct }")
		if conf.Global.ResourceCache != (setting != "resource_cache: false") {
			t.Fatalf("unexpected resource_cache default/value for %q", setting)
		}
		encoded, err := conf.Marshal(2)
		if err != nil {
			t.Fatal(err)
		}
		if restored := parseConfig(t, string(encoded)); restored.Global.ResourceCache != conf.Global.ResourceCache {
			t.Fatal("resource_cache changed after round trip")
		}
	}
}

func TestResourceUpdateInterval(t *testing.T) {
	for _, value := range []string{"0", "1s", "2h"} {
		conf := parseConfig(t, "global { resource_update_interval: "+value+" }\nrouting { fallback: direct }")
		encoded, err := conf.Marshal(2)
		if err != nil {
			t.Fatal(err)
		}
		if restored := parseConfig(t, string(encoded)); restored.Global.ResourceUpdateInterval != conf.Global.ResourceUpdateInterval {
			t.Fatal("resource update interval lost in round trip")
		}
	}
}

func TestClientExportsRejectInvalidConfiguration(t *testing.T) {
	for _, entries := range []string{
		`work { nftset: 'filter/work' }`,
		`work { nftset: 'invalid/filter/work' }`,
		`work { ipset: 'a/b' }`,
		`a { ipset: same } b { ipset: same }`,
		`a { nftset: 'inet/filter/same' } b { nftset: 'inet/filter/same' }`,
	} {
		t.Run(entries, func(t *testing.T) {
			sections, err := config_parser.Parse("global {}\nclient { " + entries + " }\nrouting { fallback: direct }")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New(sections); err == nil {
				t.Fatal("invalid client export accepted")
			}
		})
	}
}

func TestClientDescriptionsRejectDuplicateAcrossIncludes(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "config.dae")
	writeConfigFile(t, entry, "include { 'clients.dae' }\nglobal {}\nclient { gaming { description: 'first' } }\nrouting { fallback: direct }")
	writeConfigFile(t, filepath.Join(dir, "clients.dae"), "client { gaming { description: 'second' } }")
	sections, _, err := NewMerger(entry).Merge()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(sections); err == nil || !strings.Contains(err.Error(), `duplicate client name "gaming"`) {
		t.Fatalf("duplicate client description error = %v", err)
	}
}

func TestAPIDefaultsAndAccessConfiguration(t *testing.T) {
	for _, section := range []string{"", "api {}"} {
		conf := parseConfig(t, "global {}\n"+section+"\nrouting { fallback: direct }")
		if conf.API.Listen != "" || conf.API.AllowLANAnonymous || conf.API.Pprof || !conf.API.Web || conf.API.MITMTestIPv4 != "" || conf.API.MITMTestIPv6 != "" {
			t.Fatalf("API defaults: %+v", conf.API)
		}
	}
	for _, text := range []string{
		"api { listen: '0' }", "api { listen: ':9080' }", "api { listen: 'router.local:9080' }",
		"api { user_key: same admin_key: same }", "api { user_key: 'contains space' }",
		"api { web_origins: 'https://web.example/path' }", "api { web_origins: '*' }",
	} {
		sections, err := config_parser.Parse("global {}\n" + text + "\nrouting { fallback: direct }")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := New(sections); err == nil {
			t.Fatalf("invalid API config accepted: %s", text)
		}
	}
	conf := parseConfig(t, "global {}\napi { listen: '[::1]:9080' user_key: user admin_key: admin web: false pprof: true allow_lan_anonymous: true web_origins: 'https://web.example' }\nrouting { fallback: direct }")
	address, port, lan, err := conf.API.Endpoint()
	if err != nil || address != "[::1]:9080" || port != 9080 || lan || conf.API.Web || !conf.API.Pprof || len(conf.API.WebOrigins) != 1 {
		t.Fatalf("explicit endpoint: %+v %s %d %v %v", conf.API, address, port, lan, err)
	}
	address, port, lan, err = (API{Listen: "9080"}).Endpoint()
	if err != nil || address != ":9080" || port != 9080 || !lan {
		t.Fatalf("LAN endpoint: %s %d %v %v", address, port, lan, err)
	}
}

func TestAPILANListenRequiresInterfaces(t *testing.T) {
	for _, test := range []struct {
		name, global, listen, wantError string
	}{
		{name: "disabled"},
		{name: "bare port without LAN", listen: "9080", wantError: "global.lan_interface"},
		{name: "unmatched pattern allowed", global: "lan_interface: dae-test-nonexistent-*", listen: "9080"},
		{name: "explicit IPv4", listen: "127.0.0.1:9080"},
		{name: "explicit IPv6", listen: "[::1]:9080"},
		{name: "mapped link-local IPv4", listen: "[::ffff:169.254.1.1]:9080"},
		{name: "link-local IPv6", listen: "[fe80::1]:9080", wantError: "scoped IPv6"},
		{name: "named zone", listen: "[fe80::1%lan]:9080", wantError: "scoped IPv6"},
		{name: "numeric zone", listen: "[2001:db8::1%7]:9080", wantError: "scoped IPv6"},
		{name: "wildcard IPv4", listen: "0.0.0.0:9080"},
		{name: "wildcard IPv6", listen: "[::]:9080"},
		{name: "API validated first", listen: "0", wantError: "port must be between"},
	} {
		t.Run(test.name, func(t *testing.T) {
			sections, err := config_parser.Parse("global { " + test.global + " }\napi { listen: '" + test.listen + "' }\nrouting { fallback: direct }")
			if err != nil {
				t.Fatal(err)
			}
			_, err = New(sections)
			if test.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("New() error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestAPIWebOriginsValidation(t *testing.T) {
	for _, value := range []string{
		"https://WEB.Example",
		"HTTPS://WEB.Example:443",
		"http://[::1]:9080",
	} {
		t.Run(value, func(t *testing.T) {
			api := API{WebOrigins: []string{value}}
			if err := api.Validate(); err != nil || api.WebOrigins[0] != value {
				t.Fatalf("validation changed or rejected configured origin: %+v, %v", api, err)
			}
		})
	}
	for _, value := range []string{
		"", "*", "ftp://web.example", "https://web.example/", "https://web.example:0", "https://[fe80::1%25eth0]",
	} {
		t.Run(value, func(t *testing.T) {
			if err := (API{WebOrigins: []string{value}}).Validate(); err == nil {
				t.Fatal("invalid API origin accepted")
			}
		})
	}
}
