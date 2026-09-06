// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestGlobalAPIAndDynamicRoutingRoundTrip(t *testing.T) {
	conf := parseConfig(t, `global { api_port: 9080 api_token: 'test-token' }
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
	if conf.Global.APIPort != 9080 || conf.Global.APIToken != "test-token" || conf.Surge.Enabled {
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
	if restored := parseConfig(t, string(encoded)); !reflect.DeepEqual(conf, restored) {
		t.Fatal("dynamic configuration changed after round trip")
	}
	for _, port := range []string{"-1", "65536"} {
		sections, err := config_parser.Parse("global { api_port: " + port + " }\nrouting { fallback: direct }")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := New(sections); err == nil {
			t.Fatalf("invalid API port %s accepted", port)
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
