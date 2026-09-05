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
 gaming: '游戏加速：加入后使用 "代理"，路径 C:\games'
 streaming: ''
}
routing { client('游戏 加速') && l4proto(udp) -> proxy
 client(gaming) -> proxy
 fallback: direct }
`)
	if conf.Global.APIPort != 9080 || conf.Global.APIToken != "test-token" || conf.Surge.Enabled {
		t.Fatal("API configuration depends on Surge")
	}
	if conf.Client["gaming"] != `游戏加速：加入后使用 "代理"，路径 C:\games` || len(conf.Client) != 2 {
		t.Fatalf("client descriptions = %#v", conf.Client)
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

func TestClientDescriptionsRejectDuplicateAcrossIncludes(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "config.dae")
	writeConfigFile(t, entry, "include { 'clients.dae' }\nglobal {}\nclient { gaming: 'first' }\nrouting { fallback: direct }")
	writeConfigFile(t, filepath.Join(dir, "clients.dae"), "client { gaming: 'second' }")
	sections, _, err := NewMerger(entry).Merge()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(sections); err == nil || !strings.Contains(err.Error(), `duplicate client name "gaming"`) {
		t.Fatalf("duplicate client description error = %v", err)
	}
}
