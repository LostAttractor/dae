// SPDX-License-Identifier: AGPL-3.0-only

package dnscache

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestCacheSettingsRedactValues(t *testing.T) {
	const secret = "https://user:private-token@example.test/private"
	for _, body := range []string{
		"size:'" + secret + "'", "memory_limit:'" + secret + "'",
		"fixed_domain_ttl { example.test:'" + secret + "' }",
	} {
		sections, err := config_parser.Parse("cache {" + body + "}")
		if err != nil {
			t.Fatal(err)
		}
		_, err = Configure(plugin.Spec{Config: sections[0]})
		if err == nil || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "user") {
			t.Fatalf("configuration error was absent or exposed a value: %v", err)
		}
	}
}

func TestCacheSettingsDefaultsAndListForms(t *testing.T) {
	for _, body := range []string{"fixed_domain_ttl { example.test:60 }", "fixed_domain_ttl:'example.test:60'"} {
		sections, err := config_parser.Parse("cache {" + body + "}")
		if err != nil {
			t.Fatal(err)
		}
		conf, fixed, err := parseSettings(plugin.Spec{Config: sections[0]})
		if err != nil || conf.Size != 32768 || conf.MemoryLimit != 67108864 || fixed["example.test."] != 60 {
			t.Fatalf("defaults/list syntax changed: %+v, %v, %v", conf, fixed, err)
		}
	}
}
