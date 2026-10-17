// SPDX-License-Identifier: AGPL-3.0-only

package dnsrouter

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestRouterSettingsRedactValues(t *testing.T) {
	const secret = "https://user:private-token@example.test/private"
	for _, body := range []string{
		"ipversion_prefer:'" + secret + "'",
		"routing { request { '" + secret + "' } }",
		"upstream { resolver:'https://example.test:private-token/dns-query' }",
	} {
		sections, err := config_parser.Parse("router {" + body + "}")
		if err != nil {
			t.Fatal(err)
		}
		_, err = Configure(plugin.Spec{Config: sections[0]})
		if err == nil || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "user") {
			t.Fatalf("configuration error was absent or exposed a value: %v", err)
		}
	}
}
