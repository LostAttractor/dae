// SPDX-License-Identifier: AGPL-3.0-only

package dnsrouter

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestRouterFallbackDefaults(t *testing.T) {
	for _, body := range []string{"", "routing {}", "routing { request {} response {} }"} {
		sections, err := config_parser.Parse("router {" + body + "}")
		if err != nil {
			t.Fatal(err)
		}
		conf, prefer, err := parseSettings(plugin.Spec{Config: sections[0]})
		if err != nil {
			t.Fatal(err)
		}
		request, response := conf.Routing.Request.Fallback, conf.Routing.Response.Fallback
		if prefer != 0 || request == nil || request.Name != "asis" || request.Quoted || len(request.Params) != 0 || response == nil || response.Name != "accept" || response.Quoted || len(response.Params) != 0 {
			t.Fatalf("unexpected DNS defaults: request=%+v response=%+v prefer=%d", request, response, prefer)
		}
	}
}

func TestRouterFallbackParameters(t *testing.T) {
	for _, test := range []struct {
		value  string
		name   string
		quoted bool
		params int
	}{
		{"asis", "asis", false, 0},
		{`"must"`, "must", true, 0},
		{`"a,b"`, "a,b", true, 0},
		{`""`, "", true, 0},
		{"asis(skip_while_noalive)", "asis", false, 1},
	} {
		sections, err := config_parser.Parse("request { fallback: " + test.value + " }")
		if err != nil {
			t.Fatal(err)
		}
		var rules []*config_parser.RoutingRule
		var fallback *config_parser.Function
		if err := decodeRoutingSettings(sections[0], &rules, &fallback); err != nil {
			t.Fatal(err)
		}
		if fallback.Name != test.name || fallback.Quoted != test.quoted || len(fallback.Params) != test.params {
			t.Fatalf("fallback %s changed: %+v", test.value, fallback)
		}
	}
	for _, value := range []string{"asis,accept", "asis(skip_while_noalive) && accept(skip_while_noalive)"} {
		sections, err := config_parser.Parse("request { fallback: " + value + " }")
		if err != nil {
			t.Fatal(err)
		}
		var rules []*config_parser.RoutingRule
		var fallback *config_parser.Function
		if err := decodeRoutingSettings(sections[0], &rules, &fallback); err == nil {
			t.Fatalf("multiple fallbacks accepted: %s", value)
		}
	}
	for _, functions := range [][]*config_parser.Function{nil, {}, {nil}} {
		section := &config_parser.Section{Name: "request", Items: []*config_parser.Item{{Value: &config_parser.Param{Key: "fallback", AndFunctions: functions}}}}
		var rules []*config_parser.RoutingRule
		var fallback *config_parser.Function
		if err := decodeRoutingSettings(section, &rules, &fallback); err == nil {
			t.Fatalf("invalid fallback accepted: %+v", functions)
		}
	}
}

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
