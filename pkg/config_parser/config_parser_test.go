/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import (
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	sections, err := Parse(`
# gugu
include {
    another.conf
}

global {
    # tproxy port to listen.
    tproxy_port: 12345

    # Node connectivity check url.
    check_url: 'https://connectivitycheck.gstatic.com/generate_204'

    # Now only support UDP and IP:Port.
    # Please make sure DNS traffic will go through and be forwarded by dae.
    dns_upstream: '1.1.1.1:53'

    # Now only support one interface.
    ingress_interface: docker0
}

# subscription will be resolved as nodes and merged into node pool below.
subscription {
    https://LINK
}

node {
    'ss://LINK'
    'ssr://LINK'
    'vmess://LINK'
    'vless://LINK'
    'trojan://LINK'
    'trojan-go://LINK'
    'socks5://LINK#name'
    'http://LINK#name'
    'https://LINK#name'
}

group {
    my_group {
        # Pass node links as input of lua script filter.
        # gugu
        filter: link(lua:filename.lua)

        # Randomly select a node from the group for every connection.
        policy: random
    }

    disney {
        # Pass node names as input of keyword/regex filter.
        filter: name(regex:'^.*hk.*$', keyword:'sg') && name(keyword:'disney')

        # Select the node with min average of the last 10 latencies from the group for every connection.
        policy: min_avg10
    }

    netflix {
        # Pass node names as input of keyword filter.
        filter: name(keyword:netflix)

        # Select the first node from the group for every connection.
        policy: fixed(0)
    }
}

routing {
    sip(192.168.0.0/24) && !sip(192.168.0.252/30) -> direct

    domain(geosite:category-ads) -> block
    domain(geosite:disney) -> disney
    domain(geosite:netflix) -> netflix
    ip(geoip:cn) -> direct
    domain(geosite:cn) -> direct
    fallback: my_group
}
`)
	if err != nil {
		t.Fatalf("\n%v", err)
	}
	for _, section := range sections {
		t.Logf("\n%v", section.String(false, false))
	}
}

func TestParseQuotedRoutingTargets(t *testing.T) {
	sections, err := Parse(`
routing {
	domain(full: example.com) -> '香港 01'(mark: 0x800, skip_while_noalive)
	domain(full: bare.example) -> proxy(skip_while_noalive)
	fallback: 'Fallback Node'(mark: 0x400)
}
`)
	if err != nil {
		t.Fatal(err)
	}
	items := sections[0].Items
	if len(items) != 3 {
		t.Fatalf("items = %d, want 3", len(items))
	}
	quoted := items[0].Value.(*RoutingRule).Outbound
	if quoted.Name != "香港 01" || !reflect.DeepEqual(quoted.Params, []*Param{{Key: "mark", Val: "0x800"}, {Val: "skip_while_noalive"}}) {
		t.Fatalf("quoted outbound = %#v", quoted)
	}
	bare := items[1].Value.(*RoutingRule).Outbound
	if bare.Name != "proxy" || !reflect.DeepEqual(bare.Params, []*Param{{Val: "skip_while_noalive"}}) {
		t.Fatalf("bare callable outbound = %#v", bare)
	}
	fallback := items[2].Value.(*Param)
	if fallback.Key != "fallback" || len(fallback.AndFunctions) != 1 || fallback.AndFunctions[0].Name != "Fallback Node" {
		t.Fatalf("fallback = %#v", fallback)
	}
	if got := items[0].Value.(*RoutingRule).String(false, true, true); got != `domain(full:"example.com")->"香港 01"(mark:"0x800","skip_while_noalive")` {
		t.Fatalf("marshaled routing rule = %q", got)
	}
}

func TestParseProxyPath(t *testing.T) {
	sections, err := Parse(`
group {
	target {
		filter: name('relay node') [priority: 1] -> filter: subtag(exit) && name(keyword: '日本') -> group(edge)
	}
}

`)
	if err != nil {
		t.Fatal(err)
	}
	group := sections[0].Items[0].Value.(*Section)
	path := group.Items[0].Value.(*ProxyPath)
	if len(path.Stages) != 3 {
		t.Fatalf("stages = %#v", path.Stages)
	}
	if path.Stages[0].Key != "filter" || len(path.Stages[0].Annotation) != 1 || path.Stages[0].Annotation[0].Key != "priority" {
		t.Fatalf("first stage = %#v", path.Stages[0])
	}
	if path.Stages[1].Key != "filter" || len(path.Stages[1].AndFunctions) != 2 {
		t.Fatalf("second stage = %#v", path.Stages[1])
	}
	if path.Stages[2].AndFunctions[0].Name != "group" || path.Stages[2].AndFunctions[0].Params[0].Val != "edge" {
		t.Fatalf("third stage = %#v", path.Stages[2])
	}
	if got := path.String(true, true); got != `filter:name("relay node") [priority:"1"]->filter:subtag("exit")&&name(keyword:"日本")->group("edge")` {
		t.Fatalf("marshaled proxy path = %q", got)
	}
}

func TestParseRejectsInvalidContextualExpressions(t *testing.T) {
	for _, test := range []struct {
		name    string
		config  string
		message string
	}{
		{
			name:    "routing chain",
			config:  `routing { domain(full: example.com) -> direct -> block }`,
			message: "routing rules require exactly two arrow operands",
		},
		{
			name:    "untyped path reference",
			config:  `group { target { name(proxy) } }`,
			message: "path reference must be node(name) or group(name)",
		},
		{
			name:    "path reference outside group",
			config:  `global { node(proxy) }`,
			message: "proxy path reference outside a group definition",
		},
		{
			name:    "legacy via",
			config:  `group { target { filter: name(exit) [via: node(entry)] } }`,
			message: "via annotations are no longer supported",
		},
		{
			name:    "legacy bare via",
			config:  `group { target { filter: name(exit) [via: entry] } }`,
			message: "via annotations are no longer supported",
		},
		{
			name:    "legacy via among annotations",
			config:  `group { target { filter: name(exit) [priority: 1, via: node(entry)] } }`,
			message: "via annotations are no longer supported",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(test.config)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestQuotedRoutingTargetUnescapesMarshallerOutput(t *testing.T) {
	name := `Node "A" \ path`
	sections, err := Parse(`routing { domain(full: example.com) -> "Node \"A\" \\ path" }`)
	if err != nil {
		t.Fatal(err)
	}
	rule := sections[0].Items[0].Value.(*RoutingRule)
	if rule.Outbound.Name != name {
		t.Fatalf("name = %q, want %q", rule.Outbound.Name, name)
	}
	marshaled := rule.String(false, true, true)
	sections, err = Parse("routing { " + marshaled + " }")
	if err != nil {
		t.Fatal(err)
	}
	if got := sections[0].Items[0].Value.(*RoutingRule).Outbound.Name; got != name {
		t.Fatalf("round-trip name = %q, want %q", got, name)
	}
}

func TestQuotedTargetPreservesNonQuoteEscapes(t *testing.T) {
	sections, err := Parse(`routing { domain(full: example.com) -> "node\nname" }`)
	if err != nil {
		t.Fatal(err)
	}
	if got := sections[0].Items[0].Value.(*RoutingRule).Outbound.Name; got != `node\nname` {
		t.Fatalf("name = %q, want a literal backslash escape", got)
	}
}

func TestQuotedParameterRoundTrip(t *testing.T) {
	const input = `group { proxy { filter: name(regex: '^HK\d+$') } }`
	sections, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	group := sections[0].Items[0].Value.(*Section)
	path := group.Items[0].Value.(*ProxyPath)
	if got := path.Stages[0].AndFunctions[0].Params[0].Val; got != `^HK\d+$` {
		t.Fatalf("regex = %q, want quoted literal escapes preserved", got)
	}
	sections, err = Parse("group { proxy { " + path.String(true, true) + " } }")
	if err != nil {
		t.Fatal(err)
	}
	group = sections[0].Items[0].Value.(*Section)
	got := group.Items[0].Value.(*ProxyPath).Stages[0].AndFunctions[0].Params[0].Val
	if got != `^HK\d+$` {
		t.Fatalf("round-trip regex = %q", got)
	}
}

func TestQuotedControlCharactersRoundTrip(t *testing.T) {
	want := "node\n\tname\\"
	path := &ProxyPath{Stages: []*Param{{AndFunctions: []*Function{{
		Name: "node", Params: []*Param{{Val: want}},
	}}}}}
	sections, err := Parse("group { proxy { " + path.String(true, true) + " } }")
	if err != nil {
		t.Fatal(err)
	}
	group := sections[0].Items[0].Value.(*Section)
	got := group.Items[0].Value.(*ProxyPath).Stages[0].AndFunctions[0].Params[0].Val
	if got != want {
		t.Fatalf("round-trip parameter = %q, want %q", got, want)
	}

	rule := &RoutingRule{
		AndFunctions: []*Function{{Name: "domain", Params: []*Param{{Key: "full", Val: "example.com"}}}},
		Outbound:     Function{Name: want, Quoted: true},
	}
	sections, err = Parse("routing { " + rule.String(false, true, true) + " }")
	if err != nil {
		t.Fatal(err)
	}
	if got := sections[0].Items[0].Value.(*RoutingRule).Outbound.Name; got != want {
		t.Fatalf("round-trip target = %q, want %q", got, want)
	}
}

func TestQuotedRoutingMatcherRoundTrip(t *testing.T) {
	sections, err := Parse(`routing { 'domain matcher'(full: example.com) -> direct }`)
	if err != nil {
		t.Fatal(err)
	}
	rule := sections[0].Items[0].Value.(*RoutingRule)
	if got := rule.String(false, true, true); got != `"domain matcher"(full:"example.com")->direct` {
		t.Fatalf("marshaled routing rule = %q", got)
	}
	if _, err := Parse("routing { " + rule.String(false, true, true) + " }"); err != nil {
		t.Fatalf("parse marshaled routing rule: %v", err)
	}
}
