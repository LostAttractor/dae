// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
	dnsmessage "github.com/miekg/dns"
)

func TestRequestAndResponseMatchCompoundRules(t *testing.T) {
	sections, err := config_parser.Parse(`rules {
		qname(suffix: example) && !qtype(A, AAAA) -> hit
		qtype(A, AAAA) && qname(full: hot.test) -> hit
	}`)
	if err != nil {
		t.Fatal(err)
	}
	var rules []*config_parser.RoutingRule
	for _, item := range sections[0].Items {
		rules = append(rules, item.Value.(*config_parser.RoutingRule))
	}
	names := map[string]uint8{"hit": 1, "otherwise": 2}
	requestBuilder, err := NewRequestMatcherBuilder(rules, names, "otherwise", nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := requestBuilder.Build()
	if err != nil {
		t.Fatal(err)
	}
	responseBuilder, err := NewResponseMatcherBuilder(rules, names, "otherwise")
	if err != nil {
		t.Fatal(err)
	}
	response, err := responseBuilder.Build()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		qtype uint16
		want  uint8
	}{
		{"test.example.", dnsmessage.TypeTXT, 1},
		{"test.example.", dnsmessage.TypeA, 2},
		{"test.example.", dnsmessage.TypeAAAA, 2},
		{"hot.test.", dnsmessage.TypeA, 1},
		{"hot.test.", dnsmessage.TypeAAAA, 1},
		{"hot.test.", dnsmessage.TypeTXT, 2},
		{"outside.test.", dnsmessage.TypeA, 2},
	} {
		req, err := request.Match(test.name, test.qtype, 0, netip.IPv4Unspecified(), netip.IPv4Unspecified())
		if err != nil || uint8(req) != test.want {
			t.Fatalf("request %s/%d = %d, %v; want %d", test.name, test.qtype, req, err, test.want)
		}
		resp, err := response.Match(test.name, test.qtype, nil, DnsRequestOutboundIndex_AsIs)
		if err != nil || uint8(resp) != test.want {
			t.Fatalf("response %s/%d = %d, %v; want %d", test.name, test.qtype, resp, err, test.want)
		}
	}
}
