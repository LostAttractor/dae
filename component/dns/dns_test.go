/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"net/url"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dnsmessage "github.com/miekg/dns"
)

func TestGetUpstreamValidatesIndex(t *testing.T) {
	raw, err := url.Parse("udp://192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	s := &Dns{upstream: []*UpstreamResolver{{Raw: raw}}}

	invalid := []struct {
		name  string
		index consts.DnsRequestOutboundIndex
	}{
		{name: "negative", index: -1},
		{name: "reject", index: consts.DnsRequestOutboundIndex_Reject},
		{name: "asis", index: consts.DnsRequestOutboundIndex_AsIs},
		{name: "logical or", index: consts.DnsRequestOutboundIndex_LogicalOr},
		{name: "logical and", index: consts.DnsRequestOutboundIndex_LogicalAnd},
		{name: "out of bounds", index: 1},
		{name: "out of bounds above reserved range", index: 256},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.GetUpstream(context.Background(), tt.index); err == nil {
				t.Fatalf("GetUpstream(%v) succeeded", tt.index)
			}
		})
	}

	upstream, err := s.GetUpstream(context.Background(), 0)
	if err != nil {
		t.Fatalf("GetUpstream(0): %v", err)
	}
	if upstream.Ip4.String() != "192.0.2.1" {
		t.Fatalf("upstream IPv4 = %v, want 192.0.2.1", upstream.Ip4)
	}
}

func TestNewSupportsOnlyCanonicalInterfaceRequestRule(t *testing.T) {
	for _, test := range []struct {
		name    string
		wantErr bool
	}{
		{name: consts.Function_Interface},
		{name: "ifindex", wantErr: true},
		{name: "ifname", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			rule := &config_parser.RoutingRule{
				AndFunctions: []*config_parser.Function{{
					Name:   test.name,
					Params: []*config_parser.Param{{Val: "eth0"}},
				}},
				Outbound: config_parser.Function{Name: consts.DnsRequestOutboundIndex_AsIs.String()},
			}
			conf := &config.Dns{Routing: config.DnsRouting{
				Request: config.DnsRequestRouting{
					Rules:    []*config_parser.RoutingRule{rule},
					Fallback: config.FunctionOrString(consts.DnsRequestOutboundIndex_AsIs.String()),
				},
				Response: config.DnsResponseRouting{
					Fallback: config.FunctionOrString(consts.DnsResponseOutboundIndex_Accept.String()),
				},
			}}

			_, err := New(conf, &NewOption{})
			if (err != nil) != test.wantErr {
				t.Fatalf("New() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestResponseSelectOnlyMatches(t *testing.T) {
	builder, err := NewResponseMatcherBuilder(nil, map[string]uint8{"next": 0}, config.FunctionOrString("next"))
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := url.Parse("udp://does-not-resolve.invalid")
	if err != nil {
		t.Fatal(err)
	}
	resolver := &UpstreamResolver{Raw: raw}
	s := &Dns{
		upstream:    []*UpstreamResolver{resolver},
		respMatcher: matcher,
	}
	msg := &dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{Response: true},
		Question: []dnsmessage.Question{{
			Name:  "example.com.",
			Qtype: dnsmessage.TypeA,
		}},
	}

	index, err := s.ResponseSelect(msg, consts.DnsRequestOutboundIndex_AsIs)
	if err != nil {
		t.Fatalf("ResponseSelect: %v", err)
	}
	if index != 0 {
		t.Fatalf("ResponseSelect index = %v, want 0", index)
	}
	if resolver.upstream != nil {
		t.Fatal("ResponseSelect initialized the selected upstream")
	}
}
