/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"reflect"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestOutboundForEachLogicalOrPreservesTypes(t *testing.T) {
	type outboundID int16
	type visit struct {
		value string
		id    outboundID
	}
	outbound := &Outbound{Name: "proxy"}
	ids := map[string]outboundID{
		consts.OutboundLogicalOr.String(): 0xfe,
		"proxy":                           7,
	}
	var got []visit
	err := outbound.ForEachLogicalOr([]string{"first", "second", "third"}, func(name string) (outboundID, error) {
		return ids[name], nil
	}, func(value string, id outboundID) error {
		got = append(got, visit{value: value, id: id})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []visit{{"first", 0xfe}, {"second", 0xfe}, {"third", 7}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("visits = %#v, want %#v", got, want)
	}
}

func TestParseOutboundSkipWhileNoalive(t *testing.T) {
	tests := []struct {
		name    string
		params  []*config_parser.Param
		want    bool
		wantErr bool
	}{
		{
			name:   "bare",
			params: []*config_parser.Param{{Key: "", Val: "skip_while_noalive"}},
			want:   true,
		},
		{
			name:   "keyed true",
			params: []*config_parser.Param{{Key: "skip_while_noalive", Val: "true"}},
			want:   true,
		},
		{
			name:   "keyed 1",
			params: []*config_parser.Param{{Key: "skip_while_noalive", Val: "1"}},
			want:   true,
		},
		{
			name:   "keyed false",
			params: []*config_parser.Param{{Key: "skip_while_noalive", Val: "false"}},
			want:   false,
		},
		{
			name:    "keyed invalid",
			params:  []*config_parser.Param{{Key: "skip_while_noalive", Val: "maybe"}},
			wantErr: true,
		},
		{
			name:   "combined with mark",
			params: []*config_parser.Param{{Key: "mark", Val: "0x80"}, {Key: "", Val: "skip_while_noalive"}},
			want:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outbound, err := ParseOutbound(&config_parser.Function{Name: "proxy", Params: tt.params})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", outbound)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseOutbound: %v", err)
			}
			if outbound.SkipWhileNoalive != tt.want {
				t.Fatalf("SkipWhileNoalive = %v, want %v", outbound.SkipWhileNoalive, tt.want)
			}
		})
	}
}

func TestAliasOptimizer(t *testing.T) {
	params := []*config_parser.Param{{Val: "example.com"}, {Key: "full", Val: "example.org"}}
	rules := []*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{{Name: consts.Function_Domain, Params: params}},
		Outbound:     config_parser.Function{Name: "direct"},
	}}
	if _, err := (&AliasOptimizer{}).Optimize(rules); err != nil {
		t.Fatalf("Optimize: %v", err)
	}
	if params[0].Key != string(consts.RoutingDomainKey_Suffix) || params[1].Key != "full" {
		t.Fatalf("domain keys = %q, %q; want a bare domain to match its suffix", params[0].Key, params[1].Key)
	}
}

func TestDatReaderOptimizerRejectsMalformedSpecialParams(t *testing.T) {
	for _, test := range []struct {
		key   string
		value string
	}{
		{key: "mmdb", value: "country"},
		{key: "mmdb", value: "=cn"},
		{key: "mmdb", value: "country="},
		{key: "ext", value: "geoip.dat"},
		{key: "ext", value: ":cn"},
		{key: "ext", value: "geoip.dat:"},
	} {
		rules := []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_DestIp,
				Params: []*config_parser.Param{{
					Key: test.key,
					Val: test.value,
				}},
			}},
		}}
		if _, err := (&DatReaderOptimizer{}).Optimize(rules); err == nil {
			t.Errorf("%s:%q unexpectedly succeeded", test.key, test.value)
		}
	}
}
