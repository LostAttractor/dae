/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestParsePrefixesBareAddresses(t *testing.T) {
	got, err := parsePrefixes([]string{"192.0.2.1", "2001:db8::1"})
	if err != nil {
		t.Fatalf("parsePrefixes: %v", err)
	}

	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.1/32"),
		netip.MustParsePrefix("2001:db8::1/128"),
	}
	if len(got) != len(want) {
		t.Fatalf("len(parsePrefixes(...)) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("prefix %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestL4ProtoParserRejectsUnknownValues(t *testing.T) {
	parser := L4ProtoParserFactory(func(_ *config_parser.Function, got consts.L4ProtoType, _ *Outbound) error {
		if got != consts.L4ProtoType_TCP|consts.L4ProtoType_UDP {
			t.Fatalf("l4proto mask = %v", got)
		}
		return nil
	})
	if err := parser(&config_parser.Function{}, "", []string{"tcp", "udp"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := parser(&config_parser.Function{}, "protocol", []string{"tcp", "udp"}, nil); err == nil {
		t.Error("keyed l4proto values unexpectedly succeeded")
	}
	for _, values := range [][]string{{"icmp"}, {"tcp", "icmp"}, {"TCP"}} {
		if err := parser(&config_parser.Function{}, "", values, nil); err == nil {
			t.Errorf("l4proto values %v unexpectedly succeeded", values)
		}
	}
}

func TestIpVersionParserRejectsUnknownValues(t *testing.T) {
	parser := IpVersionParserFactory(func(_ *config_parser.Function, got consts.IpVersionType, _ *Outbound) error {
		if got != consts.IpVersion_4|consts.IpVersion_6 {
			t.Fatalf("ipversion mask = %v", got)
		}
		return nil
	})
	if err := parser(&config_parser.Function{}, "", []string{"4", "6"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := parser(&config_parser.Function{}, "version", []string{"4", "6"}, nil); err == nil {
		t.Error("keyed ipversion values unexpectedly succeeded")
	}
	for _, values := range [][]string{{"5"}, {"4", "5"}, {"v4"}} {
		if err := parser(&config_parser.Function{}, "", values, nil); err == nil {
			t.Errorf("ipversion values %v unexpectedly succeeded", values)
		}
	}
}

func TestScalarParsersRejectKeys(t *testing.T) {
	parsers := map[string]struct {
		parser FunctionParser
		value  string
	}{
		"ip": {
			parser: IpParserFactory(func(*config_parser.Function, []netip.Prefix, *Outbound) error { return nil }),
			value:  "192.0.2.1",
		},
		"mac": {
			parser: MacParserFactory(func(*config_parser.Function, [][6]byte, *Outbound) error { return nil }),
			value:  "00:11:22:33:44:55",
		},
		"port": {
			parser: PortRangeParserFactory(func(*config_parser.Function, [][2]uint16, *Outbound) error { return nil }),
			value:  "443",
		},
		"process": {
			parser: ProcessNameParserFactory(func(*config_parser.Function, [][consts.TaskCommLen]byte, *Outbound) error { return nil }),
			value:  "dae",
		},
		"uint": {
			parser: UintParserFactory(func(*config_parser.Function, []uint32, *Outbound) error { return nil }),
			value:  "2",
		},
	}
	for name, test := range parsers {
		t.Run(name, func(t *testing.T) {
			if err := test.parser(&config_parser.Function{}, "typo", []string{test.value}, nil); err == nil {
				t.Fatal("keyed scalar value unexpectedly succeeded")
			}
		})
	}
}
