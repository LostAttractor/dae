/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestRoutingMatcherBuilderForEachStaleLpmSlot(t *testing.T) {
	tests := []struct {
		name           string
		previousCount  uint32
		currentCount   int
		wantIterations []uint32
	}{
		{name: "first activation leaves unused slots untouched", currentCount: 2},
		{name: "shrink visits only stale tail", previousCount: 4, currentCount: 2, wantIterations: []uint32{2, 3}},
		{name: "shrink to no tries visits every old slot", previousCount: 3, wantIterations: []uint32{0, 1, 2}},
		{name: "same size rebuild leaves unused slots untouched", previousCount: 2, currentCount: 2},
		{name: "growth leaves unused slots untouched", previousCount: 1, currentCount: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := &RoutingMatcherBuilder{
				bpf:               &bpfState{activeLpmTrieCount: tt.previousCount},
				simulatedLpmTries: make([][]netip.Prefix, tt.currentCount),
			}
			var iterations []uint32
			if err := builder.forEachStaleLpmSlot(func(i uint32) error {
				iterations = append(iterations, i)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(iterations, tt.wantIterations) {
				t.Fatalf("iterations = %v, want %v", iterations, tt.wantIterations)
			}
		})
	}

	t.Run("callback failure stops iteration", func(t *testing.T) {
		builder := &RoutingMatcherBuilder{
			bpf:               &bpfState{activeLpmTrieCount: 5},
			simulatedLpmTries: make([][]netip.Prefix, 2),
		}
		callbackErr := errors.New("callback failed")
		var iterations []uint32
		err := builder.forEachStaleLpmSlot(func(i uint32) error {
			iterations = append(iterations, i)
			if i == 3 {
				return callbackErr
			}
			return nil
		})
		if !errors.Is(err, callbackErr) {
			t.Fatalf("error = %v, want wrapped callback error", err)
		}
		if !strings.Contains(err.Error(), "index 3") {
			t.Fatalf("error = %v, want failing slot index", err)
		}
		if want := []uint32{2, 3}; !slices.Equal(iterations, want) {
			t.Fatalf("iterations = %v, want %v", iterations, want)
		}
	})
}

func TestRoutingMatcherBuilderRejectsSkipWhileNoaliveOnBuiltins(t *testing.T) {
	outboundName2ID := map[string]uint8{
		consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
		consts.OutboundBlock.String():  uint8(consts.OutboundBlock),
	}

	for _, outboundName := range []string{consts.OutboundDirect.String(), consts.OutboundBlock.String()} {
		t.Run(outboundName, func(t *testing.T) {
			rules := []*config_parser.RoutingRule{{
				AndFunctions: []*config_parser.Function{{
					Name:   consts.Function_DestPort,
					Params: []*config_parser.Param{{Val: "80"}},
				}},
				Outbound: config_parser.Function{
					Name:   outboundName,
					Params: []*config_parser.Param{{Val: consts.OutboundParam_SkipWhileNoalive}},
				},
			}}

			_, err := NewRoutingMatcherBuilder(rules, outboundName2ID, nil, consts.OutboundDirect.String(), nil)
			if err == nil {
				t.Fatal("expected configuration error")
			}
			if !strings.Contains(err.Error(), "skip_while_noalive cannot be used on outbound "+outboundName) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRoutingMatcherBuilderCriticalOutbounds(t *testing.T) {
	const (
		criticalID = uint8(consts.OutboundUserDefinedMin) + iota
		skipOnlyID
		mixedID
		unusedID
		fallbackID
	)
	rule := func(port, outbound string, skip bool) *config_parser.RoutingRule {
		var params []*config_parser.Param
		if skip {
			params = []*config_parser.Param{{Val: consts.OutboundParam_SkipWhileNoalive}}
		}
		return &config_parser.RoutingRule{
			AndFunctions: []*config_parser.Function{{
				Name:   consts.Function_DestPort,
				Params: []*config_parser.Param{{Val: port}},
			}},
			Outbound: config_parser.Function{Name: outbound, Params: params},
		}
	}

	builder, err := NewRoutingMatcherBuilder(
		[]*config_parser.RoutingRule{
			rule("80", "critical", false),
			rule("81", "skip-only", true),
			rule("82", "mixed", true),
			rule("83", "mixed", false),
		},
		map[string]uint8{
			"critical":  criticalID,
			"skip-only": skipOnlyID,
			"mixed":     mixedID,
			"unused":    unusedID,
			"fallback":  fallbackID,
		},
		nil,
		"fallback",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	critical := builder.criticalOutbounds(int(fallbackID) + 1)
	tests := []struct {
		name string
		id   uint8
		want bool
	}{
		{name: "ordinary rule", id: criticalID, want: true},
		{name: "skip-only rules", id: skipOnlyID},
		{name: "mixed rules", id: mixedID, want: true},
		{name: "unreferenced", id: unusedID},
		{name: "fallback", id: fallbackID, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := critical[tt.id]; got != tt.want {
				t.Fatalf("criticalOutbounds()[%d] = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}
