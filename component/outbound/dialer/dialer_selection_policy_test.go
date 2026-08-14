/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func fixedPolicy(index string) config.Group {
	return config.Group{Policy: []*config_parser.Function{{
		Name: "fixed",
		Params: []*config_parser.Param{{
			Val: index,
		}},
	}}}
}

func TestFixedPolicyRejectsNegativeIndex(t *testing.T) {
	group := fixedPolicy("-1")
	if _, err := NewDialerSelectionPolicyFromGroupParam(&group); err == nil {
		t.Fatal("fixed(-1) unexpectedly succeeded")
	}
	group = fixedPolicy("0")
	policy, err := NewDialerSelectionPolicyFromGroupParam(&group)
	if err != nil || policy.FixedIndex != 0 {
		t.Fatalf("fixed(0) = %+v, %v", policy, err)
	}
}
