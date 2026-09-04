/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"context"
	"errors"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestDatReaderOptimizerHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rules := []*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{{Params: []*config_parser.Param{{Val: "example.com"}}}},
	}}
	_, err := NewDatReaderOptimizer(ctx, nil).Optimize(rules)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Optimize error = %v, want context cancellation", err)
	}
}
