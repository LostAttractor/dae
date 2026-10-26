// SPDX-License-Identifier: AGPL-3.0-only

package codec

import (
	"context"
	"errors"
	"math"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

var (
	ErrUnsupported    = errors.New("codec: unsupported encoding")
	ErrBudgetMismatch = errors.New("codec: input uses a different memory budget")
)

type Limits struct {
	Wire, Decoded int64
}

type Codec struct {
	ctx    context.Context
	budget *membuffer.Budget
	limits Limits
}

func New(ctx context.Context, budget *membuffer.Budget, limits Limits) (*Codec, error) {
	if ctx == nil {
		return nil, errors.New("codec: context is required")
	}
	if budget == nil {
		return nil, membuffer.ErrBudgetRequired
	}
	if limits.Wire <= 0 || limits.Decoded <= 0 || limits.Wire >= int64(math.MaxInt) || limits.Decoded >= int64(math.MaxInt) {
		return nil, membuffer.ErrInvalidLimit
	}
	return &Codec{ctx: ctx, budget: budget, limits: limits}, nil
}
