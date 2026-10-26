// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"

	"github.com/daeuniverse/dae/component/plugin/codec"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

func decodeBodyView(ctx context.Context, view *membuffer.View, encoding string, limit int64) (*membuffer.View, error) {
	c, err := codec.New(ctx, view.Budget(), codec.Limits{Wire: limit, Decoded: limit})
	if err != nil {
		view.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		view.Close()
		return nil, err
	}
	if len(view.Bytes()) == 0 {
		encoding = ""
	}
	return c.HTTPView(view, encoding)
}
