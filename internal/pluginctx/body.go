// SPDX-License-Identifier: AGPL-3.0-only

package pluginctx

import (
	"context"
	"time"
)

type snapshotKey struct{}

func WithSnapshotObserver(ctx context.Context, observe func(time.Duration)) context.Context {
	return context.WithValue(ctx, snapshotKey{}, observe)
}

func SnapshotObserver(ctx context.Context) func(time.Duration) {
	observe, _ := ctx.Value(snapshotKey{}).(func(time.Duration))
	return observe
}
