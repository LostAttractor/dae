// SPDX-License-Identifier: AGPL-3.0-only

package pluginctx

import "context"

type idsKey struct{}
type ids struct{ connection, request string }

func IDs(ctx context.Context) (string, string) {
	v, _ := ctx.Value(idsKey{}).(ids)
	return v.connection, v.request
}

func WithIDs(ctx context.Context, connection, request string) context.Context {
	return context.WithValue(ctx, idsKey{}, ids{connection: connection, request: request})
}
