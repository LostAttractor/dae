// SPDX-License-Identifier: AGPL-3.0-only

package pluginctx

import "context"

type policyKey struct{}

func WithHTTPPolicy(ctx context.Context, policy string) context.Context {
	return context.WithValue(ctx, policyKey{}, policy)
}

func HTTPPolicy(ctx context.Context) string {
	policy, _ := ctx.Value(policyKey{}).(string)
	return policy
}
