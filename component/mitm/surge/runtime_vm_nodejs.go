//go:build surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"

	"github.com/daeuniverse/dae/component/mitm/surge/internal/nodejs"
)

const compiledJSRuntime = "nodejs"

type runtimeBackend struct{ pool *nodejs.Pool }

func newRuntimeBackend(ctx context.Context, opts RuntimeOptions) (*runtimeBackend, error) {
	pool, err := nodejs.NewPool(ctx, opts.NodePath, opts.MemoryLimit, opts.NodeWorkers, runtimeBootstrapSource)
	if err != nil {
		return nil, err
	}
	return &runtimeBackend{pool: pool}, nil
}

func (b *runtimeBackend) newVM(ctx context.Context) (scriptVM, error) { return b.pool.Acquire(ctx) }
func (b *runtimeBackend) Close()                                      { b.pool.Close() }
