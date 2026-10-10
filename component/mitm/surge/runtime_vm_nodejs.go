//go:build surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"

	"github.com/daeuniverse/dae/api"
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

func (b *runtimeBackend) status() api.SurgeRuntimeStatus {
	s := b.pool.Stats()
	return api.SurgeRuntimeStatus{Backend: compiledJSRuntime, NodeJS: &api.NodeJSRuntimeStatus{
		Active: s.Active, Idle: s.Idle, Limit: s.Limit,
		Started: s.Started, Reused: s.Reused, StartFailures: s.StartFailures,
		IdleReaped: s.IdleReaped, Discarded: s.Discarded,
		RSSBytes: s.RSSBytes, PSSBytes: s.PSSBytes,
		MemorySampledWorkers: s.MemorySampledWorkers, MemorySampledAt: s.MemorySampledAt,
		IdleTimeoutSeconds: s.IdleTimeout.Seconds(),
	}}
}
