// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"cmp"
	"testing"
	"time"
)

// Exercise the same initialization invariants as production, including metrics.
func newTestEngine(t *testing.T, options EngineOptions) *Engine {
	t.Helper()
	options.BodyMemory = cmp.Or(options.BodyMemory, testBodyMemory)
	options.MaxBodySize = cmp.Or(options.MaxBodySize, 1<<20)
	options.MaxConcurrentScripts = cmp.Or(options.MaxConcurrentScripts, 2)
	options.ScriptTimeout = cmp.Or(options.ScriptTimeout, time.Second)
	engine, err := NewEngine(options)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}
