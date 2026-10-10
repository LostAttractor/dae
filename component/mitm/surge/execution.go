// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"time"

	"github.com/daeuniverse/dae/common/resource"
)

func (e *Engine) acquire(ctx context.Context, kind string) (func(), error) {
	defer func(started time.Time) {
		e.metrics.wait.WithLabelValues(kind).Observe(time.Since(started).Seconds())
	}(time.Now())
	select {
	case e.slots <- struct{}{}:
		return func() { <-e.slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (e *Engine) scriptTimeout(s *Script) time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return e.options.ScriptTimeout
}

// Every script entry point uses the same declared metadata, body limits and
// source refresh behavior. Callers supply only their event-specific input.
func (e *Engine) runInvocation(ctx context.Context, module *Module, script *Script, invocation Invocation) (*Result, error) {
	defer func(started time.Time) {
		e.metrics.duration.WithLabelValues(script.Type).Observe(time.Since(started).Seconds())
	}(time.Now())
	invocation.ModuleName = module.Name
	invocation.ScriptName, invocation.ScriptType, invocation.ScriptPath = script.Name, script.Type, script.Path
	invocation.Argument, invocation.ArgumentSet = script.Argument, script.ArgumentSet
	invocation.BinaryBodyMode, invocation.FullHeaderMode = script.BinaryBodyMode, script.FullHeaderMode
	invocation.CronExp, invocation.Timeout = script.CronExp, e.scriptTimeout(script)
	invocation.BodyMemory, invocation.BodyLimit = e.options.BodyMemory, e.options.MaxBodySize
	source := script.Source
	if script.Debug {
		path := resource.Source{Location: script.Path}
		if !path.Remote() {
			result, err := resource.Read(ctx, nil, path, resource.ReadOptions{MaxBytes: MaxScriptBytes})
			if err != nil {
				return nil, err
			}
			source = string(result.Data)
		}
	}
	return e.options.Runtime.Run(ctx, source, invocation)
}
