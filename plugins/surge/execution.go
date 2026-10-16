// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

func (e *Engine) acquire(ctx context.Context, kind string) (func(), error) {
	if slot, _ := ctx.Value(executionSlotKey{}).(*httpExecutionSlot); slot != nil && slot.slots == e.slots && slot.release != nil {
		return func() {}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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

// CPU work shares one admission limit, including matching and decoding. Network
// body reads temporarily surrender the slot; neither network nor queue time is
// charged to a script's execution budget.
type executionSlotKey struct{}

type httpExecutionSlot struct {
	slots   chan struct{}
	kind    string
	release func()
}

func (e *Engine) beginHTTPProcessing(r *http.Request, kind string) (func(*error), error) {
	ctx := withRegexBudget(r.Context())
	release, err := e.acquire(ctx, kind)
	if err != nil {
		return nil, err
	}
	slot := &httpExecutionSlot{slots: e.slots, kind: kind, release: release}
	*r = *r.WithContext(context.WithValue(ctx, executionSlotKey{}, slot))
	return func(result *error) {
		defer func() {
			if slot.release != nil {
				slot.release()
				slot.release = nil
			}
		}()
		defer func() { *r = *r.WithContext(ctx) }()
		if budgetErr := regexBudgetError(r.Context()); budgetErr != nil {
			e.metrics.skip(kind, traceErrorReason(budgetErr))
			*result = budgetErr
		}
	}, nil
}

// snapshotHTTPBody retains the original representation for forwarding. Only
// request cancellation interrupts a network read; execution timeouts begin
// after this function returns. Memory and body-size limits still bound storage.
func (e *Engine) snapshotHTTPBody(ctx context.Context, body *io.ReadCloser, limit int64, setReadDeadline func(time.Time) error) (view *membuffer.View, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if slot, _ := ctx.Value(executionSlotKey{}).(*httpExecutionSlot); slot != nil && slot.slots == e.slots && slot.release != nil {
		slot.release()
		slot.release = nil
		defer func() {
			var admissionErr error
			slot.release, admissionErr = e.acquire(ctx, slot.kind)
			if admissionErr != nil {
				view.Close()
				view, err = nil, admissionErr
			}
		}()
	}
	original := *body
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(closed)
		// Closing an HTTP/1 server body alone cannot interrupt its Read.
		if setReadDeadline != nil {
			_ = setReadDeadline(time.Now())
		}
		if original != nil {
			_ = original.Close()
		}
	})
	view, err = plugin.SnapshotBody(body, limit, e.options.BodyMemory)
	if !stop() {
		<-closed
	}
	if cause := ctx.Err(); cause != nil {
		view.Close()
		return nil, cause
	}
	return view, err
}
