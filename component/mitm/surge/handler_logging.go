// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/daeuniverse/dae/component/mitm/plugin"
)

func (e *Engine) tracing() bool {
	return e.options.Trace != nil && (e.options.TraceEnabled == nil || e.options.TraceEnabled())
}

// trace emits daemon-owned diagnostics. Values are quoted and bounded; URLs
// contribute only hostname and path, never query, credentials, or fragment.
// Script console output and existing warning messages are separate channels.
func (e *Engine) trace(ctx context.Context, event string, fields ...any) {
	if !e.tracing() {
		return
	}
	var line strings.Builder
	line.WriteString("surge event=")
	line.WriteString(event)
	write := func(key string, value any) {
		text := fmt.Sprint(value)
		if len(text) > 512 {
			text = text[:512] + "..."
		}
		fmt.Fprintf(&line, " %s=%q", key, text)
	}
	connection, request := plugin.IDs(ctx)
	if connection != "" {
		write("connection_id", connection)
	}
	if request != "" {
		write("request_id", request)
	}
	for i := 0; i+1 < len(fields); i += 2 {
		write(fields[i].(string), fields[i+1])
	}
	e.options.Trace(line.String())
}

func (e *Engine) traceRequest(r *http.Request, event string, fields ...any) {
	if !e.tracing() {
		return
	}
	base := []any{"method", r.Method}
	if r.URL != nil {
		base = append(base, "host", r.URL.Hostname(), "path", r.URL.EscapedPath())
	}
	e.trace(r.Context(), event, append(base, fields...)...)
}

func (e *Engine) logRequest(r *http.Request, message string) {
	connectionID, requestID := plugin.IDs(r.Context())
	e.log(fmt.Sprintf("%s request_id=%q connection_id=%q", message, requestID, connectionID))
}

// Errors may contain script-controlled body/URL values. Only stable categories
// are copied into the automatic trace; detailed existing warnings remain intact.
func traceErrorReason(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, errBodyTooLarge):
		return "body_limit"
	case errors.Is(err, ErrMissingDone):
		return "missing_done"
	case errors.Is(err, errScriptAbort):
		return "aborted"
	default:
		return "error"
	}
}

type scriptExecutionLog struct {
	engine   *Engine
	request  *http.Request
	script   *Script
	started  time.Time
	executed bool
	outcome  string
	reason   string
}

func (e *Engine) traceScript(r *http.Request, s *Script) *scriptExecutionLog {
	entry := &scriptExecutionLog{engine: e, request: r, script: s, outcome: "unchanged", started: time.Now()}
	if e.tracing() {
		e.traceRequest(r, "script_match", "script", s.Name, "phase", s.Type)
	}
	return entry
}

func (l *scriptExecutionLog) start() {
	l.executed = true
	l.engine.traceRequest(l.request, "script_start", "script", l.script.Name, "phase", l.script.Type)
}

func (l *scriptExecutionLog) failed(err error) {
	l.outcome, l.reason = "failed", traceErrorReason(err)
}

func (l *scriptExecutionLog) finish(err error) {
	if !l.engine.tracing() {
		return
	}
	if errors.Is(err, errScriptAbort) {
		l.outcome = "abort"
	} else if err != nil {
		l.failed(err)
		if !l.executed {
			l.outcome = "skipped"
		}
	}
	fields := []any{"script", l.script.Name, "phase", l.script.Type, "outcome", l.outcome, "elapsed_ms", time.Since(l.started).Milliseconds()}
	if l.reason != "" {
		fields = append(fields, "reason", l.reason)
	}
	l.engine.traceRequest(l.request, "script_end", fields...)
}
