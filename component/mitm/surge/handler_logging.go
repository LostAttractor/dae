// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/mitm/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
	log "github.com/sirupsen/logrus"
)

func (e *Engine) tracing() bool {
	return e.options.Logger != nil && e.options.Logger.Logger.IsLevelEnabled(log.TraceLevel)
}

// Automatic traces include identity and hostname, never request URLs or bodies.
func (e *Engine) traceRequest(r *http.Request, event string, fields ...any) {
	if !e.tracing() {
		return
	}
	connection, request := plugin.IDs(r.Context())
	data := log.Fields{"event": event, "method": r.Method, "connection_id": connection, "request_id": request}
	if r.URL != nil {
		data["host"] = r.URL.Hostname()
	}
	for i := 0; i < len(fields); i += 2 {
		value := fmt.Sprint(fields[i+1])
		if len(value) > 512 {
			value = value[:512] + "..."
		}
		data[fields[i].(string)] = value
	}
	e.options.Logger.WithFields(data).Trace("Surge request")
}

func (e *Engine) logRequest(r *http.Request, message string, err error) {
	if e.options.Logger == nil || r.Context().Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, errScriptAbort) {
		return
	}
	connectionID, requestID := plugin.IDs(r.Context())
	e.options.Logger.WithFields(log.Fields{"request_id": requestID, "connection_id": connectionID}).WithError(resource.RedactError(err)).Warn(message)
}

// Errors may contain script-controlled body/URL values. Only stable categories
// are copied into the automatic trace; detailed existing warnings remain intact.
func traceErrorReason(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, membuffer.ErrBudgetExhausted):
		return "buffer_memory_limit"
	case errors.Is(err, membuffer.ErrTooLarge):
		return "body_limit"
	case errors.Is(err, ErrMissingDone):
		return "missing_done"
	case errors.Is(err, errScriptAbort), errors.Is(err, plugin.ErrAbort):
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
	e.traceRequest(r, "script_match", "script", s.Name, "phase", s.Type)
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
