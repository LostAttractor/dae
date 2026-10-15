// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

func (e *Engine) rewriteResponseBody(r *http.Response) error {
	if r.Request == nil || r.Request.URL == nil || r.Body == nil || !responseHasBody(r.Request.Method, r.StatusCode) {
		return nil
	}
	body, err := e.rewriteBody("http-response", r.Request, &r.Body, r.Header, r.ContentLength, nil)
	defer body.Close()
	if body != nil {
		plugin.SetResponseBody(r, body)
	}
	return err
}

func (e *Engine) rewriteRequestBody(exchange *plugin.Exchange) error {
	r := exchange.Request
	body, err := e.rewriteBody("http-request", r, &r.Body, r.Header, r.ContentLength, exchange.SetReadDeadline)
	defer body.Close()
	if body != nil {
		plugin.SetRequestBody(r, body)
	}
	return err
}

// Rewrites share one body snapshot and budget. Failed expressions keep the
// preceding value; response overflow replays the original, request overflow fails.
func (e *Engine) rewriteBody(kind string, request *http.Request, source *io.ReadCloser, header http.Header, length int64, setReadDeadline func(time.Time) error) (*membuffer.View, error) {
	type matchedBodyRewrite struct {
		rule   BodyRewrite
		module string
		index  int
	}
	var matches []matchedBodyRewrite
	for _, module := range e.options.Modules {
		for i, rule := range module.BodyRewrites {
			if rule.Type == kind && rule.Match(request.URL.String()) {
				matches = append(matches, matchedBodyRewrite{rule, module.Name, i + 1})
				e.traceRequest(request, "body_rewrite_match", "module", module.Name, "rule", i+1, "phase", kind)
				e.metrics.match("body_rewrite")
			}
		}
	}
	if len(matches) == 0 {
		return nil, nil
	}
	isRequest := kind == "http-request"
	if isRequest && (len(request.TransferEncoding) != 0 || strings.EqualFold(header.Get("Expect"), "100-continue")) {
		e.traceRequest(request, "body_rewrite_skip", "reason", "request_framing")
		return nil, nil
	}
	limit := e.options.MaxBodySize
	if length > limit {
		if isRequest {
			return nil, membuffer.ErrTooLarge
		}
		e.metrics.skip("body_rewrite", "body_limit")
		e.traceRequest(request, "body_rewrite_skip", "reason", "body_limit")
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(request.Context(), e.options.ScriptTimeout)
	defer cancel()
	release, err := e.acquire(ctx, "body_rewrite")
	if err != nil {
		e.metrics.skip("body_rewrite", traceErrorReason(err))
		e.traceRequest(request, "body_rewrite_skip", "reason", traceErrorReason(err))
		e.logRequest(request, "Surge Body Rewrite skipped while waiting for execution slot", err)
		return nil, nil
	}
	defer release()
	if setReadDeadline != nil {
		deadline, _ := ctx.Deadline()
		_ = setReadDeadline(deadline)
		defer setReadDeadline(time.Time{})
	}

	original := *source
	stop := context.AfterFunc(ctx, func() {
		if original != nil {
			_ = original.Close()
		}
	})
	raw, err := plugin.SnapshotBody(source, limit, e.options.BodyMemory)
	stop()
	if err != nil {
		replay := errors.Is(err, membuffer.ErrBudgetExhausted) || !isRequest && errors.Is(err, membuffer.ErrTooLarge)
		if ctx.Err() != nil {
			err, replay = ctx.Err(), false
		}
		if !replay {
			e.metrics.skip("body_rewrite", "read_failed")
			e.traceRequest(request, "body_rewrite_skip", "reason", "read_failed")
			return nil, err
		}
		e.metrics.skip("body_rewrite", traceErrorReason(err))
		e.traceRequest(request, "body_rewrite_skip", "reason", traceErrorReason(err))
		e.logRequest(request, "Surge Body Rewrite skipped; forwarding original body", err)
		return nil, nil
	}
	body, err := decodeBodyView(ctx, raw, header.Get("Content-Encoding"), limit, e.options.BodyMemory)
	if err != nil {
		if err := request.Context().Err(); err != nil {
			return nil, err
		}
		if isRequest && errors.Is(err, membuffer.ErrTooLarge) {
			return nil, err
		}
		reason := "decode_failed"
		if errors.Is(err, membuffer.ErrTooLarge) || errors.Is(err, membuffer.ErrBudgetExhausted) || errors.Is(err, context.DeadlineExceeded) {
			reason = traceErrorReason(err)
		}
		e.metrics.skip("body_rewrite", reason)
		e.traceRequest(request, "body_rewrite_skip", "reason", reason)
		e.logRequest(request, "Surge Body Rewrite skipped; forwarding original body", err)
		return nil, nil
	}
	decoded := body
	defer func() {
		if body != decoded {
			body.Close()
		}
	}()
	defer decoded.Close()
	for _, match := range matches {
		tracing := e.tracing()
		var started time.Time
		if tracing {
			started = time.Now()
		}
		output, err := match.rule.Apply(ctx, body.Bytes(), limit, e.options.BodyMemory)
		if err != nil {
			e.metrics.skip("body_rewrite", traceErrorReason(err))
			if tracing {
				e.traceRequest(request, "body_rewrite_end", "module", match.module, "rule", match.index, "outcome", "failed", "reason", traceErrorReason(err), "elapsed_ms", time.Since(started).Milliseconds())
			}
			e.logRequest(request, fmt.Sprintf("Surge Body Rewrite module=%q rule=%d failed; keeping previous body", match.module, match.index), err)
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if tracing {
			outcome := "unchanged"
			if output != nil && !bytes.Equal(output.Bytes(), body.Bytes()) {
				outcome = "modified"
			}
			e.traceRequest(request, "body_rewrite_end", "module", match.module, "rule", match.index, "outcome", outcome, "elapsed_ms", time.Since(started).Milliseconds())
		}
		if output != nil {
			if body != decoded {
				body.Close()
			}
			body = output
		}
	}
	if bytes.Equal(body.Bytes(), decoded.Bytes()) {
		return nil, nil
	}
	return body.Clone(), nil
}
