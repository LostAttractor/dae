// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/daeuniverse/dae/component/mitm/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

// rewriteResponseBody runs matching rules before the response script. Invalid
// JSON, failed jq filters, and size limits leave the current body unchanged;
// network read failures are returned because a complete body cannot be replayed.
func (e *Engine) rewriteResponseBody(r *http.Response) error {
	if r.Request == nil || r.Request.URL == nil || r.Body == nil || !responseHasBody(r.Request.Method, r.StatusCode) {
		return nil
	}
	type matchedBodyRewrite struct {
		rule   BodyRewrite
		module string
		index  int
	}
	var matches []matchedBodyRewrite
	for _, module := range e.options.Modules {
		for i, rule := range module.BodyRewrites {
			if rule.Match(r.Request.URL.String()) {
				matches = append(matches, matchedBodyRewrite{rule, module.Name, i + 1})
				e.traceRequest(r.Request, "body_rewrite_match", "module", module.Name, "rule", i+1)
			}
		}
	}
	if len(matches) == 0 {
		return nil
	}
	limit := e.options.MaxBodySize
	if r.ContentLength > limit {
		e.traceRequest(r.Request, "body_rewrite_skip", "reason", "body_limit")
		e.logRequest(r.Request, "Surge Body Rewrite skipped; increase max_body_size to process this response", membuffer.ErrTooLarge)
		return nil
	}
	ctx, cancel := context.WithTimeout(r.Request.Context(), e.options.ScriptTimeout)
	defer cancel()
	release, err := e.acquire(ctx)
	if err != nil {
		e.traceRequest(r.Request, "body_rewrite_skip", "reason", traceErrorReason(err))
		e.logRequest(r.Request, "Surge Body Rewrite skipped while waiting for execution slot", err)
		return nil
	}
	defer release()

	original := r.Body
	stop := context.AfterFunc(ctx, func() { _ = original.Close() })
	raw, err := plugin.SnapshotBody(&r.Body, limit, e.options.BodyMemory)
	stop()
	if (err != nil && !errors.Is(err, membuffer.ErrTooLarge) && !errors.Is(err, membuffer.ErrBudgetExhausted)) || ctx.Err() != nil {
		e.traceRequest(r.Request, "body_rewrite_skip", "reason", "read_failed")
		raw.Close()
		_ = r.Body.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if err != nil {
		e.traceRequest(r.Request, "body_rewrite_skip", "reason", traceErrorReason(err))
		e.logRequest(r.Request, "Surge Body Rewrite skipped; forwarding original response", err)
		return nil
	}
	body, err := decodeBodyView(raw, r.Header.Get("Content-Encoding"), limit, e.options.BodyMemory)
	if err != nil {
		e.traceRequest(r.Request, "body_rewrite_skip", "reason", "decode_failed")
		e.logRequest(r.Request, "Surge Body Rewrite skipped; forwarding original response", err)
		return nil
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
			if tracing {
				e.traceRequest(r.Request, "body_rewrite_end", "module", match.module, "rule", match.index, "outcome", "failed", "reason", traceErrorReason(err), "elapsed_ms", time.Since(started).Milliseconds())
			}
			e.logRequest(r.Request, fmt.Sprintf("Surge Body Rewrite module=%q rule=%d failed; keeping previous body", match.module, match.index), err)
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if tracing {
			outcome := "unchanged"
			if len(output.Bytes()) != 0 && !bytes.Equal(output.Bytes(), body.Bytes()) {
				outcome = "modified"
			}
			e.traceRequest(r.Request, "body_rewrite_end", "module", match.module, "rule", match.index, "outcome", outcome, "elapsed_ms", time.Since(started).Milliseconds())
		}
		if len(output.Bytes()) != 0 {
			if body != decoded {
				body.Close()
			}
			body = output
		} else {
			output.Close()
		}
	}
	if bytes.Equal(body.Bytes(), decoded.Bytes()) {
		return nil
	}
	plugin.SetResponseBody(r, body)
	return nil
}
