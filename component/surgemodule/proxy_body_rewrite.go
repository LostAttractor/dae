// SPDX-License-Identifier: AGPL-3.0-only

package surgemodule

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
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
		e.logRequest(r.Request, "surge Body Rewrite skipped: "+errBodyTooLarge.Error())
		return nil
	}
	ctx, cancel := context.WithTimeout(r.Request.Context(), e.options.ScriptTimeout)
	defer cancel()
	release, err := e.acquire(ctx)
	if err != nil {
		e.traceRequest(r.Request, "body_rewrite_skip", "reason", traceErrorReason(err))
		e.logRequest(r.Request, "surge Body Rewrite skipped while waiting for execution slot: "+err.Error())
		return nil
	}
	defer release()

	original := r.Body
	stop := context.AfterFunc(ctx, func() { _ = original.Close() })
	raw, err := io.ReadAll(io.LimitReader(original, limit+1))
	stop()
	if err != nil || ctx.Err() != nil {
		e.traceRequest(r.Request, "body_rewrite_skip", "reason", "read_failed")
		_ = original.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if int64(len(raw)) > limit {
		// Retain the bounded prefix and stream the unread remainder. Do not
		// truncate oversized/chunked responses or close their upstream body.
		r.Body = &bodyRewriteReplay{Reader: io.MultiReader(bytes.NewReader(raw), original), Closer: original}
		e.traceRequest(r.Request, "body_rewrite_skip", "reason", "body_limit")
		e.logRequest(r.Request, "surge Body Rewrite skipped: "+errBodyTooLarge.Error())
		return nil
	}
	_ = original.Close()
	r.Body = io.NopCloser(bytes.NewReader(raw))
	body, err := decodeBody(raw, r.Header.Get("Content-Encoding"), limit)
	if err != nil {
		e.traceRequest(r.Request, "body_rewrite_skip", "reason", "decode_failed")
		e.logRequest(r.Request, "surge Body Rewrite skipped; forwarding original response: "+err.Error())
		return nil
	}
	decoded := body
	for _, match := range matches {
		tracing := e.tracing()
		var started time.Time
		if tracing {
			started = time.Now()
		}
		output, err := match.rule.Apply(ctx, body, limit)
		if err != nil {
			if tracing {
				e.traceRequest(r.Request, "body_rewrite_end", "module", match.module, "rule", match.index, "outcome", "failed", "reason", traceErrorReason(err), "elapsed_ms", time.Since(started).Milliseconds())
			}
			e.logRequest(r.Request, fmt.Sprintf("surge Body Rewrite http-response-jq %s failed; keeping previous body: %v", match.rule.Pattern, err))
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if tracing {
			outcome := "unchanged"
			if output != nil && !bytes.Equal(output, body) {
				outcome = "modified"
			}
			e.traceRequest(r.Request, "body_rewrite_end", "module", match.module, "rule", match.index, "outcome", outcome, "elapsed_ms", time.Since(started).Milliseconds())
		}
		if output != nil {
			body = output
		}
	}
	if bytes.Equal(body, decoded) {
		return nil
	}
	replaceResponseBody(r, body)
	removeBodyMetadata(r.Trailer)
	r.Header.Del("Trailer")
	return nil
}

type bodyRewriteReplay struct {
	io.Reader
	io.Closer
}
