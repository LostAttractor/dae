// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
	"golang.org/x/net/http/httpguts"
)

var errScriptAbort = errors.New("request aborted by script")

// Only raised after SnapshotBody has captured a complete replay. A script's
// processing deadline can then skip the script without losing upstream bytes.
var errBufferedBodyTimeout = errors.New("buffered script body processing timed out")

func replayableBodyTimeout(err error, parent context.Context) bool {
	return errors.Is(err, errBufferedBodyTimeout) && parent.Err() == nil
}

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

func (e *Engine) matchScript(kind string, request *http.Request) (*Module, *Script) {
	urls := []string{request.URL.String()}
	if request.Host != "" && request.Host != request.URL.Host {
		alias := request.URL.Clone()
		alias.Host = request.Host
		urls = append(urls, alias.String())
	}
	if request.TLS != nil && request.TLS.ServerName != "" {
		alias := request.URL.Clone()
		alias.Host = request.TLS.ServerName
		if port := request.URL.Port(); port != "" {
			alias.Host = net.JoinHostPort(alias.Host, port)
		}
		urls = append(urls, alias.String())
	}
	for _, m := range e.options.Modules {
		for i := range m.Scripts {
			s := &m.Scripts[i]
			if s.Type != kind {
				continue
			}
			for _, rawURL := range urls {
				if s.Match(rawURL) {
					return m, s
				}
			}
		}
	}
	return nil, nil
}

func (e *Engine) scriptTimeout(s *Script) time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return e.options.ScriptTimeout
}

func (e *Engine) runScript(ctx context.Context, module *Module, s *Script, req, resp *Message, client *http.Client) (*Result, error) {
	return e.runInvocation(ctx, s.Source, Invocation{
		ModuleName: module.Name,
		Request:    req, Response: resp, ScriptName: s.Name, ScriptType: s.Type,
		Argument: s.Argument, BinaryBodyMode: s.BinaryBodyMode,
		ArgumentSet: s.ArgumentSet, ScriptPath: s.Path, FullHeaderMode: s.FullHeaderMode,
		Timeout: e.scriptTimeout(s), HTTPClient: client,
		BodyMemory: e.options.BodyMemory, BodyLimit: e.options.MaxBodySize,
	})
}

func (e *Engine) processRequest(exchange *plugin.Exchange) (response *http.Response, err error) {
	r, client, setReadDeadline := exchange.Request, exchange.Client, exchange.SetReadDeadline
	r.Header.Set("Host", r.Host)
	if err := e.rewriteHeaders("http-request", r, r.Header); err != nil {
		return nil, err
	}
	if host := r.Header.Get("Host"); host != "" {
		r.Host = host
		r.Header.Del("Host")
	}
	if response, err := e.rewriteURL(r); response != nil || err != nil {
		return response, err
	}
	if response, err := e.mapLocal(r); response != nil || err != nil {
		return response, err
	}
	module, s := e.matchScript("http-request", r)
	if s == nil {
		e.traceRequest(r, "script_skip", "phase", "http-request", "reason", "no_match")
		return nil, nil
	}
	execution := e.traceScript(r, s)
	defer func() { execution.finish(err) }()
	ctx, cancel := context.WithTimeout(r.Context(), e.scriptTimeout(s))
	defer cancel()
	// Closing a server request body cannot interrupt an in-progress read.
	// Handler clears this deadline before forwarding the remaining body.
	deadline, _ := ctx.Deadline()
	if setReadDeadline != nil {
		_ = setReadDeadline(deadline)
	}
	release, err := e.acquire(ctx, "http-request")
	if err != nil {
		return nil, err
	}
	defer release()
	message := requestMessage(r)
	canReplaceBody := len(r.TransferEncoding) == 0 && !strings.EqualFold(r.Header.Get("Expect"), "100-continue")
	if s.RequiresBody && r.Body != nil {
		body, err := e.bufferBody(ctx, &r.Body, r.Header, s)
		if errors.Is(err, membuffer.ErrBudgetExhausted) || replayableBodyTimeout(err, r.Context()) {
			execution.outcome, execution.reason = "skipped", traceErrorReason(err)
			e.logRequest(r, fmt.Sprintf("Surge script %q skipped; forwarding original request", s.Name), err)
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		defer body.Close()
		message.Body = body.Bytes()
	}
	execution.start()
	result, err := e.runScript(ctx, module, s, message, nil, client)
	if err != nil {
		execution.failed(err)
		e.logRequest(r, fmt.Sprintf("Surge script %q failed; forwarding original request", s.Name), err)
		return nil, nil
	}
	defer result.Close()
	if result.Abort {
		return nil, errScriptAbort
	}
	if result.Response != nil {
		execution.outcome = "synthetic"
		return responseFromResult(r, result.Response)
	}
	if result.URL != nil {
		if err := replaceURL(r, *result.URL); err != nil {
			return nil, err
		}
		execution.outcome = "success"
	}
	if result.Headers != nil {
		headers, err := resultHeaders(result.Headers)
		if err != nil {
			return nil, err
		}
		r.Header = headers
		if host := headers.Get("Host"); host != "" {
			r.Host = host
			headers.Del("Host")
		}
		// Go owns framing. Script-supplied values cannot create request smuggling.
		r.Header.Del("Content-Length")
		r.Header.Del("Transfer-Encoding")
		execution.outcome = "success"
	}
	if s.RequiresBody && canReplaceBody && result.Body != nil {
		plugin.SetRequestBody(exchange.Request, result.Body)
		execution.outcome = "success"
	}
	return nil, nil
}

func (e *Engine) processResponse(r *http.Response, client *http.Client) (err error) {
	if err := e.rewriteHeaders("http-response", r.Request, r.Header); err != nil {
		return err
	}
	if err := e.rewriteResponseBody(r); err != nil {
		return err
	}
	module, s := e.matchScript("http-response", r.Request)
	if s == nil || r.StatusCode == http.StatusSwitchingProtocols {
		reason := "no_match"
		if r.StatusCode == http.StatusSwitchingProtocols {
			reason = "protocol_upgrade"
		}
		e.traceRequest(r.Request, "script_skip", "phase", "http-response", "reason", reason)
		return nil
	}
	execution := e.traceScript(r.Request, s)
	defer func() { execution.finish(err) }()
	ctx, cancel := context.WithTimeout(r.Request.Context(), e.scriptTimeout(s))
	defer cancel()
	release, err := e.acquire(ctx, "http-response")
	if err != nil {
		return err
	}
	defer release()
	message := &Message{Status: r.StatusCode, Headers: r.Header}
	hasBody := responseHasBody(r.Request.Method, r.StatusCode)
	if s.RequiresBody && hasBody && r.Body != nil {
		body, err := e.bufferBody(ctx, &r.Body, r.Header, s)
		if errors.Is(err, membuffer.ErrTooLarge) || errors.Is(err, membuffer.ErrBudgetExhausted) || replayableBodyTimeout(err, r.Request.Context()) {
			execution.outcome, execution.reason = "skipped", traceErrorReason(err)
			e.logRequest(r.Request, fmt.Sprintf("Surge script %q skipped; forwarding original response", s.Name), err)
			return nil
		}
		if err != nil {
			return err
		}
		defer body.Close()
		message.Body = body.Bytes()
	}
	// net/http populates trailers after the response body reaches EOF.
	if len(r.Trailer) != 0 {
		message.Trailers = r.Trailer
	}
	execution.start()
	result, err := e.runScript(ctx, module, s, requestMessage(r.Request), message, client)
	if err != nil {
		execution.failed(err)
		e.logRequest(r.Request, fmt.Sprintf("Surge script %q failed; forwarding original response", s.Name), err)
		return nil
	}
	defer result.Close()
	if result.Abort || !s.RequiresBody && result.Body != nil {
		return errScriptAbort
	}
	if result.Headers != nil {
		headers, err := resultHeaders(result.Headers)
		if err != nil {
			return err
		}
		r.Header = headers
		r.Header.Del("Content-Length")
		r.Header.Del("Transfer-Encoding")
		removeHopHeaders(r.Header)
		execution.outcome = "success"
	}
	if result.Status != 0 {
		if result.Status < 200 || result.Status > 599 {
			return fmt.Errorf("invalid script response status %d", result.Status)
		}
		r.StatusCode = result.Status
		r.Status = fmt.Sprintf("%d %s", result.Status, http.StatusText(result.Status))
		execution.outcome = "success"
	}
	if result.Trailers != nil {
		trailers, err := resultTrailers(result.Trailers)
		if err != nil {
			return err
		}
		r.Trailer = trailers
		execution.outcome = "success"
	}
	if s.RequiresBody && hasBody && result.Body != nil {
		plugin.SetResponseBody(r, result.Body)
		execution.outcome = "success"
	}
	if !responseHasBody(r.Request.Method, r.StatusCode) {
		_ = r.Body.Close()
		r.Body = http.NoBody
		r.TransferEncoding = nil
		if r.StatusCode == http.StatusNoContent {
			r.ContentLength = 0
			r.Header.Del("Content-Length")
		}
	}
	return nil
}

func responseHasBody(method string, status int) bool {
	return method != http.MethodHead && status >= 200 && status != http.StatusNoContent && status != http.StatusNotModified
}

// URL rewrites stop at the first match, including an in-place URL change.
func (e *Engine) rewriteURL(r *http.Request) (*http.Response, error) {
	for _, module := range e.options.Modules {
		for i, rewrite := range module.URLRewrites {
			if !rewrite.Match(r.URL.String()) {
				continue
			}
			e.traceRequest(r, "url_rewrite_match", "module", module.Name, "rule", i+1, "action", rewrite.Type)
			e.metrics.match("url_rewrite")
			target, err := rewrite.Rewrite(r.URL.String())
			if err != nil {
				return nil, err
			}
			switch rewrite.Type {
			case "reject":
				return syntheticResponse(r, http.StatusForbidden, nil, nil), nil
			case "302", "307":
				code, _ := strconv.Atoi(rewrite.Type)
				return syntheticResponse(r, code, http.Header{"Location": {target}}, nil), nil
			case "header":
				if err := replaceURL(r, target); err != nil {
					return nil, err
				}
				r.Host = r.URL.Host
				return nil, nil
			default:
				return nil, fmt.Errorf("unsupported URL rewrite type %q", rewrite.Type)
			}
		}
	}
	return nil, nil
}

func (e *Engine) rewriteHeaders(kind string, request *http.Request, headers http.Header) error {
	for _, m := range e.options.Modules {
		for i, rewrite := range m.HeaderRewrites {
			if rewrite.Type == kind && rewrite.Match(request.URL.String()) {
				e.traceRequest(request, "header_rewrite_match", "module", m.Name, "rule", i+1, "phase", kind, "action", rewrite.Action)
				e.metrics.match("header_rewrite")
				if err := rewrite.Apply(headers); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (e *Engine) bufferBody(ctx context.Context, body *io.ReadCloser, header http.Header, s *Script) (*membuffer.View, error) {
	limit := e.options.MaxBodySize
	if s.MaxSize > 0 && s.MaxSize < limit {
		limit = s.MaxSize
	}
	original := *body
	stop := context.AfterFunc(ctx, func() { _ = original.Close() })
	// Keep the unread tail attached on overflow so response scripts can skip
	// buffering without truncating the upstream response. Ownership stays with
	// the exchange until the body is forwarded or replaced.
	raw, err := plugin.SnapshotBody(body, limit, e.options.BodyMemory)
	stop()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	decoded, err := decodeBodyView(ctx, raw, header.Get("Content-Encoding"), limit, e.options.BodyMemory)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, fmt.Errorf("%w: %w", errBufferedBodyTimeout, err)
	}
	return decoded, err
}

func requestMessage(r *http.Request) *Message {
	headers := r.Header.Clone()
	headers.Set("Host", r.Host)
	_, id := plugin.IDs(r.Context())
	return &Message{URL: r.URL.String(), Method: r.Method, Headers: headers, ID: id}
}

func resultHeaders(values http.Header) (http.Header, error) {
	headers := make(http.Header, len(values))
	for k, entries := range values {
		if !httpguts.ValidHeaderFieldName(k) {
			return nil, fmt.Errorf("invalid script header %q", k)
		}
		for _, v := range entries {
			if !httpguts.ValidHeaderFieldValue(v) {
				return nil, fmt.Errorf("invalid script header %q", k)
			}
			headers.Add(k, v)
		}
	}
	return headers, nil
}

func resultTrailers(values http.Header) (http.Header, error) {
	headers, err := resultHeaders(values)
	if err != nil {
		return nil, err
	}
	for key := range headers {
		if !httpguts.ValidTrailerHeader(key) {
			return nil, fmt.Errorf("invalid script trailer %q", key)
		}
	}
	return headers, nil
}

func replaceURL(r *http.Request, target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("script URL must be an absolute HTTP(S) URL without credentials or fragment")
	}
	r.URL = u
	return nil
}

func syntheticResponse(request *http.Request, status int, header http.Header, body []byte) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	removeHopHeaders(header)
	header.Del("Content-Length")
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: request}
}

func responseFromResult(request *http.Request, result *Result) (*http.Response, error) {
	status := result.Status
	if status == 0 {
		status = http.StatusOK
	}
	if status < 200 || status > 599 {
		return nil, fmt.Errorf("invalid synthetic response status %d", status)
	}
	header, err := resultHeaders(result.Headers)
	if err != nil {
		return nil, err
	}
	var body []byte
	if result.Body != nil {
		body = result.Body.Bytes()
	}
	response := syntheticResponse(request, status, header, body)
	if result.Body != nil {
		response.Body = result.Body.Open()
	}
	if result.Trailers != nil {
		response.Trailer, err = resultTrailers(result.Trailers)
		if err != nil {
			_ = response.Body.Close()
			return nil, err
		}
	}
	return response, nil
}

func removeHopHeaders(header http.Header) {
	for name := range strings.SplitSeq(header.Get("Connection"), ",") {
		header.Del(strings.TrimSpace(name))
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Alt-Svc"} {
		header.Del(name)
	}
}
