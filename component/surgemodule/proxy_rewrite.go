// SPDX-License-Identifier: AGPL-3.0-only

package surgemodule

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"golang.org/x/net/http/httpguts"
)

var errBodyTooLarge = errors.New("body exceeds configured buffering limit")
var errScriptAbort = errors.New("request aborted by script")

func (e *Engine) acquire(ctx context.Context) (func(), error) {
	select {
	case e.slots <- struct{}{}:
		return func() { <-e.slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (e *Engine) matchScript(kind, rawURL string) *Script {
	for _, m := range e.options.Modules {
		for i := range m.Scripts {
			s := &m.Scripts[i]
			if s.Type == kind && s.Match(rawURL) {
				return s
			}
		}
	}
	return nil
}

func (e *Engine) runScript(ctx context.Context, s *Script, req, resp *Message, client *http.Client) (*Result, error) {
	timeout := e.options.ScriptTimeout
	if s.Timeout > 0 && s.Timeout < timeout {
		timeout = s.Timeout
	}
	return e.options.Runtime.Run(ctx, s.Source, Invocation{
		Request: req, Response: resp, ScriptName: s.Name, ScriptType: s.Type,
		Argument: s.Argument, BinaryBodyMode: s.BinaryBodyMode,
		Timeout: timeout, HTTPClient: client,
	})
}

func (e *Engine) processRequest(r *http.Request, client *http.Client) (response *http.Response, err error) {
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
	s := e.matchScript("http-request", r.URL.String())
	if s == nil {
		e.traceRequest(r, "script_skip", "phase", "http-request", "reason", "no_match")
		return nil, nil
	}
	execution := e.traceScript(r, s)
	defer func() { execution.finish(err) }()
	ctx, cancel := context.WithTimeout(r.Context(), e.options.ScriptTimeout)
	defer cancel()
	release, err := e.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	message := requestMessage(r)
	if s.RequiresBody && r.Body != nil {
		body, err := e.bufferBody(ctx, &r.Body, r.Header, s)
		if err != nil {
			return nil, err
		}
		message.Body = body
	}
	execution.start()
	result, err := e.runScript(ctx, s, message, nil, client)
	if err != nil {
		execution.failed(err)
		e.logRequest(r, fmt.Sprintf("surge script %s failed; forwarding original request: %v", s.Name, err))
		return nil, nil
	}
	if result.Abort {
		return nil, errScriptAbort
	}
	if result.Response != nil {
		execution.outcome = "synthetic"
		return responseFromResult(r, result.Response, e.options.MaxBodySize)
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
	if s.RequiresBody && result.Body != nil {
		if int64(len(*result.Body)) > e.options.MaxBodySize {
			return nil, errBodyTooLarge
		}
		replaceRequestBody(r, *result.Body)
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
	s := e.matchScript("http-response", r.Request.URL.String())
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
	ctx, cancel := context.WithTimeout(r.Request.Context(), e.options.ScriptTimeout)
	defer cancel()
	release, err := e.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	message := &Message{Status: r.StatusCode, Headers: messageHeaders(r.Header)}
	hasBody := responseHasBody(r.Request.Method, r.StatusCode)
	if s.RequiresBody && hasBody && r.Body != nil {
		body, err := e.bufferBody(ctx, &r.Body, r.Header, s)
		if err != nil {
			return err
		}
		message.Body = body
	}
	// net/http populates trailers after the response body reaches EOF.
	if len(r.Trailer) != 0 {
		message.Trailers = messageHeaders(r.Trailer)
	}
	execution.start()
	result, err := e.runScript(ctx, s, requestMessage(r.Request), message, client)
	if err != nil {
		execution.failed(err)
		e.logRequest(r.Request, fmt.Sprintf("surge script %s failed; forwarding original response: %v", s.Name, err))
		return nil
	}
	if result.Abort {
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
		if int64(len(*result.Body)) > e.options.MaxBodySize {
			return errBodyTooLarge
		}
		replaceResponseBody(r, *result.Body)
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
				if err := rewrite.Apply(headers); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (e *Engine) bufferBody(ctx context.Context, body *io.ReadCloser, header http.Header, s *Script) ([]byte, error) {
	limit := e.options.MaxBodySize
	if s.MaxSize > 0 && s.MaxSize < limit {
		limit = s.MaxSize
	}
	original := *body
	stop := context.AfterFunc(ctx, func() { _ = original.Close() })
	raw, err := readLimited(original, limit)
	stop()
	_ = original.Close()
	*body = io.NopCloser(bytes.NewReader(raw))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}
	return decodeBody(raw, header.Get("Content-Encoding"), limit)
}

func decodeBody(data []byte, encoding string, limit int64) ([]byte, error) {
	encodings := strings.Split(strings.ToLower(encoding), ",")
	for i := len(encodings) - 1; i >= 0; i-- {
		var reader io.Reader
		var closer io.Closer
		switch strings.TrimSpace(encodings[i]) {
		case "", "identity":
			continue
		case "gzip":
			r, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				return nil, err
			}
			reader, closer = r, r
		case "deflate":
			r, err := zlib.NewReader(bytes.NewReader(data))
			if err != nil {
				r = flate.NewReader(bytes.NewReader(data))
			}
			reader, closer = r, r
		case "br":
			reader = brotli.NewReader(bytes.NewReader(data))
		default:
			return nil, fmt.Errorf("unsupported Content-Encoding %q", encoding)
		}
		decoded, err := readLimited(reader, limit)
		if closer != nil {
			_ = closer.Close()
		}
		if err != nil {
			return nil, err
		}
		data = decoded
	}
	return data, nil
}

func requestMessage(r *http.Request) *Message {
	headers := messageHeaders(r.Header)
	headers["Host"] = r.Host
	id, _ := r.Context().Value(requestIDKey{}).(string)
	return &Message{URL: r.URL.String(), Method: r.Method, Headers: headers, ID: id}
}

func resultHeaders(values map[string]string) (http.Header, error) {
	headers := make(http.Header, len(values))
	for k, v := range values {
		if !httpguts.ValidHeaderFieldName(k) || !httpguts.ValidHeaderFieldValue(v) {
			return nil, fmt.Errorf("invalid script header %q", k)
		}
		headers.Set(k, v)
	}
	return headers, nil
}

func resultTrailers(values map[string]string) (http.Header, error) {
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

func removeBodyMetadata(header http.Header) {
	for _, key := range []string{"Content-Encoding", "Content-Length", "Transfer-Encoding", "Content-Md5", "Digest", "Etag"} {
		header.Del(key)
	}
}

func replaceRequestBody(r *http.Request, body []byte) {
	if r.Body != nil {
		_ = r.Body.Close()
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	removeBodyMetadata(r.Header)
}

func replaceResponseBody(r *http.Response, body []byte) {
	if r.Body != nil {
		_ = r.Body.Close()
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	removeBodyMetadata(r.Header)
	r.Header.Set("Content-Length", strconv.FormatInt(r.ContentLength, 10))
}

func syntheticResponse(request *http.Request, status int, header http.Header, body []byte) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	removeHopHeaders(header)
	header.Del("Content-Length")
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: request}
}

func responseFromResult(request *http.Request, result *Result, limit int64) (*http.Response, error) {
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
		body = *result.Body
	}
	if int64(len(body)) > limit {
		return nil, errBodyTooLarge
	}
	response := syntheticResponse(request, status, header, body)
	if result.Trailers != nil {
		response.Trailer, err = resultTrailers(result.Trailers)
		if err != nil {
			return nil, err
		}
	}
	return response, nil
}

func removeHopHeaders(header http.Header) {
	for _, name := range strings.Split(header.Get("Connection"), ",") {
		header.Del(strings.TrimSpace(name))
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Alt-Svc"} {
		header.Del(name)
	}
}
