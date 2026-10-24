// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

// HTTP/1 waits for its upload writer before returning a response-header read
// error. Closing the upstream socket must therefore interrupt that attempt's
// Body.Read, even while RoundTrip has not yet returned to its caller.
type httpTransportConn struct {
	net.Conn
	ctx    context.Context
	cancel context.CancelFunc
}

func (c *httpTransportConn) Close() error {
	c.cancel()
	return c.Conn.Close()
}

func (c *httpTransportConn) CloseWrite() error { return netproxy.CloseWrite(c.Conn) }

// Arm the close notification only when this attempt starts reading. An HTTP/1
// transport may retry a stale connection with the same still-unread Body.
// Closing it at GotConn time would poison that otherwise safe retry.
type httpUploadBody struct {
	io.ReadCloser
	mu          sync.Mutex
	conn        context.Context
	stop        func() bool
	requestBody *http1RequestBody
	done        chan struct{}
	closeOnce   sync.Once
}

func (b *httpUploadBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	conn := b.conn
	if b.stop == nil && conn != nil {
		b.stop = context.AfterFunc(conn, func() { _ = b.Close() })
	}
	b.mu.Unlock()
	n, err := b.ReadCloser.Read(p)
	if conn != nil && b.requestBody != nil && errors.Is(err, http.ErrBodyReadAfterClose) && b.requestBody.responseStarted.Load() {
		// Only the HTTP/1 upload writer must defer this error; local response readers must not wait on themselves.
		select {
		case <-b.done:
		case <-b.requestBody.done:
		}
	}
	return n, err
}

func (b *httpUploadBody) Close() error {
	// Release the writer before the underlying Close can wait for its Read.
	b.closeOnce.Do(func() { close(b.done) })
	b.mu.Lock()
	if b.stop != nil {
		b.stop()
	}
	b.mu.Unlock()
	return b.ReadCloser.Close()
}

func watchHTTP1Upload(request *http.Request) *http.Request {
	if request.Body == nil || request.Body == http.NoBody {
		return request
	}
	var mu sync.Mutex
	requestBody, _ := request.Context().Value(http1RequestBodyKey{}).(*http1RequestBody)
	body := &httpUploadBody{ReadCloser: request.Body, requestBody: requestBody, done: make(chan struct{})}
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		conn := info.Conn
		if secured, ok := conn.(*tls.Conn); ok {
			if secured.ConnectionState().NegotiatedProtocol == "h2" {
				conn = nil
			} else {
				conn = secured.NetConn()
			}
		}
		var upstreamContext context.Context
		if upstream, ok := conn.(*httpTransportConn); ok {
			upstreamContext = upstream.ctx
		}
		mu.Lock()
		body.mu.Lock()
		body.conn = upstreamContext
		body.mu.Unlock()
		mu.Unlock()
	}}
	attempt := request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
	attempt.Body = body
	if request.GetBody != nil {
		attempt.GetBody = func() (io.ReadCloser, error) {
			replay, err := request.GetBody()
			if err != nil {
				return nil, err
			}
			next := &httpUploadBody{ReadCloser: replay, requestBody: requestBody, done: make(chan struct{})}
			mu.Lock()
			body = next
			mu.Unlock()
			return next, nil
		}
	}
	return attempt
}
