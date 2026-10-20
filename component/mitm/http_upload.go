// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
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
	mu   sync.Mutex
	conn context.Context
	stop func() bool
}

func (b *httpUploadBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	if b.stop == nil && b.conn != nil {
		b.stop = context.AfterFunc(b.conn, func() { _ = b.ReadCloser.Close() })
	}
	b.mu.Unlock()
	return b.ReadCloser.Read(p)
}

func (b *httpUploadBody) Close() error {
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
	body := &httpUploadBody{ReadCloser: request.Body}
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		conn := info.Conn
		if secured, ok := conn.(*tls.Conn); ok {
			if secured.ConnectionState().NegotiatedProtocol == "h2" {
				return
			}
			conn = secured.NetConn()
		}
		upstream, ok := conn.(*httpTransportConn)
		if !ok {
			return
		}
		mu.Lock()
		body.mu.Lock()
		body.conn = upstream.ctx
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
			next := &httpUploadBody{ReadCloser: replay}
			mu.Lock()
			body = next
			mu.Unlock()
			return next, nil
		}
	}
	return attempt
}
