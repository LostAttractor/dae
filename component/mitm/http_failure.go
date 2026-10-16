// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"

	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
)

type requestNotProcessedError struct{ error }

func (e *requestNotProcessedError) Unwrap() error { return e.error }

// The HTTP/3 transport returns the peer's original reset after exhausting its
// internal retry. GetBody is not called in that case, even with a full replay.
func preserveHTTP3Rejection(request *http.Request, err error) error {
	if request.Context().Err() != nil || errors.Is(err, context.Canceled) {
		return err
	}
	if failure, ok := errors.AsType[*quic.StreamError](err); ok && failure.Remote && failure.ErrorCode == quic.StreamErrorCode(http3.ErrCodeRequestRejected) {
		return &requestNotProcessedError{err}
	}
	return err
}

// HTTP/2 and HTTP/3 call GetBody only after deciding that an attempt was not
// processed (REFUSED_STREAM / H3_REQUEST_REJECTED, GOAWAY, or an unusable
// connection). Preserve that decision when the bounded replay is unavailable.
// HTTP/1 also retries ambiguous errors for idempotent requests: it must never
// use this marker. GotConn identifies the actual negotiated upstream protocol,
// independently of the downstream protocol or URL scheme.
func preserveRequestRejection(request *http.Request, packet bool) *http.Request {
	if request.GetBody == nil {
		return request
	}
	var multiplexed atomic.Bool
	multiplexed.Store(packet)
	ctx := request.Context()
	if !packet {
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
			conn, ok := info.Conn.(interface{ ConnectionState() tls.ConnectionState })
			multiplexed.Store(ok && conn.ConnectionState().NegotiatedProtocol == "h2")
		}})
	}
	attempt := request.WithContext(ctx)
	attempt.GetBody = func() (io.ReadCloser, error) {
		body, err := request.GetBody()
		if err != nil && multiplexed.Load() && request.Context().Err() == nil {
			return nil, &requestNotProcessedError{err}
		}
		return body, err
	}
	return attempt
}

// resetUnprocessedRequest emits the protocol's safe-retry signal without
// committing response headers. HTTP/1 has no equivalent; its handler abort
// closes the connection and leaves retry policy with the client.
func resetUnprocessedRequest(w http.ResponseWriter) {
	for {
		if writer, ok := w.(interface{ RejectRequest() error }); ok {
			_ = writer.RejectRequest()
			return
		}
		wrapper, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return
		}
		w = wrapper.Unwrap()
	}
}
