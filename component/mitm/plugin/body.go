// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"io"
	"net/http"
	"strconv"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

// SetResponseBody borrows immutable bytes until the response is sent or closed.
// The caller still owns and closes its view. Trailers survive replacement except
// for stale representation metadata; protocol-specific encoding is the plugin's responsibility.
func SetResponseBody(r *http.Response, view *membuffer.View) {
	next := view.Open()
	if r.Body != nil {
		_ = r.Body.Close()
	}
	r.Body = next
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	r.ContentLength = replaceBodyMetadata(r.Header, r.Trailer, len(view.Bytes()))
	r.TransferEncoding = nil
}

// SetRequestBody keeps retry ownership on the exchange, independently of the
// transport's body cursors. Close the exchange only after response forwarding ends.
func (e *Exchange) SetRequestBody(view *membuffer.View) {
	owned := view.Clone()
	r := e.Request
	if r.Body != nil {
		_ = r.Body.Close()
	}
	e.retryBody.Close()
	e.retryBody = owned
	r.Body = owned.Open()
	r.GetBody = func() (io.ReadCloser, error) { return owned.Open(), nil }
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	r.ContentLength = replaceBodyMetadata(r.Header, r.Trailer, len(view.Bytes()))
	r.TransferEncoding = nil
}

// Close ends request ownership after all forwarding and retries. The host calls
// it on success, abort, cancellation and failure, after the complete HTTP exchange.
func (e *Exchange) Close() error {
	var err error
	if e.Request.Body != nil {
		err = e.Request.Body.Close()
	}
	e.Request.GetBody = nil
	e.retryBody.Close()
	return err
}

func replaceBodyMetadata(header, trailer http.Header, size int) int64 {
	for _, key := range []string{"Content-Encoding", "Content-Length", "Transfer-Encoding", "Trailer", "Content-MD5", "Digest", "Content-Digest", "Repr-Digest", "ETag"} {
		header.Del(key)
		trailer.Del(key)
	}
	if len(trailer) != 0 {
		return -1
	}
	header.Set("Content-Length", strconv.Itoa(size))
	return int64(size)
}
