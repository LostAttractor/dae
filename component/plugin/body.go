// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
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
	r.Header, r.ContentLength = replaceBodyMetadata(r.Header, r.Trailer, len(view.Bytes()))
	r.TransferEncoding = nil
}

// SetRequestBody transfers a body cursor to the request, just like
// SetResponseBody. The host owns retry storage only while forwarding upstream.
func SetRequestBody(r *http.Request, view *membuffer.View) {
	next := view.Open()
	if r.Body != nil {
		_ = r.Body.Close()
	}
	r.Body, r.GetBody = next, nil
	r.Header, r.ContentLength = replaceBodyMetadata(r.Header, r.Trailer, len(view.Bytes()))
	r.TransferEncoding = nil
}

func replaceBodyMetadata(header, trailer http.Header, size int) (http.Header, int64) {
	if header == nil {
		header = make(http.Header)
	}
	for _, key := range []string{"Content-Encoding", "Content-Length", "Transfer-Encoding", "Trailer", "Content-MD5", "Digest", "Content-Digest", "Repr-Digest", "ETag"} {
		header.Del(key)
		trailer.Del(key)
	}
	if len(trailer) != 0 {
		return header, -1
	}
	header.Set("Content-Length", strconv.Itoa(size))
	return header, int64(size)
}
