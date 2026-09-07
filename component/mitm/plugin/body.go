// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"bytes"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
)

var ErrBodyTooLarge = errors.New("body exceeds configured buffering limit")

// SnapshotBody reads at most limit+1 bytes and restores them for the next reader,
// including on overflow or an I/O error. It does not close the body; the caller
// must close the replacement or transfer it downstream. It does not decompress.
// An I/O error is replayed after the consumed bytes, never hidden as a clean EOF.
// The returned bytes may be edited without changing the replayed original.
func SnapshotBody(body *io.ReadCloser, limit int64) ([]byte, error) {
	if limit <= 0 || limit == math.MaxInt64 {
		return nil, errors.New("body snapshot requires a positive, bounded limit")
	}
	if body == nil || *body == nil {
		return nil, nil
	}
	original := *body
	raw, err := io.ReadAll(io.LimitReader(original, limit+1))
	var tail io.Reader = original
	if err != nil {
		tail = bodyReadError{err}
	}
	*body = &replayBody{Reader: io.MultiReader(bytes.NewReader(raw), tail), Closer: original}
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, ErrBodyTooLarge
	}
	return bytes.Clone(raw), nil
}

type replayBody struct {
	io.Reader
	io.Closer
}

type bodyReadError struct{ err error }

func (e bodyReadError) Read([]byte) (int, error) { return 0, e.err }

// ReplaceResponseBody installs unencoded bytes, closes the old body and updates
// framing and representation metadata. Trailers (including gRPC status) survive,
// except stale representation metadata. Callers must handle HEAD/204/206/304 and
// protocol-specific encoding headers themselves, and must not mutate body later.
func ReplaceResponseBody(r *http.Response, body []byte) {
	if r.Body != nil {
		_ = r.Body.Close()
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	r.ContentLength = replaceBodyMetadata(r.Header, r.Trailer, len(body))
	r.TransferEncoding = nil
}

// ReplaceRequestBody has the same ownership and metadata rules as
// ReplaceResponseBody and also updates GetBody for HTTP client retries.
func ReplaceRequestBody(r *http.Request, body []byte) {
	if r.Body != nil {
		_ = r.Body.Close()
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	r.ContentLength = replaceBodyMetadata(r.Header, r.Trailer, len(body))
	r.TransferEncoding = nil
}

func replaceBodyMetadata(header, trailer http.Header, size int) int64 {
	for _, key := range []string{"Content-Encoding", "Content-Length", "Transfer-Encoding", "Trailer", "Content-MD5", "Digest", "Content-Digest", "Repr-Digest", "ETag"} {
		header.Del(key)
		trailer.Del(key)
	}
	if len(trailer) != 0 {
		return -1 // HTTP/1 requires chunked framing to transmit trailers.
	}
	header.Set("Content-Length", strconv.Itoa(size))
	return int64(size)
}
