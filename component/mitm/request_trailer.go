// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
)

// ReverseProxy clones Trailer but shares Body. Synchronize the server's final
// trailers into the outbound map before returning EOF to middleware / transport.
// The map stays attached to shallow transport copies and to completed retries;
// never replace it at EOF. This also handles HTTP/3 replacing the source map.
func forwardRequestTrailers(out, source *http.Request) {
	if source.Body == nil || source.Body == http.NoBody {
		return
	}
	if out.Trailer == nil {
		out.Trailer = make(http.Header)
	}
	// ReverseProxy drops Body for ContentLength == 0, but H2/H3 can still
	// carry trailers after zero DATA bytes. Keep reading through their EOF.
	out.Body = &requestTrailerBody{ReadCloser: source.Body, source: source, trailer: out.Trailer}
}

// Choose framing once, after middleware may have answered locally or changed
// Body / Trailer. Announced trailers use streaming framing immediately: even
// a zero-DATA upload may wait for an early response before sending its EOF.
func prepareRequestFraming(out *http.Request) error {
	if out.Body == nil || out.Body == http.NoBody {
		return nil
	}
	if out.ContentLength == 0 && len(out.Trailer) == 0 {
		// Without announced trailers we must distinguish an empty H2/H3
		// stream from late trailers to preserve Content-Length: 0 for HTTP/1.
		var one [1]byte
		if n, err := io.ReadFull(out.Body, one[:]); n != 0 {
			return fmt.Errorf("mitm: request body exceeds zero Content-Length")
		} else if !errors.Is(err, io.EOF) {
			return fmt.Errorf("mitm: read empty request trailers: %w", err)
		}
		if len(out.Trailer) == 0 {
			_ = out.Body.Close()
			out.Body = http.NoBody
		}
		// With trailers, keep the exhausted reader: HTTP/1 needs a non-NoBody
		// body to emit the trailer block.
	}
	if len(out.Trailer) > 0 {
		// Declared trailers must survive an upstream HTTP/1 fallback, where
		// they require chunked framing even if the input length was known.
		out.ContentLength = -1
		out.Header.Del("Content-Length")
	}
	return nil
}

type requestTrailerBody struct {
	io.ReadCloser
	source  *http.Request
	trailer http.Header
}

func (b *requestTrailerBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF && b.source != nil {
		maps.Copy(b.trailer, b.source.Trailer)
		// A later EOF must not overwrite middleware's trailer edits.
		b.source = nil
	}
	return n, err
}
