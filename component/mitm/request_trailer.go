// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"fmt"
	"io"
	"maps"
	"net/http"

	"github.com/daeuniverse/dae/pkg/membuffer"
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
	out.Body = &requestTrailerBody{ReadCloser: source.Body, source: source, trailer: out.Trailer, empty: source.ContentLength == 0}
}

// Choose framing once, after middleware may have answered locally or changed
// Body / Trailer. Announced trailers use streaming framing immediately: even
// a zero-DATA upload may wait for an early response before sending its EOF.
func prepareRequestFraming(out *http.Request) error {
	if out.Body == nil || out.Body == http.NoBody {
		return nil
	}
	if out.ContentLength == 0 && len(out.Trailer) == 0 {
		// Zero DATA bytes do not imply END_STREAM / FIN. Only normalize an
		// empty request when its reader can confirm completion immediately.
		var ended bool
		if body, ok := out.Body.(interface{ TryReadEOF() (bool, error) }); ok {
			var err error
			ended, err = body.TryReadEOF()
			if err != nil {
				return fmt.Errorf("mitm: inspect empty request: %w", err)
			}
		} else if view := membuffer.Snapshot(out.Body); view != nil {
			// Plugin snapshots and replacements expose complete immutable
			// buffers. Partial snapshots cannot confirm EOF and return nil.
			ended = len(view.Bytes()) == 0
			view.Close()
		}
		if ended && len(out.Trailer) == 0 {
			_ = out.Body.Close()
			out.Body = http.NoBody
			return nil
		}
		// An open stream can carry late trailers. Forward its headers now;
		// upstream HTTP/1 requires chunked framing to preserve those trailers.
		out.ContentLength = -1
		out.Header.Del("Content-Length")
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
	empty   bool
}

func (b *requestTrailerBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if b.empty && n != 0 {
		return 0, fmt.Errorf("mitm: request body exceeds zero Content-Length")
	}
	if err == io.EOF {
		b.copyTrailers()
	}
	return n, err
}

func (b *requestTrailerBody) TryReadEOF() (bool, error) {
	reader, ok := b.ReadCloser.(interface{ TryReadEOF() (bool, error) })
	if !ok {
		return false, nil
	}
	ended, err := reader.TryReadEOF()
	if ended && err == nil {
		b.copyTrailers()
	}
	return ended, err
}

func (b *requestTrailerBody) copyTrailers() {
	if b.source != nil {
		maps.Copy(b.trailer, b.source.Trailer)
		// A later EOF must not overwrite middleware's trailer edits.
		b.source = nil
	}
}
