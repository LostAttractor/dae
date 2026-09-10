// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

// decodeBodyView consumes its input view, preserving the original replay owned
// by the exchange. Each decoded layer releases its predecessor after reading.
func decodeBodyView(view *membuffer.View, encoding string, limit int64, budget *membuffer.Budget) (_ *membuffer.View, err error) {
	defer func() {
		if err != nil {
			view.Close()
		}
	}()
	if len(view.Bytes()) == 0 {
		return view, nil
	}
	encodings := strings.Split(strings.ToLower(encoding), ",")
	for i := len(encodings) - 1; i >= 0; i-- {
		var reader io.Reader
		var closer io.Closer
		switch strings.TrimSpace(encodings[i]) {
		case "", "identity":
			continue
		case "gzip":
			r, err := gzip.NewReader(bytes.NewReader(view.Bytes()))
			if err != nil {
				return nil, err
			}
			reader, closer = r, r
		case "deflate":
			r, err := zlib.NewReader(bytes.NewReader(view.Bytes()))
			if err != nil {
				r = flate.NewReader(bytes.NewReader(view.Bytes()))
			}
			reader, closer = r, r
		case "br":
			reader = brotli.NewReader(bytes.NewReader(view.Bytes()))
		default:
			return nil, fmt.Errorf("unsupported Content-Encoding %q", encoding)
		}
		decoded, err := membuffer.Read(reader, limit, budget)
		if closer != nil {
			_ = closer.Close()
		}
		if err != nil {
			decoded.Close()
			return nil, err
		}
		view.Close()
		view = decoded
	}
	return view, nil
}
