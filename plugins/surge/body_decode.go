// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

// decodeBodyView consumes its input view, preserving the original replay owned
// by the exchange. Each decoded layer releases its predecessor after reading.
func decodeBodyView(ctx context.Context, view *membuffer.View, encoding string, limit int64, budget *membuffer.Budget) (_ *membuffer.View, err error) {
	defer func() {
		if err != nil {
			view.Close()
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(view.Bytes()) == 0 {
		return view, nil
	}
	encodings := strings.Split(strings.ToLower(encoding), ",")
	for i := len(encodings) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var reader io.Reader
		var closer io.Closer
		source := common.NewContextReader(ctx, bytes.NewReader(view.Bytes()))
		switch strings.TrimSpace(encodings[i]) {
		case "", "identity":
			continue
		case "gzip":
			r, err := gzip.NewReader(source)
			if err != nil {
				return nil, err
			}
			reader, closer = r, r
		case "deflate":
			r, err := zlib.NewReader(source)
			if err != nil {
				r = flate.NewReader(common.NewContextReader(ctx, bytes.NewReader(view.Bytes())))
			}
			reader, closer = r, r
		case "br":
			reader = brotli.NewReader(source)
		default:
			return nil, fmt.Errorf("unsupported Content-Encoding %q", encoding)
		}
		// Check both compressed input and decoded output: a decoder can consume
		// many empty gzip members or expand buffered input without another read.
		decoded, err := membuffer.Read(common.NewContextReader(ctx, reader), limit, budget)
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return view, nil
}
