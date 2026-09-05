// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"io"
)

// NewContextReader checks ctx before each read from r. It observes cancellation
// between Read calls; it cannot interrupt an already blocking read from r.
func NewContextReader(ctx context.Context, r io.Reader) io.Reader {
	return contextReader{ctx: ctx, reader: r}
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
