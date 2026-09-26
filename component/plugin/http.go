// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"context"
	"errors"

	"github.com/daeuniverse/dae/internal/pluginctx"
)

var ErrAbort = errors.New("mitm: abort HTTP stream")

type HTTPError struct {
	Status int
	Err    error
}

func (e *HTTPError) Error() string { return e.Err.Error() }
func (e *HTTPError) Unwrap() error { return e.Err }

func IDs(ctx context.Context) (string, string) {
	return pluginctx.IDs(ctx)
}
