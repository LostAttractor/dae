// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"context"
	"errors"
	"net/http"

	"github.com/daeuniverse/dae/internal/pluginctx"
)

var ErrAbort = errors.New("mitm: abort HTTP stream")

// PolicyTransport selects a named outbound for a plugin's auxiliary request.
// A client without this capability must not silently ignore an explicit policy.
type PolicyTransport interface {
	RoundTripPolicy(*http.Request, string) (*http.Response, error)
}

type HTTPError struct {
	Status int
	Err    error
}

func (e *HTTPError) Error() string { return e.Err.Error() }
func (e *HTTPError) Unwrap() error { return e.Err }

func IDs(ctx context.Context) (string, string) {
	return pluginctx.IDs(ctx)
}
