// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"context"
	"errors"
)

var ErrAbort = errors.New("mitm: abort HTTP stream")

type HTTPError struct {
	Status int
	Err    error
}

func (e *HTTPError) Error() string { return e.Err.Error() }
func (e *HTTPError) Unwrap() error { return e.Err }

type idsKey struct{}
type ids struct{ connection, request string }

func IDs(ctx context.Context) (string, string) {
	v, _ := ctx.Value(idsKey{}).(ids)
	return v.connection, v.request
}

// WithIDs attaches host-assigned trace identities to a request context.
func WithIDs(ctx context.Context, connection, request string) context.Context {
	return context.WithValue(ctx, idsKey{}, ids{connection: connection, request: request})
}
