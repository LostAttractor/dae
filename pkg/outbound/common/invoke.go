package common

import (
	"context"
)

func Invoke[R any](ctx context.Context, fn func() (R, error), cb func()) (res R, err error) {
	type result struct {
		value R
		err   error
	}
	if err = ctx.Err(); err != nil {
		if cb != nil {
			cb()
		}
		return
	}
	resultChan := make(chan result, 1)

	go func() {
		value, err := fn()
		resultChan <- result{value, err}
	}()

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case result := <-resultChan:
		// Cancellation owns cleanup if it became observable before the
		// completed operation was committed to the caller.
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = ctxErr
		} else {
			res, err = result.value, result.err
		}
	}

	if err != nil && cb != nil {
		cb()
	}

	return
}
