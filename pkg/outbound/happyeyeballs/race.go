// SPDX-License-Identifier: AGPL-3.0-only

package happyeyeballs

import (
	"context"
	"errors"
	"iter"
	"sync"
	"time"
)

const (
	attemptDelay = 250 * time.Millisecond
	minimumDelay = 10 * time.Millisecond
)

// Race staggers attempts, returns the first success, and cancels and joins losers.
// discard releases successful results that arrive after another attempt won.
// A source error is terminal (for example, a routing rejection); recoverable
// per-address errors belong to attempt. Source and attempt must honor ctx.
func Race[A, R any](parent context.Context, source func(context.Context) iter.Seq2[A, error], attempt func(context.Context, A) (R, error), discard func(R)) (R, error) {
	var zero R
	var workers sync.WaitGroup
	defer workers.Wait()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	type candidate struct {
		address A
		err     error
	}
	input := make(chan candidate)
	request := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(input)
		defer close(finished)
		next, stop := iter.Pull2(source(ctx))
		defer stop()
		for {
			select {
			case <-request:
			case <-ctx.Done():
				return
			}
			address, err, ok := next()
			if !ok {
				return
			}
			select {
			case input <- candidate{address, err}:
			case <-ctx.Done():
				return
			}
		}
	}()
	defer func() { cancel(); <-finished }()
	type result struct {
		value R
		err   error
	}
	results := make(chan result)
	returned := make(chan struct{})
	defer close(returned)
	var failures []error
	var pending *candidate
	active := 0
	var started time.Time
	timer := time.NewTimer(0)
	defer timer.Stop()
	ready, waiting := false, false
	for {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		if pending != nil && ready {
			address := pending.address
			pending, ready = nil, false
			active++
			started = time.Now()
			timer.Reset(attemptDelay)
			workers.Go(func() {
				value, err := attempt(ctx, address)
				select {
				case results <- result{value, err}:
				case <-returned:
					if err == nil && discard != nil {
						discard(value)
					}
				}
			})
		}
		if input == nil && pending == nil && active == 0 {
			return zero, errors.Join(errors.New("no reachable address"), errors.Join(failures...))
		}
		var pull chan struct{}
		if ready && pending == nil && !waiting && input != nil {
			pull = request
		}
		select {
		case pull <- struct{}{}:
			waiting = true
		case c, ok := <-input:
			waiting = false
			if !ok {
				input = nil
			} else if c.err != nil {
				return zero, c.err
			} else {
				pending = &c
			}
		case r := <-results:
			active--
			if r.err == nil {
				return r.value, nil
			}
			failures = append(failures, r.err)
			if active == 0 && !ready {
				timer.Reset(max(0, minimumDelay-time.Since(started)))
			}
		case <-timer.C:
			ready = true
		case <-ctx.Done():
			return zero, ctx.Err()
		}
	}
}
