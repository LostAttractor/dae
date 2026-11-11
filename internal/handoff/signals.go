// SPDX-License-Identifier: AGPL-3.0-only

package handoff

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// Signals keeps real stop requests separate from cancellation used for cleanup.
// Stop is the final signal barrier before exec, not just a context cancel function.
type Signals struct {
	ctx      context.Context
	cancel   context.CancelFunc
	queue    chan os.Signal
	done     chan struct{}
	joined   chan struct{}
	once     sync.Once
	stopping atomic.Bool
}

func NewSignals() *Signals {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Signals{ctx: ctx, cancel: cancel, queue: make(chan os.Signal, 3), done: make(chan struct{}), joined: make(chan struct{})}
	signal.Notify(s.queue, unix.SIGINT, unix.SIGTERM, unix.SIGQUIT)
	go func() {
		defer close(s.joined)
		for {
			select {
			case <-s.queue:
				s.stopping.Store(true)
				s.cancel()
			case <-s.done:
				return
			}
		}
	}()
	return s
}

func (s *Signals) Context() context.Context { return s.ctx }

// Stop unregisters, joins the receiver, and drains every queued stop signal.
// It also cancels Context, but reports only actual signal delivery. It is idempotent.
func (s *Signals) Stop() bool {
	s.once.Do(func() {
		signal.Stop(s.queue)
		close(s.done)
		<-s.joined
		for {
			select {
			case <-s.queue:
				s.stopping.Store(true)
			default:
				s.cancel()
				return
			}
		}
	})
	return s.stopping.Load()
}
