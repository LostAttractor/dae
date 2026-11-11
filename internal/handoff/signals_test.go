// SPDX-License-Identifier: AGPL-3.0-only

package handoff

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSignalsCleanupIsNotStopRequest(t *testing.T) {
	s := NewSignals()
	defer s.Stop()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if s.Stop() {
				t.Error("cleanup cancellation counted as a stop signal")
			}
		})
	}
	wg.Wait()
	if s.Context().Err() == nil {
		t.Fatal("Stop did not cancel cleanup context")
	}
}

func TestSignalsReceiveStop(t *testing.T) {
	for _, sig := range []unix.Signal{unix.SIGINT, unix.SIGTERM, unix.SIGQUIT} {
		t.Run(sig.String(), func(t *testing.T) {
			s := NewSignals()
			defer s.Stop()
			if err := unix.Kill(os.Getpid(), sig); err != nil {
				t.Fatal(err)
			}
			select {
			case <-s.Context().Done():
			case <-time.After(time.Second):
				t.Fatal("stop signal did not cancel context")
			}
			if !s.Stop() || !s.Stop() {
				t.Fatal("real stop request was lost")
			}
			if len(s.queue) != 0 {
				t.Fatal("Stop left queued signals")
			}
		})
	}
}

func TestSignalsStopDrainsQueuedSIGTERM(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	// A joined receiver makes the old-heap queue race deterministic.
	s := &Signals{ctx: ctx, cancel: cancel, queue: make(chan os.Signal, 3), done: make(chan struct{}), joined: make(chan struct{})}
	close(s.joined)
	signal.Notify(s.queue, unix.SIGTERM)
	defer s.Stop()
	if err := unix.Kill(os.Getpid(), unix.SIGTERM); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for len(s.queue) == 0 {
		select {
		case <-deadline.C:
			t.Fatal("SIGTERM was not queued")
		case <-time.After(time.Millisecond):
		}
	}
	// Stop must drain the entire queue, not just observe the first request.
	s.queue <- unix.SIGINT
	s.queue <- unix.SIGQUIT
	if !s.Stop() || !s.Stop() || len(s.queue) != 0 {
		t.Fatal("Stop lost a queued stop request or did not fully drain")
	}
	if s.Context().Err() == nil {
		t.Fatal("queued request did not cancel context")
	}
}
