package netproxy

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestLeaseAbortCallbacks(t *testing.T) {
	parent := NewLease(NewResourceRef())
	child := parent.NewStream()
	called := make(chan struct{})
	stop := child.AfterAbort(func() { close(called) })
	removed := child.AfterAbort(func() { t.Error("stopped callback ran") })
	if !removed() || removed() {
		t.Fatal("stop must remove a pending callback exactly once")
	}
	parent.Abort(nil)
	<-called
	if stop() {
		t.Fatal("stopped an already scheduled callback")
	}
	late := make(chan struct{})
	child.AfterAbort(func() { close(late) })
	<-late
	drained := NewLease(NewResourceRef())
	drained.AfterAbort(func() { t.Error("ordinary invalidation aborted a consumer") })
	drained.Invalidate(nil)
	drained.AfterAbort(func() { t.Error("late registration changed invalidation to abort") })
	if len(drained.onAbort) != 0 {
		t.Fatal("invalidation retained callbacks")
	}
}

func TestLeaseAbortRacesWithCallbackStop(t *testing.T) {
	for range 100 {
		lease := NewLease(NewResourceRef())
		var calls atomic.Int32
		done := make(chan struct{})
		stop := lease.AfterAbort(func() { calls.Add(1); close(done) })
		var work sync.WaitGroup
		work.Go(func() { lease.Abort(nil) })
		removed := stop()
		work.Wait()
		if !removed {
			<-done
		}
		if got := calls.Load(); removed && got != 0 || !removed && got != 1 {
			t.Fatalf("stop=%t calls=%d", removed, got)
		}
	}
}
