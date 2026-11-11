// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

type runtimeTestState struct {
	closes atomic.Int32
	err    error
}

func (s *runtimeTestState) Close() error {
	s.closes.Add(1)
	return s.err
}

func TestRuntimeSharedStatesCloseAfterGenerationsRetire(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := NewRuntime()
		state := &runtimeTestState{err: errors.New("shared state cleanup failed")}
		_, release, err := r.SharedStates().Acquire(t.Context(), "state", func() (io.Closer, error) { return state, nil })
		if err != nil {
			t.Fatal(err)
		}
		plane := newLifecycleTestControlPlane(t, r.udpEndpoints)
		plane.core = &controlPlaneCore{close: func() {}}
		planeClosed := make(chan struct{})
		plane.cleanups.add(func() error {
			if state.closes.Load() != 0 {
				t.Error("shared state closed before the plane")
			}
			defer close(planeClosed)
			return release()
		})
		r.planes[1] = plane
		retired := make(chan struct{})
		r.retired = retired
		closed := make(chan error, 1)
		go func() { closed <- r.Close() }()
		<-planeClosed
		synctest.Wait()
		if state.closes.Load() != 0 {
			t.Fatal("shared state closed before retired hosts finished")
		}
		_, _, err = r.SharedStates().Acquire(t.Context(), "other", func() (io.Closer, error) {
			t.Error("shutdown admitted new state")
			return new(runtimeTestState), nil
		})
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Acquire during shutdown = %v", err)
		}
		close(retired)
		if err := <-closed; !errors.Is(err, state.err) {
			t.Fatalf("shared-state close failure missing from shutdown: %v", err)
		}
		if err := r.Close(); !errors.Is(err, state.err) {
			t.Fatalf("repeated close lost shared-state failure: %v", err)
		}
		if state.closes.Load() != 1 {
			t.Fatalf("state closes = %d, want 1", state.closes.Load())
		}
		select {
		case err := <-r.errors:
			t.Fatalf("shutdown failure reached asynchronous errors: %v", err)
		default:
		}
	})
}

func TestRuntimeSharedStatesRetryFailedFinalRelease(t *testing.T) {
	r := NewRuntime()
	state := &runtimeTestState{err: errors.New("save failed")}
	_, release, err := r.SharedStates().Acquire(t.Context(), "state", func() (io.Closer, error) { return state, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); !errors.Is(err, state.err) {
		t.Fatal(err)
	}
	if err := r.Close(); !errors.Is(err, state.err) {
		t.Fatalf("shutdown retry lost shared-state close failure: %v", err)
	}
	if state.closes.Load() != 2 {
		t.Fatalf("state closes = %d, want a shutdown retry", state.closes.Load())
	}
}
