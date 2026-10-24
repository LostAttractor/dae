// SPDX-License-Identifier: AGPL-3.0-only

package pluginhost

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

type poolTestState struct {
	closes atomic.Int32
	close  func() error
}

func (s *poolTestState) Close() error {
	s.closes.Add(1)
	if s.close != nil {
		return s.close()
	}
	return nil
}

func acquireTestState(t *testing.T, pool *StatePool, key string, build func() (io.Closer, error)) (io.Closer, func() error) {
	t.Helper()
	value, release, err := pool.Acquire(t.Context(), key, build)
	if err != nil {
		t.Fatal(err)
	}
	return value, release
}

func TestStatePoolConcurrentBuildAndIdempotentRelease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var pool StatePool
		state := new(poolTestState)
		var builds atomic.Int32
		built := make(chan struct{})
		build := func() (io.Closer, error) {
			builds.Add(1)
			<-built
			return state, nil
		}
		const count = 16
		var leases [count]func() error
		var wg sync.WaitGroup
		for i := range count {
			wg.Go(func() {
				value, release, err := pool.Acquire(t.Context(), "state", build)
				if err != nil || value != state {
					t.Errorf("Acquire = %v, %v", value, err)
				}
				leases[i] = release
			})
		}
		synctest.Wait()
		if builds.Load() != 1 {
			t.Fatalf("builders = %d, want 1", builds.Load())
		}
		close(built)
		wg.Wait()
		for _, release := range leases {
			if release == nil {
				t.Fatal("missing lease")
			}
			for range 2 {
				wg.Go(func() {
					if err := release(); err != nil {
						t.Error(err)
					}
				})
			}
		}
		wg.Wait()
		if err := pool.Close(); err != nil || state.closes.Load() != 1 {
			t.Fatalf("Close = %v; state closes = %d", err, state.closes.Load())
		}
	})
}

func TestStatePoolCancelledBuild(t *testing.T) {
	failure := errors.New("save failed")
	for name, closeErr := range map[string]error{"success": nil, "failure": failure} {
		t.Run(name, func(t *testing.T) {
			var pool StatePool
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			_, _, err := pool.Acquire(ctx, "state", func() (io.Closer, error) {
				t.Fatal("cancelled caller constructed state")
				return nil, nil
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			state := &poolTestState{close: func() error { return closeErr }}
			ctx, cancel = context.WithCancel(t.Context())
			defer cancel()
			value, release, err := pool.Acquire(ctx, "state", func() (io.Closer, error) {
				cancel()
				return state, nil
			})
			if !errors.Is(err, context.Canceled) || value != nil || release != nil || state.closes.Load() != 1 {
				t.Fatalf("cancel during build = %v, %v; closes = %d", value, err, state.closes.Load())
			}
			if closeErr != nil {
				if !errors.Is(err, closeErr) {
					t.Fatal("cancelled build lost cleanup error")
				}
				value, release = acquireTestState(t, &pool, "state", func() (io.Closer, error) {
					t.Fatal("failed cleanup discarded state")
					return nil, nil
				})
				if value != state {
					t.Fatal("failed cleanup state was not reused")
				}
				state.close = nil
				if err := release(); err != nil {
					t.Fatal(err)
				}
			}
			if err := pool.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStatePoolBuilderFailureCanRetry(t *testing.T) {
	var pool StatePool
	failure := errors.New("build failed")
	_, _, err := pool.Acquire(t.Context(), "state", func() (io.Closer, error) { return nil, failure })
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	_, _, err = pool.Acquire(t.Context(), "state", func() (io.Closer, error) { return nil, nil })
	if err == nil {
		t.Fatal("nil builder result was accepted")
	}
	_, release := acquireTestState(t, &pool, "state", func() (io.Closer, error) { return new(poolTestState), nil })
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

func TestStatePoolAcquireDuringFinalClose(t *testing.T) {
	for name, fails := range map[string]bool{"success": false, "failure": true} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var pool StatePool
				failure := errors.New("save failed")
				closing, finish := make(chan struct{}), make(chan struct{})
				state := &poolTestState{close: func() error {
					close(closing)
					<-finish
					if fails {
						return failure
					}
					return nil
				}}
				_, release := acquireTestState(t, &pool, "state", func() (io.Closer, error) { return state, nil })
				released := make(chan error, 1)
				go func() { released <- release() }()
				<-closing

				ctx, cancel := context.WithCancel(t.Context())
				cancelled := make(chan error, 1)
				go func() {
					_, _, err := pool.Acquire(ctx, "state", func() (io.Closer, error) {
						t.Error("builder ran while previous state was closing")
						return new(poolTestState), nil
					})
					cancelled <- err
				}()
				synctest.Wait()
				cancel()
				if err := <-cancelled; !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				_, otherRelease := acquireTestState(t, &pool, "other", func() (io.Closer, error) { return new(poolTestState), nil })
				if err := otherRelease(); err != nil {
					t.Fatal(err)
				}

				var next io.Closer
				var nextRelease func() error
				acquired := make(chan struct{})
				var builds atomic.Int32
				go func() {
					var err error
					next, nextRelease, err = pool.Acquire(t.Context(), "state", func() (io.Closer, error) {
						builds.Add(1)
						return new(poolTestState), nil
					})
					if err != nil {
						t.Error(err)
					}
					close(acquired)
				}()
				synctest.Wait()
				select {
				case <-acquired:
					t.Fatal("same key acquired before Close finished")
				default:
				}
				close(finish)
				err := <-released
				if fails != errors.Is(err, failure) {
					t.Fatalf("release error = %v", err)
				}
				if again := release(); again != err {
					t.Fatal("release did not memoize its result")
				}
				<-acquired
				if (next == state) != fails || (builds.Load() == 0) != fails {
					t.Fatalf("state reuse = %v, builds = %d", next == state, builds.Load())
				}
				state.close = nil
				if err := nextRelease(); err != nil {
					t.Fatal(err)
				}
				if err := pool.Close(); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestStatePoolCloseWaitsForReleaseAndRetries(t *testing.T) {
	failure := errors.New("save failed")
	for name, closeErr := range map[string]error{"success": nil, "retry": failure} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var pool StatePool
				closing, finish := make(chan struct{}), make(chan struct{})
				var attempts atomic.Int32
				state := &poolTestState{close: func() error {
					if attempts.Add(1) == 1 {
						close(closing)
						<-finish
						return closeErr
					}
					return nil
				}}
				_, release := acquireTestState(t, &pool, "state", func() (io.Closer, error) { return state, nil })
				healthy := new(poolTestState)
				_, healthyRelease := acquireTestState(t, &pool, "healthy", func() (io.Closer, error) { return healthy, nil })
				released := make(chan error, 1)
				go func() { released <- release() }()
				<-closing
				waiting := make(chan error, 1)
				go func() {
					_, _, err := pool.Acquire(t.Context(), "state", func() (io.Closer, error) {
						t.Error("shutdown waiter rebuilt state")
						return new(poolTestState), nil
					})
					waiting <- err
				}()
				synctest.Wait()
				closed := make(chan error, 1)
				go func() { closed <- pool.Close() }()
				synctest.Wait()
				if healthy.closes.Load() != 1 {
					t.Error("pending release blocked independent state close")
				}
				if err := <-waiting; !errors.Is(err, net.ErrClosed) {
					t.Fatalf("shutdown did not reject waiting Acquire: %v", err)
				}
				_, _, err := pool.Acquire(t.Context(), "other", func() (io.Closer, error) { return new(poolTestState), nil })
				if !errors.Is(err, net.ErrClosed) {
					t.Fatalf("shutdown admitted new state: %v", err)
				}
				select {
				case <-closed:
					t.Fatal("pool closed during in-flight final release")
				default:
				}
				close(finish)
				if err := <-released; !errors.Is(err, closeErr) {
					t.Fatal(err)
				}
				if err := <-closed; err != nil {
					t.Fatal(err)
				}
				wantCloses := int32(1)
				if closeErr != nil {
					wantCloses++
				}
				if err := pool.Close(); err != nil || state.closes.Load() != wantCloses {
					t.Fatalf("Close = %v; closes = %d, want %d", err, state.closes.Load(), wantCloses)
				}
				if err := healthyRelease(); err != nil || healthy.closes.Load() != 1 {
					t.Fatalf("healthy release = %v; closes = %d", err, healthy.closes.Load())
				}
				if len(pool.states) != 0 {
					t.Fatal("pool retained successfully closed states")
				}
			})
		})
	}
}

func TestStatePoolCloseWaitsForBuild(t *testing.T) {
	failure := errors.New("failed")
	for _, test := range []struct {
		name       string
		buildErr   error
		closeErr   error
		wantCloses int32
	}{
		{name: "success", wantCloses: 1},
		{name: "build failure", buildErr: failure},
		{name: "cleanup retry", closeErr: failure, wantCloses: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var pool StatePool
				var attempts atomic.Int32
				state := &poolTestState{close: func() error {
					if attempts.Add(1) == 1 {
						return test.closeErr
					}
					return nil
				}}
				healthy := new(poolTestState)
				_, healthyRelease := acquireTestState(t, &pool, "healthy", func() (io.Closer, error) { return healthy, nil })
				building, finish := make(chan struct{}), make(chan struct{})
				acquired := make(chan error, 1)
				go func() {
					_, _, err := pool.Acquire(t.Context(), "state", func() (io.Closer, error) {
						close(building)
						<-finish
						if test.buildErr != nil {
							return nil, test.buildErr
						}
						return state, nil
					})
					acquired <- err
				}()
				<-building
				closed := make(chan error, 1)
				go func() { closed <- pool.Close() }()
				synctest.Wait()
				if healthy.closes.Load() != 1 {
					t.Error("pending build blocked independent state close")
				}
				select {
				case <-closed:
					t.Fatal("pool closed during build")
				default:
				}
				close(finish)
				err := <-acquired
				if test.buildErr != nil {
					if !errors.Is(err, test.buildErr) {
						t.Fatal(err)
					}
				} else if !errors.Is(err, net.ErrClosed) || (test.closeErr != nil && !errors.Is(err, test.closeErr)) {
					t.Fatal(err)
				}
				if err := <-closed; err != nil || state.closes.Load() != test.wantCloses {
					t.Fatalf("Close = %v; closes = %d, want %d", err, state.closes.Load(), test.wantCloses)
				}
				if err := healthyRelease(); err != nil || healthy.closes.Load() != 1 {
					t.Fatalf("healthy release = %v; closes = %d", err, healthy.closes.Load())
				}
				if len(pool.states) != 0 {
					t.Fatal("pool retained successfully closed states")
				}
			})
		})
	}
}

func TestStatePoolClosesIndependentStatesConcurrently(t *testing.T) {
	for name, fails := range map[string]bool{"success": false, "failure": true} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var pool StatePool
				finish := make(chan struct{})
				var states [2]*poolTestState
				var releases [2]func() error
				var failures [2]error
				for i, key := range []string{"first", "second"} {
					if fails {
						failures[i] = errors.New(key + " failed")
					}
					states[i] = &poolTestState{close: func() error {
						<-finish
						return failures[i]
					}}
					_, releases[i] = acquireTestState(t, &pool, key, func() (io.Closer, error) { return states[i], nil })
				}
				closed := make(chan error, 2)
				go func() { closed <- pool.Close() }()
				synctest.Wait()
				for i, state := range states {
					if state.closes.Load() != 1 {
						t.Errorf("state %d closes = %d before unblock, want 1", i, state.closes.Load())
					}
					if err := releases[i](); err != nil {
						t.Fatal(err)
					}
				}
				select {
				case <-closed:
					t.Fatal("pool did not join independent closes")
				default:
				}
				go func() { closed <- pool.Close() }()
				close(finish)
				for range cap(closed) {
					err := <-closed
					for _, failure := range failures {
						if !errors.Is(err, failure) {
							t.Fatalf("Close = %v, want %v", err, failure)
						}
					}
				}
				if err := pool.Close(); !errors.Is(err, failures[0]) || !errors.Is(err, failures[1]) {
					t.Fatalf("repeated Close = %v, want %v", err, failures)
				}
				for _, state := range states {
					if state.closes.Load() != 1 {
						t.Fatalf("state closed %d times, want 1", state.closes.Load())
					}
				}
				wantRemaining := 0
				if fails {
					wantRemaining = len(states)
				}
				if len(pool.states) != wantRemaining {
					t.Fatalf("remaining states = %d, want %d", len(pool.states), wantRemaining)
				}
			})
		})
	}
}
