package common

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
)

func TestInvokeReturnsResult(t *testing.T) {
	got, err := Invoke(context.Background(), func() (int, error) {
		return 42, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != 42 {
		t.Fatalf("result = %d, want 42", got)
	}
}

func TestInvokeCancellationDoesNotBlockWorker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		started := make(chan struct{})
		release := make(chan struct{})
		callback := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			_, err := Invoke(ctx, func() (int, error) {
				close(started)
				<-release
				return 42, nil
			}, func() { close(callback) })
			done <- err
		}()

		<-started
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		<-callback
		// The bubble must finish even though Invoke no longer receives results.
		close(release)
	})
}

func TestInvokeAlreadyCanceledDoesNotStartWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	callback := false
	_, err := Invoke(ctx, func() (int, error) {
		called = true
		return 42, nil
	}, func() { callback = true })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if called {
		t.Fatal("worker started after context cancellation")
	}
	if !callback {
		t.Fatal("cancellation callback was not called")
	}
}

func TestInvokeCancellationWinsCompletedResult(t *testing.T) {
	for range 1000 {
		ctx, cancel := context.WithCancel(context.Background())
		callback := false
		got, err := Invoke(ctx, func() (int, error) {
			cancel()
			return 42, nil
		}, func() { callback = true })
		if got != 0 || !errors.Is(err, context.Canceled) {
			t.Fatalf("Invoke() = %d, %v; want 0, context.Canceled", got, err)
		}
		if !callback {
			t.Fatal("cancellation callback was not called")
		}
	}
}
