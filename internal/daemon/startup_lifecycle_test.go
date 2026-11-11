// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestReadyHonorsDeadlineOnFullNotifySocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify")
	socket, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Net: "unixgram", Name: path})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	// Don't read: once the kernel's datagram queue fills, READY must stop waiting.
	for err == nil {
		err = notifyService(ctx, "ready")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestStartupLifecycleBudget(t *testing.T) {
	for _, phase := range []string{"completed", "deadline before Run", "signal before deadline", "repeated shutdown"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				parent, signal := context.WithCancelCause(t.Context())
				defer signal(context.Canceled)
				ctx, cancel := context.WithCancelCause(parent)
				defer cancel(context.Canceled)
				var forced atomic.Int32
				begin, finish := watchShutdown(ctx, shutdownTimeout, func() { forced.Add(1) })
				defer finish()
				startup := &Startup{ctx: ctx, cancel: cancel, beginShutdown: begin}
				startup.setPreparationDeadline(time.Now().Add(time.Minute))
				defer startup.stopPreparation()
				signalCause := errors.New("fixture stop requested")
				switch phase {
				case "completed":
					startup.stopPreparation()
					startup.stopPreparation()
					time.Sleep(time.Minute + shutdownTimeout)
					synctest.Wait()
					if ctx.Err() != nil || forced.Load() != 0 {
						t.Fatalf("completed preparation expired: %v, forced=%d", context.Cause(ctx), forced.Load())
					}
					startup.beginShutdown()
					if ctx.Err() != nil {
						t.Fatal("shutdown grace canceled the exec context")
					}
				case "deadline before Run":
					time.Sleep(time.Minute)
					synctest.Wait()
					if !errors.Is(context.Cause(ctx), context.DeadlineExceeded) || forced.Load() != 0 {
						t.Fatalf("deadline did not start cleanup grace: %v, forced=%d", context.Cause(ctx), forced.Load())
					}
				case "signal before deadline":
					signal(signalCause)
				case "repeated shutdown":
					startup.beginShutdown()
					time.Sleep(5 * time.Second)
					startup.beginShutdown()
					time.Sleep(shutdownTimeout - 5*time.Second + time.Second)
					synctest.Wait()
					if forced.Load() != 1 {
						t.Fatalf("repeated shutdown extended its original grace: forced=%d", forced.Load())
					}
					return
				}
				time.Sleep(shutdownTimeout + time.Second)
				synctest.Wait()
				if forced.Load() != 1 {
					t.Fatalf("shutdown was not bounded: forced=%d", forced.Load())
				}
				if phase == "signal before deadline" {
					time.Sleep(time.Minute)
					synctest.Wait()
					if context.Cause(ctx) != signalCause || forced.Load() != 1 {
						t.Fatalf("deadline replaced an earlier stop: %v, forced=%d", context.Cause(ctx), forced.Load())
					}
				}
			})
		})
	}
}

func TestStartupJoinsExpiredPreparation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancelCause(t.Context())
		defer cancel(context.Canceled)
		begin, finish := watchShutdown(ctx, shutdownTimeout, func() { t.Error("unexpected forced exit") })
		defer finish()
		started, release := make(chan struct{}), make(chan struct{})
		startup := &Startup{ctx: ctx, beginShutdown: begin, cancel: func(cause error) {
			close(started)
			<-release
			cancel(cause)
		}}
		startup.setPreparationDeadline(time.Now())
		<-started
		joined := make(chan struct{})
		go func() {
			startup.stopPreparation()
			close(joined)
		}()
		synctest.Wait()
		select {
		case <-joined:
			t.Fatal("preparation completed before its running cancellation callback")
		default:
		}
		close(release)
		<-joined
		if !errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			t.Fatalf("lost the expired preparation cause: %v", context.Cause(ctx))
		}
		startup.stopPreparation()
	})
}
