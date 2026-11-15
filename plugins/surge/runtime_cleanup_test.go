// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestDeviceExecutionCleanupDoesNotWaitForStoreIO(t *testing.T) {
	for _, finish := range []string{"complete", "error", "cancel"} {
		t.Run(finish, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var enteredOnce, releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			writerStarted, writerDone := make(chan struct{}), make(chan struct{})
			var wrote bool
			var r *runtimeHarness
			logger := testSurgeLogger(func(entry *log.Entry) {
				if entry.Message != "ready" {
					return
				}
				close(writerStarted)
				go func() {
					defer close(writerDone)
					wrote = r.data.write(t.Context(), testLocalScope, "unrelated", "value", false)
				}()
				<-entered
				if finish == "cancel" {
					cancel()
				}
			})
			r = testRuntime(t, RuntimeOptions{StorePath: filepath.Join(t.TempDir(), "store.json"), Logger: logger})
			if !r.data.write(t.Context(), testDeviceScope, "device", "value", false) {
				t.Fatal("seed device storage")
			}
			r.data.syncDir = func(string) error {
				enteredOnce.Do(func() { close(entered) })
				<-release
				return nil
			}
			source := `console.log("ready"); $done();`
			if finish == "error" {
				source = `console.log("ready"); throw new Error("fixture");`
			}
			done := make(chan struct{})
			var runErr error
			go func() {
				defer close(done)
				result, err := r.Run(ctx, source, Invocation{Scope: testDeviceScope})
				result.Close()
				runErr = err
			}()
			defer func() {
				unblock()
				cancel()
				<-done
				select {
				case <-writerStarted:
					<-writerDone
				default:
				}
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("device cleanup waited for unrelated storage I/O")
			}
			if finish == "complete" && runErr != nil || finish != "complete" && runErr == nil {
				t.Fatalf("completion %s: %v", finish, runErr)
			}
			if finish == "cancel" && !errors.Is(runErr, context.Canceled) {
				t.Fatalf("cancellation: %v", runErr)
			}
			select {
			case <-entered:
			default:
				t.Fatal("script did not overlap the storage write")
			}
			if len(r.data.active) != 0 {
				t.Fatalf("retained device execution: %v", r.data.active)
			}
			unblock()
			<-writerDone
			if !wrote {
				t.Fatal("unrelated write failed")
			}
			if count, err := r.data.migrate(t.Context(), testDeviceScope.MAC, [6]byte{2, 0, 0, 0, 0, 99}); err != nil || count != 1 {
				t.Fatalf("migration after cleanup: count=%d err=%v", count, err)
			}
		})
	}
}
