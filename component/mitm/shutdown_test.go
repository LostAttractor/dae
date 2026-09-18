// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"sync"
	"testing"
	"time"
)

type shutdownCloser func() error

func (c shutdownCloser) Close() error { return c() }

func TestAbortClosesAllConnectionsWithoutGracePeriod(t *testing.T) {
	host := testHost(t, Options{DrainTimeout: time.Hour})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	started := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	for i := range started {
		once := sync.OnceFunc(func() { close(started[i]) })
		// Each Close needs its peer to start closing. Serial closure deadlocks.
		conn := new(shutdownCloser(func() error {
			once()
			select {
			case <-started[1-i]:
			case <-release:
			}
			return nil
		}))
		if err := host.track(conn); err != nil {
			t.Fatal(err)
		}
		if err := host.attach(conn, func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }); err != nil {
			t.Fatal(err)
		}
		go func() { <-started[i]; host.untrack(conn) }()
	}
	host.Abort()
	closed := make(chan error, 1)
	go func() { closed <- host.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("a blocked Close prevented another connection from being interrupted")
	}
}
