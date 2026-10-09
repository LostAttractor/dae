// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/plugin"
)

func TestShutdownWatchdog(t *testing.T) {
	for _, stage := range []string{"running", "stopping", "finished", "finished before signal"} {
		t.Run(stage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				forced := false
				stop := watchShutdown(ctx, time.Second, func() { forced = true })
				if stage == "finished before signal" {
					stop()
				}
				if stage != "running" {
					cancel()
				}
				synctest.Wait()
				if stage == "finished" {
					stop()
				}
				time.Sleep(2 * time.Second)
				synctest.Wait()
				if stage == "running" || stage == "stopping" {
					stop()
				}
				if forced != (stage == "stopping") {
					t.Fatalf("forced exit = %v during %s", forced, stage)
				}
			})
		})
	}
}

type shutdownTestPlugin struct {
	blockWorker bool
	release     chan struct{}
	closed      bool
}

func (*shutdownTestPlugin) Plan() plugin.Plan { return plugin.Plan{} }
func (p *shutdownTestPlugin) Run(ctx context.Context, _ *http.Client) error {
	<-ctx.Done()
	if p.blockWorker {
		<-p.release // Simulate cleanup that ignores cancellation.
	}
	return nil
}
func (p *shutdownTestPlugin) Close() error {
	if !p.blockWorker {
		<-p.release
	}
	p.closed = true
	return nil
}

func TestShutdownWatchdogBoundsStuckMITM(t *testing.T) {
	for _, stage := range []string{"worker", "plugin close"} {
		t.Run(stage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := &shutdownTestPlugin{blockWorker: stage == "worker", release: make(chan struct{})}
				host, err := mitm.New(mitm.Options{DrainTimeout: time.Second}, mitm.Instance{Plugin: p})
				if err != nil {
					t.Fatal(err)
				}
				if err := host.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(t.Context())
				forced := false
				stop := watchShutdown(ctx, shutdownTimeout, func() { forced = true })
				defer stop()
				cancel()
				host.Abort()
				closed := make(chan error, 1)
				go func() { closed <- host.Close() }()
				time.Sleep(shutdownTimeout + time.Second)
				synctest.Wait()
				if !forced || p.closed {
					t.Errorf("forced exit = %v, plugin closed = %v", forced, p.closed)
				}
				select {
				case <-closed:
					close(p.release)
					t.Fatal("shared state could be retired while plugin cleanup was still running")
				default:
				}
				close(p.release)
				if err := <-closed; err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}
