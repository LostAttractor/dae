// SPDX-License-Identifier: AGPL-3.0-only

// Package pluginhost owns protocol-independent plugin instances and workers.
package pluginhost

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

// Instance is shared by protocol hosts while their requests drain. Every host
// owns one reference; an instance's worker runs once, independently of any host.
type Instance struct {
	ID, Type string
	Plugin   plugin.Plugin
	Plan     plugin.Plan
	Metrics  *prometheus.Registry

	input   instanceInput
	mu      sync.Mutex
	refs    int
	active  int
	started time.Time
	cancel  context.CancelFunc
	done    chan struct{}
	logger  *log.Entry
}

func Adopt(id, typ string, implementation plugin.Plugin) *Instance {
	return &Instance{ID: id, Type: typ, Plugin: implementation, Plan: implementation.Plan(), refs: 1,
		logger: log.WithField("plugin_instance", id)}
}

// Retain acquires one protocol host reference while the instance is live.
func (i *Instance) Retain() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.refs == 0 {
		return false
	}
	i.refs++
	return true
}

func (i *Instance) Activate(client *http.Client) (time.Time, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.refs == 0 || i.active == 0 && i.cancel != nil {
		return time.Time{}, net.ErrClosed
	}
	i.active++
	if !i.started.IsZero() {
		return i.started, nil
	}
	i.started = time.Now()
	if worker, ok := i.Plugin.(plugin.Worker); ok {
		ctx, cancel := context.WithCancel(context.Background())
		i.cancel, i.done = cancel, make(chan struct{})
		go func() {
			defer close(i.done)
			if err := worker.Run(ctx, client); err != nil && ctx.Err() == nil {
				i.logger.WithError(resource.RedactError(err)).Error("Plugin worker stopped")
			}
		}()
	}
	return i.started, nil
}

// Deactivate stops a worker only after its final active host is replaced.
// Request draining and the final Close are handled by Release.
func (i *Instance) Deactivate() {
	i.mu.Lock()
	i.active--
	if i.active == 0 && i.cancel != nil {
		i.cancel()
	}
	i.mu.Unlock()
}

func (i *Instance) Release() error {
	i.mu.Lock()
	i.refs--
	last := i.refs == 0
	if last && i.cancel != nil {
		i.cancel()
	}
	done := i.done
	i.mu.Unlock()
	if !last {
		return nil
	}
	if done != nil {
		<-done
	}
	if closer, ok := i.Plugin.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
