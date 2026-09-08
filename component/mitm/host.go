// SPDX-License-Identifier: AGPL-3.0-only

// Package mitm hosts compiled Go HTTP plugins. Transport and
// connection ownership belong to the host; plugins contribute immutable plans.
package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/mitm/plugin"
	logrus "github.com/sirupsen/logrus"
)

type DialContext func(context.Context, string, string) (net.Conn, error)

// Load prepares every configured plugin before constructing its host. Failed
// preparation releases the instances created by this call.
func Load(ctx context.Context, setups map[string]plugin.Setup, specs []plugin.Spec, options Options, services plugin.Services) (_ *Host, err error) {
	var instances []Instance
	defer func() {
		if err != nil {
			for i := len(instances) - 1; i >= 0; i-- {
				if c, ok := instances[i].Plugin.(io.Closer); ok {
					_ = c.Close()
				}
			}
		}
	}()
	for _, spec := range specs {
		setup := setups[spec.Type]
		if setup == nil {
			return nil, fmt.Errorf("mitm.%s: plugin type %q is not compiled into this binary", spec.ID, spec.Type)
		}
		local := services
		if local.Logger == nil {
			local.Logger = logrus.NewEntry(logrus.StandardLogger())
		}
		local.Logger = local.Logger.WithField("mitm_instance", spec.ID)
		implementation, err := setup(ctx, spec, local)
		if err != nil {
			return nil, fmt.Errorf("mitm.%s: %w", spec.ID, err)
		}
		instances = append(instances, Instance{ID: spec.ID, Type: spec.Type, Plugin: implementation})
	}
	return New(options, instances...)
}

type Instance struct {
	ID, Type string
	Plugin   plugin.Plugin
	plan     plugin.Plan
}
type Options struct {
	Authority         *mitmca.Authority
	UpstreamTLSConfig *tls.Config
	Log               func(string)
	DrainTimeout      time.Duration
	// HTTPClient is passed to workers only after activation.
	HTTPClient *http.Client
}
type Host struct {
	options      Options
	instances    []Instance
	plan         plugin.Plan
	mu           sync.Mutex
	cancel       context.CancelFunc
	closed       bool
	workers      sync.WaitGroup
	requests     sync.WaitGroup
	serving      sync.WaitGroup
	connections  map[net.Conn]*http.Server
	forceContext context.Context
	forceCancel  context.CancelFunc
	closeDone    chan struct{}
	closeErr     error
}

// New takes ownership of the instances and their plans on success. Plans remain read-only
// for the lifetime of the host; construction is the only mutation phase.
func New(options Options, instances ...Instance) (*Host, error) {
	if options.DrainTimeout <= 0 {
		options.DrainTimeout = 5 * time.Second
	}
	h := &Host{options: options, instances: instances, connections: make(map[net.Conn]*http.Server), closeDone: make(chan struct{})}
	for i := range h.instances {
		instance := &h.instances[i]
		instance.plan = instance.Plugin.Plan()
		h.plan.Scopes = append(h.plan.Scopes, instance.plan.Scopes...)
		h.plan.Destinations = append(h.plan.Destinations, instance.plan.Destinations...)
		h.plan.EarlyRoutes = append(h.plan.EarlyRoutes, instance.plan.EarlyRoutes...)
		h.plan.Routes = append(h.plan.Routes, instance.plan.Routes...)
	}
	if len(h.plan.Scopes) > 0 && options.Authority == nil {
		return nil, errors.New("mitm: HTTPS scopes require ca_cert and ca_key")
	}
	h.forceContext, h.forceCancel = context.WithCancel(context.Background())
	return h, nil
}

func (h *Host) Authority() *mitmca.Authority { return h.options.Authority }

// Plan returns the read-only construction result.
func (h *Host) Plan() plugin.Plan { return h.plan }
func (h *Host) Match(host string, port uint16) bool {
	for _, i := range h.instances {
		for _, s := range i.plan.Scopes {
			if s.Match(host, port) {
				return true
			}
		}
	}
	return false
}
func (h *Host) Start(parent context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return net.ErrClosed
	}
	if h.cancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(parent)
	h.cancel = cancel
	for _, instance := range h.instances {
		worker, ok := instance.Plugin.(plugin.Worker)
		if !ok {
			continue
		}
		h.workers.Add(1)
		go func() {
			defer h.workers.Done()
			if err := worker.Run(ctx, h.options.HTTPClient); err != nil && ctx.Err() == nil && h.options.Log != nil {
				h.options.Log(fmt.Sprintf("mitm.%s: worker stopped: %v", instance.ID, err))
			}
		}()
	}
	return nil
}
func (h *Host) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		<-h.closeDone
		return h.closeErr
	}
	h.closed = true
	if h.cancel != nil {
		h.cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), h.options.DrainTimeout)
	defer cancel()
	var shutdowns sync.WaitGroup
	for conn, server := range h.connections {
		if server == nil {
			_ = conn.Close()
		} else {
			shutdowns.Add(1)
			go func() { defer shutdowns.Done(); _ = server.Shutdown(ctx) }()
		}
	}
	h.mu.Unlock()
	finished := make(chan error, 1)
	go func() {
		h.workers.Wait()
		shutdowns.Wait()
		h.serving.Wait()
		h.requests.Wait()
		var errs []error
		for i := len(h.instances) - 1; i >= 0; i-- {
			if c, ok := h.instances[i].Plugin.(io.Closer); ok {
				errs = append(errs, c.Close())
			}
		}
		finished <- errors.Join(errs...)
	}()
	select {
	case h.closeErr = <-finished:
	case <-ctx.Done():
		h.closeErr = fmt.Errorf("mitm: drain deadline exceeded: %w", ctx.Err())
	}
	h.forceCancel()
	h.mu.Lock()
	for conn := range h.connections {
		_ = conn.Close()
	}
	h.mu.Unlock()
	close(h.closeDone)
	return h.closeErr
}

func (h *Host) chain(flow plugin.Flow, terminal plugin.Handler) plugin.Handler {
	instances := h.instances
	for i := len(instances) - 1; i >= 0; i-- {
		instance := instances[i]
		matches := false
		for _, scope := range instance.plan.Scopes {
			if scope.Match(flow.Host, flow.Port) {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		next := terminal
		terminal = instance.Plugin.Wrap(flow, func(e *plugin.Exchange) (*http.Response, error) {
			// A plugin's read budget ends when it hands the request downstream,
			// before another plugin buffers it or the transport streams it.
			if e.SetReadDeadline != nil {
				_ = e.SetReadDeadline(time.Time{})
			}
			response, err := next(e)
			if response != nil {
				// Local responses need the same request association as RoundTrip
				// responses before an outer plugin can inspect or rewrite them.
				response.Request = e.Request
			}
			return response, err
		})
	}
	return terminal
}
