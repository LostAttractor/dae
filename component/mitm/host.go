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

	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
	logrus "github.com/sirupsen/logrus"
)

type DialContext func(context.Context, string, string) (net.Conn, error)

// Load validates the complete configuration before preparing any plugin. Failed
// preparation releases the instances created by this call.
func Load(ctx context.Context, definitions map[string]plugin.Definition, specs []plugin.Spec, options Options, services plugin.Services) (_ *Host, err error) {
	if err := plugin.ValidateSpecs(definitions, specs); err != nil {
		return nil, err
	}
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
		setup := definitions[spec.Type].Setup
		local := services
		if local.Logger == nil {
			local.Logger = logrus.NewEntry(logrus.StandardLogger())
		}
		local.Logger = local.Logger.WithField("plugin_instance", spec.ID)
		implementation, err := setup(ctx, spec, local)
		if err != nil {
			return nil, fmt.Errorf("plugins.%s: %w", spec.ID, err)
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
	DisableHTTP       bool
	BufferMemoryLimit int64
	Authority         *mitmca.Authority
	UpstreamTLSConfig *tls.Config
	Logger            *logrus.Entry
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
	connections  map[io.Closer]func(context.Context) error
	forceContext context.Context
	forceCancel  context.CancelFunc
	closeDone    chan struct{}
	closeErr     error
	memoryLimit  *membuffer.Limit
}

// New takes ownership of the instances and their plans on success. Plans remain read-only
// for the lifetime of the host; construction is the only mutation phase.
func New(options Options, instances ...Instance) (*Host, error) {
	if options.BufferMemoryLimit < 0 {
		return nil, errors.New("mitm: buffer memory limit must be positive")
	}
	if options.BufferMemoryLimit == 0 {
		options.BufferMemoryLimit = plugin.DefaultBufferMemoryLimit
	}
	if options.Logger == nil {
		options.Logger = logrus.NewEntry(logrus.StandardLogger())
	}
	options.Logger = options.Logger.WithField("component", "mitm")
	if options.DrainTimeout <= 0 {
		options.DrainTimeout = 5 * time.Second
	}
	h := &Host{options: options, instances: instances, connections: make(map[io.Closer]func(context.Context) error), closeDone: make(chan struct{})}
	for i := range h.instances {
		instance := &h.instances[i]
		instance.plan = instance.Plugin.Plan()
		if options.DisableHTTP {
			instance.plan.Scopes = nil
		}
		h.plan.DNS = append(h.plan.DNS, instance.plan.DNS...)
		h.plan.Scopes = append(h.plan.Scopes, instance.plan.Scopes...)
		h.plan.Destinations = append(h.plan.Destinations, instance.plan.Destinations...)
		h.plan.EarlyRoutes = append(h.plan.EarlyRoutes, instance.plan.EarlyRoutes...)
		h.plan.Routes = append(h.plan.Routes, instance.plan.Routes...)
	}
	if len(h.plan.Scopes) > 0 && options.Authority == nil {
		return nil, errors.New("mitm: HTTPS scopes require ca_cert and ca_key")
	}
	h.forceContext, h.forceCancel = context.WithCancel(context.Background())
	h.memoryLimit = plugin.BodyMemory.UseLimit(options.BufferMemoryLimit)
	return h, nil
}

func (h *Host) Authority() *mitmca.Authority { return h.options.Authority }

// Plan returns the read-only construction result.
func (h *Host) Plan() plugin.Plan { return h.plan }

type HTTPMode uint8

const (
	HTTPBypass HTTPMode = iota
	HTTPInspect
	HTTPRequest
)

// Match classifies once. A request-transforming scope takes precedence when
// several plugins match the same connection; exclusions remain scope-local.
func (h *Host) Match(host string, port uint16) HTTPMode {
	mode := HTTPBypass
	for _, scope := range h.plan.Scopes {
		if !scope.Match(host, port) {
			continue
		}
		if !scope.PreserveRoute {
			return HTTPRequest
		}
		mode = HTTPInspect
	}
	return mode
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
			if err := worker.Run(ctx, h.options.HTTPClient); err != nil && ctx.Err() == nil {
				h.options.Logger.WithField("plugin_instance", instance.ID).WithError(resource.RedactError(err)).Error("Plugin worker stopped")
			}
		}()
	}
	return nil
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
		httpPlugin, ok := instance.Plugin.(plugin.HTTPPlugin)
		if !ok {
			continue
		}
		terminal = httpPlugin.Wrap(flow, func(e *plugin.Exchange) (*http.Response, error) {
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
