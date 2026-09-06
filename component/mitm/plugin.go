// SPDX-License-Identifier: AGPL-3.0-only

// Package mitm hosts statically registered Go HTTP plugins. Transport and
// connection ownership belong to the host; plugins contribute immutable plans.
package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/mitmca"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type DialContext func(context.Context, string, string) (net.Conn, error)

type Flow struct {
	Host                string
	Port                uint16
	Source, Destination netip.AddrPort
}

// Exchange belongs to one synchronous invocation. Background work must copy
// the required data instead of retaining the request, body or response writer.
type Exchange struct {
	Request    *http.Request
	Client     *http.Client
	Controller *http.ResponseController
}

// Handler transfers response body ownership to its caller. Middleware calls
// next synchronously and closes its response body if later processing fails.
type Handler func(*Exchange) (*http.Response, error)

type Plan struct {
	Scopes              []Scope
	Destinations        routing.DestinationRewrites
	EarlyRoutes, Routes []*config_parser.RoutingRule
}

type Scope struct{ Hostnames []string }

func (s Scope) Match(host string, port uint16) bool {
	if host == "" {
		return false
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, pattern := range s.Hostnames {
		deny := strings.HasPrefix(pattern, "-")
		pattern = strings.TrimPrefix(pattern, "-")
		name, wanted := pattern, uint16(443)
		if h, p, err := net.SplitHostPort(pattern); err == nil {
			name = h
			n, err := strconv.ParseUint(p, 10, 16)
			if err != nil {
				continue
			}
			wanted = uint16(n)
		} else if strings.Contains(pattern, ":") {
			continue

		}
		if port != 80 && wanted != 0 && port != wanted {
			continue
		}
		if glob(strings.TrimSuffix(strings.ToLower(name), "."), host) {
			return !deny
		}
	}
	return false
}

func glob(pattern, value string) bool {
	p, v, star, back := 0, 0, -1, 0
	for v < len(value) {
		if p < len(pattern) && (pattern[p] == '?' || pattern[p] == value[v]) {
			p++
			v++
			continue
		}
		if p < len(pattern) && pattern[p] == '*' {
			star = p
			p++
			back = v
			continue
		}
		if star < 0 {
			return false
		}
		p = star + 1
		back++
		v = back
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

type Plugin interface {
	Plan() Plan
	Wrap(Flow, Handler) Handler
}

// Worker runs only after activation. It must stop when ctx is canceled.
type Worker interface {
	Run(context.Context, *http.Client) error
}
type Closer interface{ Close() error }

type Spec struct {
	ID, Type string
	Config   *config_parser.Section
}
type Services struct {
	HTTPClient *http.Client

	Log func(string)
}
type Factory func(context.Context, Spec, Services) (Plugin, error)

// Register is called by statically linked plugin packages during init.
var registry = make(map[string]Factory)

func Register(name string, factory Factory) {
	if name == "" || factory == nil || registry[name] != nil {
		panic("mitm: invalid or duplicate plugin registration: " + name)
	}
	registry[name] = factory
}

// Load prepares every configured plugin before constructing its host. Failed
// preparation releases the instances created by this call.
func Load(ctx context.Context, specs []Spec, options Options, services Services) (_ *Host, err error) {
	var instances []Instance
	defer func() {
		if err != nil {
			for i := len(instances) - 1; i >= 0; i-- {
				if c, ok := instances[i].Plugin.(Closer); ok {
					_ = c.Close()
				}
			}
		}
	}()
	for _, spec := range specs {
		factory := registry[spec.Type]
		if factory == nil {
			return nil, fmt.Errorf("mitm.%s: plugin type %q is not compiled into this binary", spec.ID, spec.Type)
		}
		local := services
		if services.Log != nil {
			local.Log = func(message string) { services.Log("mitm." + spec.ID + ": " + message) }
		}
		plugin, err := factory(ctx, spec, local)
		if err != nil {
			return nil, fmt.Errorf("mitm.%s: %w", spec.ID, err)
		}
		instances = append(instances, Instance{ID: spec.ID, Type: spec.Type, Plugin: plugin})
	}
	return New(options, instances...)
}

type Instance struct {
	ID, Type string
	Plugin   Plugin
	plan     Plan
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
	plan         Plan
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
	names := make(map[string]bool)
	for i := range h.instances {
		instance := &h.instances[i]
		if names[instance.ID] {
			return nil, fmt.Errorf("mitm: duplicate instance %q", instance.ID)
		}
		names[instance.ID] = true
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

// Instances and Plan expose read-only construction results.
func (h *Host) Instances() []Instance { return h.instances }
func (h *Host) Plan() Plan            { return h.plan }
func (h *Host) Match(host string, port uint16) bool {
	for _, i := range h.Instances() {
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
		worker, ok := instance.Plugin.(Worker)
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
			if c, ok := h.instances[i].Plugin.(Closer); ok {
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

func (h *Host) chain(flow Flow, terminal Handler) Handler {
	instances := h.Instances()
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
		terminal = instance.Plugin.Wrap(flow, terminal)
	}
	return terminal
}
