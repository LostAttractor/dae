// SPDX-License-Identifier: AGPL-3.0-only

// Package mitm hosts HTTP and DNS execution for plugin instances. The host owns
// protocol connections; instances contribute immutable plans and middleware.
package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/pluginhost"
	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/prometheus/client_golang/prometheus"
	logrus "github.com/sirupsen/logrus"
)

type DialContext func(context.Context, string, string) (net.Conn, error)

// Load prepares plugin instances independently of the protocol host. The prior
// host is read-only during preparation; unchanged instances retain their state.
func Load(ctx context.Context, configuration *pluginhost.Configuration, options Options, services plugin.Services, previous *Host) (*Host, error) {
	if previous != nil && options.Authority != nil && previous.Authority() != nil && options.Authority.Fingerprint() == previous.Authority().Fingerprint() {
		options.Authority = previous.Authority()
	}
	services.BodyMemory = options.bodyMemory()
	instances, err := configuration.Prepare(ctx, services, previous.Instances())
	if err != nil {
		return nil, err
	}
	if len(instances) == 0 && options.Diagnostic == nil {
		return nil, nil
	}
	local := make([]Instance, 0, len(instances))
	for _, instance := range instances {
		local = append(local, Instance{ID: instance.ID, Type: instance.Type, Plugin: instance.Plugin, owner: instance})
	}
	if options.Diagnostic != nil {
		local = append([]Instance{{ID: "dae-certificate-test", Type: "certificate-test", Plugin: options.Diagnostic}}, local...)
	}
	host, err := New(options, local...)
	if err != nil {
		for _, instance := range instances {
			err = errors.Join(err, instance.Release())
		}
	}
	return host, err
}

type Instance struct {
	ID, Type string
	Plugin   plugin.Plugin
	plan     plugin.Plan
	owner    *pluginhost.Instance
}

// PrepareSuccessor retains accepted instances and certificate state for suspend,
// which changes interception without refreshing external configuration inputs.
func (h *Host) PrepareSuccessor() (*Host, error) {
	if h == nil {
		return nil, nil
	}
	instances := slices.Clone(h.instances)
	for n, instance := range instances {
		if !instance.owner.Retain() {
			for _, retained := range instances[:n] {
				_ = retained.owner.Release()
			}
			return nil, net.ErrClosed
		}
	}
	next, err := New(h.options, instances...)
	if err != nil {
		for _, instance := range instances {
			err = errors.Join(err, instance.owner.Release())
		}
	}
	return next, err
}

type Options struct {
	Diagnostic        plugin.Plugin
	DisableHTTP       bool
	BufferMemoryLimit int64
	BodyMemory        *membuffer.Budget
	Authority         *mitmca.Authority
	UpstreamTLSConfig *tls.Config
	Logger            *logrus.Entry
	DrainTimeout      time.Duration
	// HTTPClient is passed to workers only after activation.
	HTTPClient *http.Client
	// Metrics is the process-level gatherer receiving this host on Start.
	Metrics *Metrics
}
type Host struct {
	options          Options
	instances        []Instance
	plan             plugin.Plan
	diagnosticScopes []plugin.HTTPScope
	mu               sync.Mutex
	started          bool
	closed           bool
	workersStopped   bool
	requests         sync.WaitGroup
	serving          sync.WaitGroup
	connections      map[io.Closer]func(context.Context) error
	forceContext     context.Context
	forceCancel      context.CancelFunc
	closeDone        chan struct{}
	closeErr         error
	memoryLimit      *membuffer.Limit
	metrics          *prometheus.Registry
	startedAt        *prometheus.GaugeVec
}

func (h *Host) Instances() []*pluginhost.Instance {
	if h == nil {
		return nil
	}
	instances := make([]*pluginhost.Instance, 0, len(h.instances))
	for _, instance := range h.instances {
		instances = append(instances, instance.owner)
	}
	return instances
}

// SameInstances compares runtime identities, not merely plugin declarations.
func (h *Host) SameInstances(other *Host) bool {
	if h == nil || other == nil {
		return h == other
	}
	if len(h.instances) != len(other.instances) {
		return false
	}
	for i := range h.instances {
		if h.instances[i].owner != other.instances[i].owner {
			return false
		}
	}
	return true
}

func (h *Host) SameRuntime(other *Host) bool {
	if h == nil || other == nil {
		return h == other
	}
	if !h.SameInstances(other) {
		return false
	}
	if h.options.DisableHTTP != other.options.DisableHTTP || h.options.BufferMemoryLimit != other.options.BufferMemoryLimit {
		return false
	}
	first, second := h.Authority(), other.Authority()
	if first == nil || second == nil {
		return first == second
	}
	return first.Fingerprint() == second.Fingerprint()
}

// New takes ownership of the instances and their plans on success. Plans remain read-only
// for the lifetime of the host; construction is the only mutation phase.
func New(options Options, instances ...Instance) (*Host, error) {
	if options.BufferMemoryLimit < 0 {
		return nil, errors.New("mitm: buffer memory limit must be positive")
	}
	if options.BufferMemoryLimit == 0 {
		options.BufferMemoryLimit = defaultBufferMemoryLimit
	}
	if options.Logger == nil {
		options.Logger = logrus.NewEntry(logrus.StandardLogger())
	}
	options.Logger = options.Logger.WithField("component", "mitm")
	if options.DrainTimeout <= 0 {
		options.DrainTimeout = 5 * time.Second
	}
	h := &Host{options: options, instances: instances, connections: make(map[io.Closer]func(context.Context) error), closeDone: make(chan struct{})}
	if options.Diagnostic != nil {
		h.diagnosticScopes = options.Diagnostic.Plan().Scopes
	}
	for i := range h.instances {
		instance := &h.instances[i]
		if instance.owner == nil {
			instance.owner = pluginhost.Adopt(instance.ID, instance.Type, instance.Plugin)
		}
		instance.plan = instance.owner.Plan
		if options.DisableHTTP {
			instance.plan.Scopes = nil
		}
		h.plan.DNS = append(h.plan.DNS, instance.plan.DNS...)
		h.plan.RequiredOutbounds = append(h.plan.RequiredOutbounds, instance.plan.RequiredOutbounds...)
		h.plan.Scopes = append(h.plan.Scopes, instance.plan.Scopes...)
		h.plan.Destinations = append(h.plan.Destinations, instance.plan.Destinations...)
		h.plan.EarlyRoutes = append(h.plan.EarlyRoutes, instance.plan.EarlyRoutes...)
		h.plan.Routes = append(h.plan.Routes, instance.plan.Routes...)
	}
	if len(h.plan.Scopes) > 0 && options.Authority == nil {
		return nil, errors.New("mitm: HTTPS scopes require ca_cert and ca_key")
	}
	registry := prometheus.NewRegistry()
	h.metrics = registry
	h.startedAt = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dae_plugin_instance_start_time_seconds",
		Help: "Activation time of the current plugin instance as Unix seconds. Instance counters reset on reconstruction.",
	}, []string{"plugin_type", "plugin_instance"})
	registry.MustRegister(h.startedAt)
	for i := range h.instances {
		instance := &h.instances[i]
		if instance.owner.Metrics != nil {
			if err := registry.Register(instance.owner.Metrics); err != nil {
				return nil, fmt.Errorf("plugin metrics: %w", err)
			}
		}
	}
	h.forceContext, h.forceCancel = context.WithCancel(context.Background())
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

// Match classifies a host/port. A request-transforming scope takes precedence
// when several plugins match; exclusions remain scope-local.
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
	if h.started {
		return nil
	}
	if err := parent.Err(); err != nil {
		return err
	}
	h.memoryLimit = h.options.bodyMemory().UseLimit(h.options.BufferMemoryLimit)
	for i, instance := range h.instances {
		started, err := instance.owner.Activate(h.options.HTTPClient)
		if err != nil {
			for _, activated := range h.instances[:i] {
				activated.owner.Deactivate()
			}
			h.memoryLimit.Close()
			h.memoryLimit = nil
			return err
		}
		h.startedAt.WithLabelValues(instance.Type, instance.ID).Set(float64(started.UnixNano()) / 1e9)
	}
	h.started = true
	h.options.Metrics.publish(h.metrics)
	return nil
}

// StopWorkers retires this host's worker ownership without interrupting its
// protocol requests. Shared instances remain active through their successor.
func (h *Host) StopWorkers() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stopWorkersLocked()
}

func (h *Host) stopWorkersLocked() {
	if !h.started || h.workersStopped {
		return
	}
	h.workersStopped = true
	for _, instance := range h.instances {
		instance.owner.Deactivate()
	}
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
				// Every response hook sees its business request, including local
				// responses and transports using an ingress-bound request copy.
				response.Request = e.Request
			}
			return response, err
		})
	}
	return terminal
}
