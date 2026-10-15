// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/daeuniverse/dae/plugins/surge/internal/jq"
	log "github.com/sirupsen/logrus"
)

type EngineOptions struct {
	Modules      []*Module
	HTTPPolicies []string

	// BodyMemory is supplied by the host, shared across instances and reloads.
	BodyMemory           *membuffer.Budget
	Runtime              *Runtime
	MaxBodySize          int64
	MaxConcurrentScripts int
	ScriptTimeout        time.Duration
	Logger               *log.Entry
}

// Engine applies module rules to intercepted traffic and runs background script tasks.
// Client selection and outbound routing are supplied by the host.
// Engines must be initialized with NewEngine.
type Engine struct {
	options        EngineOptions
	slots          chan struct{}
	metrics        *engineMetrics
	tasks          *taskRunner
	dnsCache       *dnsScriptCache
	resourceStatus *atomic.Pointer[resourceStatus]
	releaseJQ      func() error
}

func NewEngine(o EngineOptions) (*Engine, error) {
	return newEngine(context.Background(), o)
}

func newEngine(ctx context.Context, o EngineOptions) (_ *Engine, err error) {
	o.Modules = slices.Clone(o.Modules)
	for i, module := range o.Modules {
		scope, err := moduleScope(module.Hostnames)
		if err != nil {
			return nil, err
		}
		prepared := *module
		prepared.scope = &scope
		o.Modules[i] = &prepared
		if len(module.Scripts)+len(module.TaskScripts) != 0 && o.Runtime == nil {
			return nil, errors.New("surge: scripts require a JavaScript runtime")
		}
	}
	if o.MaxBodySize <= 0 || o.MaxConcurrentScripts <= 0 || o.ScriptTimeout <= 0 {
		return nil, errors.New("surge: positive body, concurrency and timeout limits are required")
	}
	if o.BodyMemory == nil {
		return nil, errors.New("surge: body memory budget is required")
	}
	e := &Engine{options: o, slots: make(chan struct{}, o.MaxConcurrentScripts), dnsCache: &dnsScriptCache{}}
	defer func() {
		if err != nil && e.releaseJQ != nil {
			_ = e.releaseJQ()
		}
	}()
	for _, module := range o.Modules {
		if slices.ContainsFunc(module.BodyRewrites, func(rule BodyRewrite) bool { return rule.expression != "" }) {
			pool, release, err := jq.Acquire()
			if err != nil {
				return nil, err
			}
			e.releaseJQ = release
			e.options.Modules, err = prepareBodyRewrites(ctx, o.Modules, pool)
			if err != nil {
				return nil, err
			}
			break
		}
	}
	e.resourceStatus = new(atomic.Pointer[resourceStatus])
	e.AcceptResources(e.options.Modules)
	e.tasks, err = newTaskRunner(e)
	if err != nil {
		return nil, err
	}
	e.metrics = newEngineMetrics(e)
	return e, nil
}

// Close releases the runtime after the host has drained scripts and workers.
func (e *Engine) Close() error {
	var err error
	if e.releaseJQ != nil {
		err = e.releaseJQ()
	}
	return errors.Join(err, e.options.Runtime.Close())
}

func prepareBodyRewrites(parent context.Context, modules []*Module, pool *jq.Pool) ([]*Module, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	prepared := make([]*Module, 0, len(modules))
	for _, module := range modules {
		copy := *module
		copy.BodyRewrites = nil
		copy.Warnings = slices.Clone(module.Warnings)
		for _, rule := range module.BodyRewrites {
			if rule.expression != "" {
				if err := pool.Validate(ctx, rule.expression); err != nil {
					if !errors.Is(err, jq.ErrExpression) {
						return nil, err
					}
					copy.Warnings = append(copy.Warnings, fmt.Sprintf("invalid Body Rewrite jq expression for %q is ignored: %v", rule.Pattern, err))
					continue
				}
				rule.jq = pool
			}
			copy.BodyRewrites = append(copy.BodyRewrites, rule)
		}
		prepared = append(prepared, &copy)
	}
	return prepared, nil
}

// forConnection fixes HTTP processing to modules that allow the intercepted
// destination. Rewrites cannot activate a different module by changing URL or
// Host. The connection shares the engine's runtime and concurrency limit.
func (e *Engine) forConnection(host string, port uint16) *Engine {
	scoped := *e
	scoped.options.Modules = nil
	for _, module := range e.options.Modules {
		if module.matchConnection(host, port) {
			scoped.options.Modules = append(scoped.options.Modules, module)
		}
	}
	return &scoped
}

// Plan exports one complete compatibility engine as one host plugin. Modules
// remain inside this engine, preserving their per-direction first-script rule.
func (e *Engine) Plan() plugin.Plan {
	plan := plugin.Plan{RequiredOutbounds: e.options.HTTPPolicies}
	for _, module := range e.options.Modules {
		if len(module.DNSHosts) != 0 {
			plan.DNS = append(plan.DNS, plugin.DNSScope{})
		}
		if len(module.Hostnames) > 0 {
			scope := *module.scope
			// Scripts may issue requests or replace URLs; rewrites and Map Local
			// may finish the request without any upstream connection at all.
			plan.Scopes = append(plan.Scopes, plugin.HTTPScope{
				Scope: scope, PreserveRoute: len(module.Scripts) == 0 && len(module.URLRewrites) == 0 && len(module.MapLocals) == 0,
			})
		}
		plan.Destinations = append(plan.Destinations, module.Hosts...)
		for _, rule := range module.Rules {
			policy := "block"
			if rule.Policy == "DIRECT" {
				policy = "direct"
			}
			for _, clause := range rule.RoutingClauses() {
				r := &config_parser.RoutingRule{Outbound: config_parser.Function{Name: policy}}
				for _, predicate := range clause {
					key, value := predicate.DomainParameter()
					r.AndFunctions = append(r.AndFunctions, &config_parser.Function{Name: "domain", Not: predicate.Not, Params: []*config_parser.Param{{Key: key, Val: value}}})
				}
				if rule.PreMatching {
					r.Sources = []config_parser.RuleSource{{File: module.source, Expression: module.Name + ": " + r.String(false, false, true)}}
					plan.EarlyRoutes = append(plan.EarlyRoutes, r)
				} else {
					r.Sources = []config_parser.RuleSource{{File: module.source, Expression: module.Name + ": " + r.String(false, false, true)}}
					plan.Routes = append(plan.Routes, r)
				}
			}
		}
	}
	return plan
}

func (e *Engine) Wrap(flow plugin.Flow, next plugin.Handler) plugin.Handler {
	e = e.forConnection(flow.Host, flow.Port)
	return func(exchange *plugin.Exchange) (response *http.Response, err error) {
		r := exchange.Request
		e.traceRequest(r, "request_begin", "protocol", r.Proto)
		response, err = e.processRequest(exchange)
		if err != nil {
			e.logRequest(r, "Surge request rewrite failed", err)
		}
		if err == nil && response != nil {
			e.traceRequest(r, "response_local", "status", response.StatusCode)
			return response, nil
		}
		if err == nil {
			e.traceRequest(r, "request_forward")
			response, err = next(exchange)
			if err == nil {
				e.traceRequest(r, "upstream_response", "status", response.StatusCode)
				err = e.processResponse(response, exchange.Client)
				if err != nil {
					e.logRequest(r, "Surge response rewrite failed", err)
				}
				if err != nil && response.Body != nil {
					_ = response.Body.Close()
					response = nil
				}
			}
		}
		if errors.Is(err, errScriptAbort) {
			err = plugin.ErrAbort
		} else if errors.Is(err, membuffer.ErrTooLarge) {
			err = &plugin.HTTPError{Status: http.StatusRequestEntityTooLarge, Err: err}
		}
		if err != nil {
			e.traceRequest(r, "request_failed", "reason", traceErrorReason(err))
		}
		return response, err
	}
}
