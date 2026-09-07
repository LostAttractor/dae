// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"errors"
	"net/http"
	"time"

	"github.com/daeuniverse/dae/component/mitm/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type EngineOptions struct {
	Modules []*Module

	Runtime              *Runtime
	MaxBodySize          int64
	MaxConcurrentScripts int
	ScriptTimeout        time.Duration
	Log                  func(string)
	// Trace receives automatic diagnostics concurrently from connections. A nil
	// callback disables tracing. TraceEnabled optionally avoids formatting when
	// the daemon's current log level filters out these diagnostics.
	Trace        func(string)
	TraceEnabled func() bool
}

// Engine applies module rules to intercepted HTTP connections. Client selection
// and outbound routing are decided by the caller before invoking the plugin.
type Engine struct {
	options EngineOptions
	slots   chan struct{}
}

func NewEngine(o EngineOptions) (*Engine, error) {
	for _, module := range o.Modules {
		if _, err := moduleScope(module.Hostnames); err != nil {
			return nil, err
		}
		if len(module.Scripts) != 0 && o.Runtime == nil {
			return nil, errors.New("surge: HTTP scripts require a QuickJS runtime")
		}
	}
	if o.MaxBodySize <= 0 || o.MaxConcurrentScripts <= 0 || o.ScriptTimeout <= 0 {
		return nil, errors.New("surge: positive body, concurrency and timeout limits are required")
	}
	return &Engine{options: o, slots: make(chan struct{}, o.MaxConcurrentScripts)}, nil
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

func (e *Engine) log(message string) {
	if e.options.Log != nil {
		e.options.Log(message)
	}
}

// Plan exports one complete compatibility engine as one host plugin. Modules
// remain inside this engine, preserving their per-direction first-script rule.
func (e *Engine) Plan() plugin.Plan {
	var plan plugin.Plan
	for _, module := range e.options.Modules {
		if len(module.Hostnames) > 0 {
			scope, _ := moduleScope(module.Hostnames) // validated by NewEngine
			plan.Scopes = append(plan.Scopes, scope)
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
					plan.EarlyRoutes = append(plan.EarlyRoutes, r)
				} else {
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
		response, err = e.processRequest(r, exchange.Client, exchange.SetReadDeadline)
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
				if err != nil && response.Body != nil {
					_ = response.Body.Close()
					response = nil
				}
			}
		}
		if errors.Is(err, errScriptAbort) {
			err = plugin.ErrAbort
		} else if errors.Is(err, errBodyTooLarge) {
			err = &plugin.HTTPError{Status: http.StatusRequestEntityTooLarge, Err: err}
		}
		if err != nil {
			e.traceRequest(r, "request_failed", "reason", traceErrorReason(err))
			e.logRequest(r, "surge processing: "+err.Error())
		}
		return response, err
	}
}
