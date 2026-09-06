// SPDX-License-Identifier: AGPL-3.0-only

package surgemodule

import (
	"context"
	"errors"
	"net/http"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// Plan exports one complete compatibility engine as one host plugin. Modules
// remain inside this engine, preserving their per-direction first-script rule.
func (e *Engine) Plan() mitm.Plan {
	plan := mitm.Plan{Destinations: e.DestinationRewrites()}
	for _, m := range e.options.Modules {
		if len(m.Hostnames) > 0 {
			plan.Scopes = append(plan.Scopes, mitm.Scope{Hostnames: append([]string(nil), m.Hostnames...)})
		}
	}
	for _, rule := range e.ModuleRules() {
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
	return plan
}

func (e *Engine) Wrap(flow mitm.Flow, next mitm.Handler) mitm.Handler {
	e = e.forConnection(flow.Host, flow.Port)
	return func(exchange *mitm.Exchange) (response *http.Response, err error) {
		r := exchange.Request
		connection, request := mitm.IDs(r.Context())
		ctx := context.WithValue(context.WithValue(r.Context(), connectionIDKey{}, connection), requestIDKey{}, request)
		r = r.WithContext(ctx)
		exchange.Request = r
		e.traceRequest(r, "request_begin", "protocol", r.Proto)
		response, err = e.processRequest(r, exchange.Client, exchange.Controller)
		if err == nil && response != nil {
			e.traceRequest(r, "response_local", "status", response.StatusCode)
			return response, nil
		}
		if err == nil {
			e.traceRequest(r, "request_forward")
			response, err = next(exchange)
			if err == nil && response == nil {
				err = errors.New("mitm: next returned a nil response")
			}
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
			err = mitm.ErrAbort
		} else if errors.Is(err, errBodyTooLarge) {
			err = &mitm.HTTPError{Status: http.StatusRequestEntityTooLarge, Err: err}
		}
		if err != nil {
			e.traceRequest(r, "request_failed", "reason", traceErrorReason(err))
			e.logRequest(r, "surge processing: "+err.Error())
		}
		return response, err
	}
}
