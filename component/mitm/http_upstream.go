// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"net/http"
	"sync"

	"github.com/daeuniverse/dae/component/plugin"
)

// upstreamRequest separates the HTTP business authority from the authenticated
// ingress. Only a URL scheme/host/port rewrite changes the network target.
// Plugins keep their business URL; the transport copy shares Body and Trailer.
func upstreamRequest(r *http.Request, scheme string, incoming, original plugin.Flow) *http.Request {
	if r.URL.Scheme != scheme || !sameAuthority(r.URL.Host, incoming.Host, incoming.Port, scheme) {
		return r
	}
	upstream := r.WithContext(r.Context())
	upstream.URL = r.URL.Clone()
	if upstream.Host == "" {
		upstream.Host = r.URL.Host
	}
	upstream.URL.Host = (httpAuthority{host: original.Host, port: original.Port}).String()
	return upstream
}

// Select the original route lazily, once per downstream connection. Local
// responses and target rewrites need no original plan. Failed planning can be
// retried. Successful plans stay fixed, but plannedTransport checks their
// lifetime before every pool lookup, including after an unsuccessful dial.
func (h *Host) connectionTransport(scheme string, flow plugin.Flow, planner UpstreamPlanner, packet bool) *plannedTransport {
	var mu sync.Mutex
	var original UpstreamPlan
	transport := h.plannedTransport(planner, packet)
	// Cache only validated selections. Pool lookup checks their lifetime on
	// every use, but need not revalidate an immutable plan's structure.
	selectPlan := transport.plan
	transport.plan = func(r *http.Request) (UpstreamPlan, error) {
		if r.URL.Scheme != scheme || !sameAuthority(r.URL.Host, flow.Host, flow.Port, scheme) {
			return selectPlan(r)
		}
		mu.Lock()
		defer mu.Unlock()
		if err := r.Context().Err(); err != nil {
			return UpstreamPlan{}, err
		}
		if original.Key == "" {
			selected, err := selectPlan(r)
			if err != nil {
				return UpstreamPlan{}, err
			}
			original = selected
		}
		return original, nil
	}
	return transport
}
