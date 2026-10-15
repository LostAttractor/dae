// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/daeuniverse/dae/component/plugin"
)

var dnsSerial atomic.Uint64

// HandleDNS shares the plugin lifecycle with HTTP. The terminal is the core's
// transparent relay; protocol-aware upstream querying belongs to plugins.
func (h *Host) HandleDNS(ctx context.Context, request *plugin.DNSExchange, terminal plugin.DNSHandler, finalize func(*plugin.DNSResponse) error) (*plugin.DNSResponse, error) {
	if h == nil {
		response, err := terminal(ctx, request)
		if err == nil && response != nil {
			err = finalize(response)
		}
		return response, err
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, net.ErrClosed
	}
	h.requests.Add(1)
	h.mu.Unlock()
	defer h.requests.Done()
	// An unchanged cache instance can be shared with a new DNS chain. Keep
	// their answers separate, including observers invoked by the finalizer.
	previousContext := request.ContextKey
	request.ContextKey = h.dnsContext + previousContext
	defer func() { request.ContextKey = previousContext }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(h.forceContext, cancel)
	defer stop()
	request.Resolve = nil
	for _, instance := range h.instances {
		if resolver, ok := instance.Plugin.(plugin.DNSResolver); ok {
			request.Resolve = resolver.ResolveDNS
			break
		}
	}
	for i := len(h.instances) - 1; i >= 0; i-- {
		instance := h.instances[i]
		implementation, ok := instance.Plugin.(plugin.DNSPlugin)
		if !ok {
			continue
		}
		for _, scope := range instance.plan.DNS {
			if scope.MatchPacket(request.DNSPacket) {
				terminal = implementation.WrapDNS(terminal)
				break
			}
		}
	}
	response, err := terminal(ctx, request)
	if err == nil && response != nil {
		err = finalize(response)
	}
	return response, err
}

// ObserveDNS must be called from HandleDNS's finalizer, under its admission.
func (h *Host) ObserveDNS(ctx context.Context, request *plugin.DNSExchange, response *plugin.DNSResponse) {
	if h == nil {
		return
	}
	for _, instance := range h.instances {
		if observer, ok := instance.Plugin.(plugin.DNSObserver); ok {
			observer.ObserveDNS(ctx, request.Copy(), response.Copy())
		}
	}
}

func (h *Host) UseDNSAddress(host string, proxy bool) bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return false
	}
	h.requests.Add(1)
	h.mu.Unlock()
	defer h.requests.Done()
	for _, instance := range h.instances {
		if policy, ok := instance.Plugin.(plugin.DNSAddressPolicy); ok {
			if use, applicable := policy.UseDNSAddress(host, proxy); applicable {
				return use
			}
		}
	}
	return false
}
