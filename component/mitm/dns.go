// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"sync/atomic"

	"github.com/daeuniverse/dae/component/plugin"
)

var dnsSerial atomic.Uint64

// HandleDNS shares the plugin lifecycle with HTTP. The terminal is the core's
// transparent relay; protocol-aware upstream querying belongs to plugins.
func (h *Host) HandleDNS(ctx context.Context, request *plugin.DNSExchange, terminal plugin.DNSHandler, finalize func(*plugin.DNSResponse) error) (*plugin.DNSResponse, error) {
	admission, err := h.Admit()
	if err != nil {
		return nil, err
	}
	defer admission.Release()
	return admission.HandleDNS(ctx, request, terminal, finalize)
}

func (a *Admission) HandleDNS(ctx context.Context, request *plugin.DNSExchange, terminal plugin.DNSHandler, finalize func(*plugin.DNSResponse) error) (*plugin.DNSResponse, error) {
	h := a.host
	if h == nil {
		response, err := terminal(ctx, request)
		if err == nil && response != nil {
			err = finalize(response)
		}
		return response, err
	}
	// An unchanged plugin instance can be shared with a new DNS chain. Results
	// derived by plugins, including in observers invoked by the finalizer, stay
	// separate per chain; raw upstream answers do not depend on it.
	previousChain := request.Chain
	request.Chain = h.dnsChain
	defer func() { request.Chain = previousChain }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(h.forceContext, cancel)
	defer stop()
	request.Resolve = nil
	previousCaches := request.SelectCaches
	defer func() { request.SelectCaches = previousCaches }()
	request.SelectCaches = nil
	if len(h.dnsCaches) != 0 {
		request.SelectCaches = h.selectDNSCaches
	}
	relay := terminal
	terminal = func(ctx context.Context, query *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		return query.ExchangeUpstream(ctx, plugin.DNSUpstream{Network: query.Network, Address: query.Destination}, relay)
	}
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

func (h *Host) selectDNSCaches(packet plugin.DNSPacket) []plugin.DNSUpstreamCache {
	var selected []plugin.DNSUpstreamCache
	for _, instance := range h.dnsCaches {
		if instance.matchesDNS(packet) {
			selected = append(selected, instance.Plugin.(plugin.DNSUpstreamCache))
		}
	}
	return selected
}

func (i Instance) matchesDNS(packet plugin.DNSPacket) bool {
	for _, scope := range i.plan.DNS {
		if scope.MatchPacket(packet) {
			return true
		}
	}
	return false
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

// UseDNSAddress reports whether a proxied flow to host dials its DNS address
// instead of sending the sniffed name.
func (h *Host) UseDNSAddress(host string) bool {
	admission, err := h.Admit()
	if err != nil {
		return false
	}
	defer admission.Release()
	return admission.UseDNSAddress(host)
}

func (a *Admission) UseDNSAddress(host string) bool {
	h := a.host
	if h == nil {
		return false
	}
	for _, instance := range h.instances {
		if policy, ok := instance.Plugin.(plugin.DNSAddressPolicy); ok {
			if use, applicable := policy.UseDNSAddress(host); applicable {
				return use
			}
		}
	}
	return false
}
