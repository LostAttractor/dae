// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

type blockingDNSObserver struct {
	entered, release chan struct{}
	closed           atomic.Bool
}

func (*blockingDNSObserver) Plan() plugin.Plan { return plugin.Plan{} }
func (p *blockingDNSObserver) Close() error    { p.closed.Store(true); return nil }
func (p *blockingDNSObserver) ObserveDNS(_ context.Context, request *plugin.DNSExchange, response *plugin.DNSResponse) {
	close(p.entered)
	<-p.release
	query, message := request.MessageCopy(), response.MessageCopy()
	query.Question[0].Name = "mutated.example."
	message.Id++
	request.DNSPacket, response.DNSPacket = plugin.DNSMessage(query), plugin.DNSMessage(message)
}

func TestDNSObserversHoldHostAdmission(t *testing.T) {
	p := &blockingDNSObserver{entered: make(chan struct{}), release: make(chan struct{})}
	h := testHost(t, Options{DisableHTTP: true, DrainTimeout: time.Second}, Instance{ID: "observer", Plugin: p})
	request := &plugin.DNSExchange{DNSPacket: plugin.DNSMessage(new(dns.Msg).SetQuestion("original.example.", dns.TypeA))}
	response := &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(new(dns.Msg).SetReply(request.MessageCopy()))}
	done := make(chan error, 1)
	go func() {
		_, err := h.HandleDNS(t.Context(), request, func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) { return response, nil }, func(r *plugin.DNSResponse) error { h.ObserveDNS(t.Context(), request, r); return nil })
		done <- err
	}()
	<-p.entered
	closed := make(chan error, 1)
	go func() { closed <- h.Close() }()
	select {
	case <-closed:
		t.Fatal("host closed while observer was active")
	case <-time.After(20 * time.Millisecond):
	}
	if p.closed.Load() {
		t.Fatal("plugin resources closed before observer returned")
	}
	close(p.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if !p.closed.Load() || request.MessageCopy().Question[0].Name != "original.example." || response.MessageCopy().Id != request.MessageCopy().Id {
		t.Fatal("observer ownership or close order violated")
	}
}

type scopedDNSCache struct{ lookups, exchanges int }

func (*scopedDNSCache) Plan() plugin.Plan {
	return plugin.Plan{DNS: []plugin.DNSScope{{Names: []string{"cached.example"}, Types: []uint16{dns.TypeA}}}}
}
func (c *scopedDNSCache) WrapDNSUpstream(next plugin.DNSHandler) plugin.DNSHandler {
	return func(ctx context.Context, request *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		c.exchanges++
		return next(ctx, request)
	}
}
func (c *scopedDNSCache) LookupDNSUpstream(request *plugin.DNSExchange) *plugin.DNSResponse {
	c.lookups++
	return &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(new(dns.Msg).SetReply(request.MessageCopy())), Cached: true}
}

func TestDNSFallbackCacheHonorsScope(t *testing.T) {
	cache := new(scopedDNSCache)
	h := testHost(t, Options{DisableHTTP: true}, Instance{ID: "cache", Plugin: cache})
	for _, test := range []struct {
		name string
		kind uint16
		hit  bool
	}{
		{"other.example.", dns.TypeA, false},
		{"cached.example.", dns.TypeAAAA, false},
		{"cached.example.", dns.TypeA, true},
	} {
		request := &plugin.DNSExchange{DNSPacket: plugin.DNSMessage(new(dns.Msg).SetQuestion(test.name, test.kind))}
		prepared, err := (&plugin.DNSExchange{DNSRequest: request.DNSRequest, SelectCaches: h.selectDNSCaches}).PrepareUpstream(t.Context(), plugin.DNSUpstream{})
		if err != nil {
			t.Fatal(err)
		}
		if response := prepared.Lookup(); (response != nil) != test.hit {
			t.Fatalf("scope mismatch for %s/%d: %+v", test.name, test.kind, response)
		}
		if _, err := prepared.Exchange(t.Context(), func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) { return nil, nil }); err != nil {
			t.Fatal(err)
		}
	}
	if cache.lookups != 1 || cache.exchanges != 1 {
		t.Fatalf("cache paths disagree on scopes: lookups=%d exchanges=%d", cache.lookups, cache.exchanges)
	}
}
