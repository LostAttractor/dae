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
func (p *blockingDNSObserver) ObserveDNS(_ context.Context, request *plugin.DNSRequest, response *plugin.DNSResponse) {
	close(p.entered)
	<-p.release
	request.Message.Question[0].Name = "mutated.example."
	response.Message.Id++
}

func TestDNSObserversHoldHostAdmission(t *testing.T) {
	p := &blockingDNSObserver{entered: make(chan struct{}), release: make(chan struct{})}
	h := testHost(t, Options{DisableHTTP: true, DrainTimeout: time.Second}, Instance{ID: "observer", Plugin: p})
	request := &plugin.DNSRequest{Message: new(dns.Msg).SetQuestion("original.example.", dns.TypeA)}
	response := &plugin.DNSResponse{Message: new(dns.Msg).SetReply(request.Message)}
	done := make(chan error, 1)
	go func() {
		_, err := h.HandleDNS(t.Context(), request, func(context.Context, *plugin.DNSRequest) (*plugin.DNSResponse, error) { return response, nil }, func(r *plugin.DNSResponse) error { h.ObserveDNS(t.Context(), request, r); return nil })
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
	if !p.closed.Load() || request.Message.Question[0].Name != "original.example." || response.Message.Id != request.Message.Id {
		t.Fatal("observer ownership or close order violated")
	}
}
