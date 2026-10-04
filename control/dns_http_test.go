// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/plugin"
)

func TestDNSHTTPPreservesClientPolicyAndInvocationLifetime(t *testing.T) {
	var dials atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	group := downloadTestGroup(t, "direct", func(ctx context.Context, _, _ string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	})
	block := downloadTestGroup(t, "block", func(context.Context, string, string) (net.Conn, error) {
		t.Error("block route dialed")
		return nil, errors.New("blocked")
	})
	matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "sip(192.0.2.10) && dport(80) -> block"))
	c := &ControlPlane{routingMatcher: matcher, outbounds: []*outbound.DialerGroup{group, block}}
	var childErr error
	var client *http.Client
	p := &dnsCallbackPlugin{handle: func(ctx context.Context, r *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		client = r.Client
		request, _ := http.NewRequestWithContext(ctx, "GET", "http://198.51.100.9/", nil)
		response, err := r.Client.Do(request)
		childErr = err
		if response != nil {
			response.Body.Close()
		}
		return nil, nil
	}}
	host, err := mitm.New(mitm.Options{DisableHTTP: true}, mitm.Instance{ID: "dns-http", Plugin: p})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	c.mitmHost = host
	for _, source := range []string{"192.0.2.11:1234", "192.0.2.10:1234"} {
		identity := routingResult{CaptureFlags: 8}
		q, _, err := c.dnsRequest(dnsTestWire(t, dnsTestRequest(t, "script.example.", 1)), "udp", netip.MustParseAddrPort(source), netip.MustParseAddrPort("192.0.2.53:53"), identity)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.processDNS(t.Context(), q, identity, false, nil, func([]byte) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if (childErr != nil) != (source == "192.0.2.10:1234") {
			t.Fatalf("source=%s child error=%v", source, childErr)
		}
		if source == "192.0.2.11:1234" {
			response, err := client.Get("http://198.51.100.9/")
			if response != nil {
				response.Body.Close()
			}
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("HTTP client survived DNS invocation: %v", err)
			}
		}
	}
	if dials.Load() != 1 {
		t.Fatalf("cross-client route/pool bypass: dials=%d", dials.Load())
	}
}
