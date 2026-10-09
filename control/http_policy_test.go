// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/internal/pluginctx"
	"github.com/daeuniverse/outbound/netproxy"
)

func TestHTTPPolicyOverridesRetainedOutbound(t *testing.T) {
	var directDials, proxyDials atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") }))
	defer server.Close()
	dial := func(ctx context.Context, _, address string) (net.Conn, error) {
		if address != "192.0.2.20:80" {
			t.Errorf("original target lost: %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	plane, _, param := newHTTPRequestRouteTest(t, "sip(192.0.2.10) -> proxy(mark:91)", mitmRoutingPlugin("original.example"), dial)
	plane.outbounds[0] = downloadTestGroup(t, "direct", func(ctx context.Context, network, address string) (net.Conn, error) {
		directDials.Add(1)
		return dial(ctx, network, address)
	})
	plane.outbounds[2] = downloadTestGroup(t, "proxy", func(ctx context.Context, network, address string) (net.Conn, error) {
		proxyDials.Add(1)
		return dial(ctx, network, address)
	})
	// Avoid real marked sockets in the test while retaining mark in the plan.
	plane.soMarkFromDae = 91
	retained, err := plane.selectRoutedAddress("tcp", param.Src, *param.routingResult, param.Domain, param.Dest)
	if err != nil {
		t.Fatal(err)
	}
	before := *param.routingResult
	planner := &httpRoutePlanner{plane: plane, network: "tcp", original: httpTarget{host: param.Domain, port: 80},
		source: param.Src, destination: param.Dest, identity: before, retained: retained}
	client, closeClient := mitm.NewRoutedHTTPClient(planner.plan)
	defer closeClient()
	for _, policy := range []string{"", "DIRECT", "proxy", "DIRECT", "missing", "REJECT"} {
		ctx := pluginctx.WithHTTPPolicy(t.Context(), policy)
		options, err := planner.routeOptions(ctx, planner.original)
		if policy == "missing" {
			if err == nil {
				t.Fatal("unknown policy selected an outbound")
			}
			continue
		}
		if err != nil || options[0].Mark != 91 || options[0].DialTarget != "192.0.2.20:80" {
			t.Fatalf("policy=%s changed address or mark: %+v %v", policy, options, err)
		}
		request, _ := http.NewRequestWithContext(t.Context(), "GET", "http://original.example/", nil)
		var response *http.Response
		if policy == "" {
			response, err = client.Do(request)
		} else {
			response, err = client.Transport.(plugin.PolicyTransport).RoundTripPolicy(request, policy)
		}
		if policy == "REJECT" {
			if err == nil {
				t.Fatal("REJECT policy dialed upstream")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
	}
	if directDials.Load() != 1 || proxyDials.Load() != 1 || *param.routingResult != before || retained.Outbound.Name != "proxy" {
		t.Fatalf("policy pool or ingress changed: direct=%d proxy=%d retained=%s", directDials.Load(), proxyDials.Load(), retained.Outbound.Name)
	}
}

func TestHTTPPolicyKeepsDestinationPredicates(t *testing.T) {
	unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
	plane, _, param := newHTTPRequestRouteTest(t, "", mitmRoutingPlugin("original.example"), unused)
	prepared := prepareFlowRulesForTest(t, "sip(192.0.2.10) && dip(192.0.2.20) && dport(80) -> dnat(198.51.100.9)", "dip(198.51.100.9) -> proxy(mark:91)")
	plane.routingMatcher, _ = routingMatcherForTest(t, prepared)
	plane.soMarkFromDae = 91
	ctx := pluginctx.WithHTTPPolicy(t.Context(), "DIRECT")
	for _, test := range []struct {
		source, destination, want string
		mark                      uint32
	}{
		{"192.0.2.10:5000", "192.0.2.20:80", "198.51.100.9:80", 91},
		{"192.0.2.11:5000", "192.0.2.20:80", "192.0.2.20:80", 0},
		{"192.0.2.10:5000", "192.0.2.20:443", "192.0.2.20:443", 0},
	} {
		option, err := plane.selectHTTPAddress(ctx, "tcp", netip.MustParseAddrPort(test.source), *param.routingResult, param.Domain, netip.MustParseAddrPort(test.destination))
		if err != nil || option.DialTarget != test.want || option.Mark != test.mark || !option.Direct {
			t.Fatalf("policy changed destination filtering: %+v, %v", option, err)
		}
	}
}

func TestHTTPPolicyDoesNotFallBackFromUnavailableGroup(t *testing.T) {
	unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
	plane, _, param := newHTTPRequestRouteTest(t, "", mitmRoutingPlugin("original.example"), unused)
	options := &dialer.GlobalOption{}
	d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: unused}), options, &dialer.Property{Name: "unavailable"}, true, "")
	group := outbound.NewDialerGroup(options, "unavailable", outbound.GroupKindSelector,
		[]*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, nil)
	t.Cleanup(func() { _ = group.Close() })
	plane.outbounds[2] = group
	ctx := pluginctx.WithHTTPPolicy(t.Context(), "unavailable")
	option, err := plane.selectHTTPAddress(ctx, "tcp", param.Src, *param.routingResult, param.Domain, param.Dest)
	if !errors.Is(err, outbound.ErrNoAliveDialer) || option != nil {
		t.Fatalf("unavailable policy fell back to another outbound: %+v, %v", option, err)
	}
}
