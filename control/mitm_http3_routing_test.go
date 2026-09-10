// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/plugin"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
)

type http3RoutingPlugin struct{ target string }

func (http3RoutingPlugin) Plan() plugin.Plan {
	return plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: plugin.Scope{{Host: "original.example", Ports: []uint16{443}}}}}}
}

func (p http3RoutingPlugin) Wrap(_ plugin.Flow, next plugin.Handler) plugin.Handler {
	return func(e *plugin.Exchange) (*http.Response, error) {
		switch e.Request.URL.Path {
		case "/local":
			return &http.Response{StatusCode: 418, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("local"))}, nil
		case "/auxiliary":
			r, _ := http.NewRequestWithContext(e.Request.Context(), "GET", "http://198.51.100.30:8080/", nil)
			return e.Client.Do(r)
		default:
			e.Request.URL.Host, e.Request.Host = p.target, p.target
			return next(e)
		}
	}
}

func TestHTTP3RequestsRouteAfterRewriteAndBeforePoolLookup(t *testing.T) {
	authority, roots := mitmQUICTestAuthority(t)
	packets, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packets.Close()
	rewritten := fmt.Sprintf("198.51.100.9:%d", addrPortOf(packets.LocalAddr()).Port())
	upstream := &http3.Server{TLSConfig: authority.TLSConfig("198.51.100.9"), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 3 || r.Host != rewritten {
			t.Errorf("wrong final request: %s %s", r.Proto, r.Host)
		}
		fmt.Fprint(w, "HTTP/3")
	})}
	done := make(chan error, 1)
	go func() { done <- upstream.Serve(packets) }()
	defer func() { _ = upstream.Close(); <-done }()
	auxiliary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "TCP") }))
	defer auxiliary.Close()
	var tcpDials atomic.Int32
	plane, _, param := newHTTPRequestRouteTest(t, "", mitmRoutingPlugin("original.example"), func(context.Context, string, string) (net.Conn, error) {
		t.Error("unexpected unplanned dial")
		return nil, net.ErrClosed
	})
	host, err := mitm.New(mitm.Options{Authority: authority, UpstreamTLSConfig: &tls.Config{RootCAs: roots}}, mitm.Instance{Plugin: http3RoutingPlugin{target: rewritten}})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	plane.mitmHost = host
	param.Domain, param.Dest, param.networkType = "original.example", netip.MustParseAddrPort("192.0.2.20:443"), *common.NetworkUDP4.NetworkType()
	param.routingResult.Ifindex, param.routingResult.Dscp = 7, 46
	copy(param.routingResult.Pname[:], "app")
	before := *param.routingResult
	prepared := prepareFlowRulesForTest(t, "dip(198.51.100.9) && sip(192.0.2.10) && pname(app) -> dnat(127.0.0.1)", fmt.Sprintf(`
client(blocked) -> block
l4proto(tcp) && dip(198.51.100.30) -> proxy(mark:73)
l4proto(udp) && dip(127.0.0.1) && dport(%d) && sip(192.0.2.10) && sport(5000) && pname(app) && dscp(46) && client(marked) -> direct(mark:92)
l4proto(udp) && dip(127.0.0.1) && dport(%d) && sip(192.0.2.10) && sport(5000) && pname(app) && dscp(46) -> direct(mark:91)
domain(full: original.example) -> block
dip(192.0.2.20) -> block`, addrPortOf(packets.LocalAddr()).Port(), addrPortOf(packets.LocalAddr()).Port()))
	prepared.enableMITMPlan(host.Plan())
	matcher, builder := routingMatcherForTest(t, prepared)
	plane.routingMatcher = matcher
	plane.outbounds[2] = downloadTestGroup(t, "proxy", func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "198.51.100.30:8080" {
			t.Errorf("auxiliary route=%s/%s", network, address)
		}
		tcpDials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, "tcp", auxiliary.Listener.Addr().String())
	})
	first, second := new(mitmQUICDialer), new(mitmQUICDialer)
	plane.markedDirectDialers.Store(uint32(91), first)
	plane.markedDirectDialers.Store(uint32(92), second)
	option, planner, release, err := plane.prepareHTTPRoute(t.Context(), param.Domain, param)
	if err != nil || option != nil || planner == nil || release != nil {
		t.Fatalf("old route ran before HTTP: %+v, %v", option, err)
	}
	bridge := plane.newMITMQUIC(param, planner, release)
	defer bridge.Close()
	wire := &quic.Transport{Conn: bridge}
	defer wire.Close()
	transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, Dial: func(ctx context.Context, _ string, cfg *tls.Config, qc *quic.Config) (*quic.Conn, error) {
		return wire.Dial(ctx, net.UDPAddrFromAddrPort(param.Dest), cfg, qc)
	}}
	defer transport.Close()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	request := func(path string, status int, body string) {
		t.Helper()
		r, _ := http.NewRequestWithContext(t.Context(), "GET", "https://original.example/"+path, nil)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != status || body != "" && string(data) != body {
			t.Fatalf("%s: status=%d body=%q err=%v", path, response.StatusCode, data, err)
		}
	}
	request("local", 418, "local")
	request("rewrite", 200, "HTTP/3")
	request("rewrite", 200, "HTTP/3")
	request("auxiliary", 200, "TCP")
	if err := builder.SetClientMembers(matcher, "marked", [][6]byte{before.Mac}, false); err != nil {
		t.Fatal(err)
	}
	request("rewrite", 200, "HTTP/3")
	if err := builder.SetClientMembers(matcher, "blocked", [][6]byte{before.Mac}, false); err != nil {
		t.Fatal(err)
	}
	request("rewrite", 502, "")
	request("local", 418, "local")
	for _, selected := range []*mitmQUICDialer{first, second} {
		selected.mu.Lock()
		if len(selected.targets) != 1 || selected.targets[0] != packets.LocalAddr().String() {
			t.Errorf("route/mark pool reused incorrectly: %v", selected.targets)
		}
		selected.mu.Unlock()
	}
	if tcpDials.Load() != 1 || *param.routingResult != before {
		t.Fatalf("TCP fallback or ingress mutation: dials=%d route=%+v", tcpDials.Load(), param.routingResult)
	}
}
