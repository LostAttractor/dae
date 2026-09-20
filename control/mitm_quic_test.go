// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
)

type mitmQUICDialer struct {
	mu      sync.Mutex
	targets []string
	err     error
}

func (*mitmQUICDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected TCP fallback")
}

func (d *mitmQUICDialer) ListenPacket(ctx context.Context, target string) (net.PacketConn, error) {
	d.mu.Lock()
	d.targets = append(d.targets, target)
	d.mu.Unlock()
	if d.err != nil {
		return nil, d.err
	}
	return (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
}

func mitmQUICTestAuthority(t *testing.T) (*mitmca.Authority, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	if err := mitmca.Generate(cert, key, "QUIC control integration", time.Hour); err != nil {
		t.Fatal(err)
	}
	authority, err := mitmca.Load(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := mitmca.ReadCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return authority, roots
}

func TestMITMQUICUsesSelectedOutboundAndOriginalTarget(t *testing.T) {
	authority, roots := mitmQUICTestAuthority(t)
	upstreamPackets, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamPackets.Close()
	upstream := &http3.Server{TLSConfig: authority.TLSConfig("video.example"), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 3 || r.Header.Get("X-Plugin") != "request" || r.Host != "video.example" {
			t.Errorf("unexpected upstream request: %s %s %v", r.Proto, r.Host, r.Header)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		_, _ = w.Write(body)
	})}
	upstreamDone := make(chan error, 1)
	go func() { upstreamDone <- upstream.Serve(upstreamPackets) }()
	defer func() { _ = upstream.Close(); <-upstreamDone }()
	extension := mitmRoutingPlugin("video.example")
	extension.handle = func(e *plugin.Exchange, next plugin.Handler) (*http.Response, error) {
		e.Request.Header.Set("X-Plugin", "request")
		response, err := next(e)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			return nil, err
		}
		body = append(body, []byte(" rewritten")...)
		response.Body = io.NopCloser(strings.NewReader(string(body)))
		response.ContentLength = int64(len(body))
		response.Header.Del("Content-Length")
		return response, nil
	}
	host, err := mitm.New(mitm.Options{Authority: authority, UpstreamTLSConfig: &tls.Config{RootCAs: roots}}, mitm.Instance{ID: "test", Type: "test", Plugin: extension})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	base := &mitmQUICDialer{err: errors.New("must use mark-selected dialer")}
	selected := new(mitmQUICDialer)
	d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: base}), &dialer.GlobalOption{}, &dialer.Property{Name: t.Name()}, false, "")
	defer d.Close()
	source, destination := netip.MustParseAddrPort("192.0.2.10:56000"), netip.MustParseAddrPort("198.51.100.10:443")
	option := &DialOption{Dialer: d, connectionDialer: selected, DialTarget: upstreamPackets.LocalAddr().String(), Outbound: &outbound.DialerGroup{Name: "direct"}, NetworkType: *common.NetworkUDP4.NetworkType()}
	plane := &ControlPlane{mitmHost: host}
	release, err := d.Retain()
	if err != nil {
		t.Fatal(err)
	}
	param := &RouteParam{Src: source, Dest: destination, Domain: "video.example", routingResult: &bpfRoutingResult{}}
	bridge := plane.newMITMQUIC(param, plane.mitmUpstreamPlanner("udp", param.Domain, source, destination, *param.routingResult, option), release, nil)
	defer bridge.Close()
	clientQUIC := &quic.Transport{Conn: bridge}
	defer clientQUIC.Close()
	clientHTTP := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, Dial: func(ctx context.Context, _ string, cfg *tls.Config, qc *quic.Config) (*quic.Conn, error) {
		return clientQUIC.Dial(ctx, net.UDPAddrFromAddrPort(destination), cfg, qc)
	}}
	defer clientHTTP.Close()
	client := &http.Client{Transport: clientHTTP, Timeout: 3 * time.Second}
	response, err := client.Post("https://video.example/play", "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || response.ProtoMajor != 3 || string(body) != "payload rewritten" {
		t.Fatalf("response=%+v body=%q err=%v", response, body, err)
	}
	selected.mu.Lock()
	defer selected.mu.Unlock()
	base.mu.Lock()
	defer base.mu.Unlock()
	// Forwarding uses the selected mark-aware outbound and original destination.
	if len(base.targets) != 0 || len(selected.targets) != 1 || selected.targets[0] != option.DialTarget {
		t.Fatalf("selected outbound or original target lost: default=%v selected=%v", base.targets, selected.targets)
	}
}

// Exercise packet dial -> bridge lease -> endpoint removal without requiring a
// peer to perform I/O after the owner has explicitly aborted its resource.
func TestMITMQUICAbortEndsSourceLifetime(t *testing.T) {
	authority, _ := mitmQUICTestAuthority(t)
	for _, owner := range []string{"resource", "policy", "policy after retire", "route"} {
		t.Run(owner, func(t *testing.T) {
			host, err := mitm.New(mitm.Options{Authority: authority})
			if err != nil {
				t.Fatal(err)
			}
			defer host.Close()
			selected := &udpLifecycleDialer{opened: make(chan *udpLifecyclePacket, 1)}
			d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: selected}), new(dialer.GlobalOption), &dialer.Property{Name: t.Name()}, false, "")
			defer d.Close()
			policy, route := netproxy.NewLease(netproxy.NewResourceRef()), netproxy.NewLease(netproxy.NewResourceRef())
			defer policy.Invalidate(nil)
			defer route.Invalidate(nil)
			src, dst := netip.MustParseAddrPort("192.0.2.1:51000"), netip.MustParseAddrPort("198.51.100.1:443")
			option := &DialOption{Dialer: d, PolicyLease: policy, DialTarget: dst.String(), Outbound: &outbound.DialerGroup{Name: "selected"}, NetworkType: *common.NetworkUDP4.NetworkType()}
			var endpoints UdpEndpointPool
			defer endpoints.closeAll()
			plane := &ControlPlane{mitmHost: host, udpEndpoints: &endpoints}
			param := &RouteParam{Src: src, Dest: dst, Domain: "video.example", routingResult: &bpfRoutingResult{}}
			planner := plane.mitmUpstreamPlanner("udp", param.Domain, src, dst, *param.routingResult, option)
			bridge := plane.newMITMQUIC(param, planner, nil, route)
			lease := netproxy.DependencyOf(bridge)
			endpoint := newUdpEndpoint(&UdpEndpointOptions{PacketConn: bridge, NatTimeout: time.Minute})
			endpoint.mitm, endpoint.firstDst = true, dst
			endpoint.lease, endpoint.policyLease, endpoint.routeLease = lease, policy, route
			endpoints.add(src, endpoint)
			endpoint.startSocket(&endpoints, src, dst, netip.AddrPort{}, bridge)
			request, _ := http.NewRequestWithContext(t.Context(), "GET", "https://video.example/", nil)
			plan, err := mitmPlannerWithLease(planner, lease)(request)
			if err != nil {
				t.Fatal(err)
			}
			packets, _, err := plan.DialPacket(t.Context(), dst.String())
			if err != nil {
				t.Fatal(err)
			}
			defer packets.Close()
			upstream := <-selected.opened
			cause := errors.New("owner aborted")
			switch owner {
			case "resource":
				upstream.lease.Abort(cause)
			case "policy", "policy after retire":
				if owner == "policy after retire" {
					upstream.lease.Invalidate(errors.New("graceful retirement"))
				}
				policy.Abort(cause)
			case "route":
				route.Abort(cause)
				if !errors.Is(lease.AbortCause(), cause) {
					t.Fatal("route abort did not synchronously stop upstream admission")
				}
			}
			deadline := time.Now().Add(time.Second)
			for {
				if _, ok := endpoints.Get(src); !ok {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("aborted HTTP/3 source remained reusable")
				}
				time.Sleep(time.Millisecond)
			}
			if _, _, err := plan.DialPacket(t.Context(), dst.String()); !errors.Is(err, cause) {
				t.Fatalf("aborted source dial = %v, want owner cause", err)
			}
		})
	}
}
