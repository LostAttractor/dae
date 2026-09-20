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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/mitm"
	dnsmessage "github.com/miekg/dns"
)

func TestHTTP2CoalescedAuthorityRoutes(t *testing.T) {
	authority, roots := mitmQUICTestAuthority(t)
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != "original.example" {
			t.Errorf("upstream TLS identity mismatch: %s/%s", r.TLS.ServerName, r.Host)
		}
		fmt.Fprint(w, r.Host)
	}))
	backend.EnableHTTP2 = true
	upstreamCert, err := authority.ServerCertificate("original.example")
	if err != nil {
		t.Fatal(err)
	}
	backend.TLS = &tls.Config{Certificates: []tls.Certificate{*upstreamCert}}
	backend.StartTLS()
	t.Cleanup(backend.Close)
	extension := mitmRoutingPlugin("original.example", "app.example")
	plane, _, param := newHTTPRequestRouteTest(t,
		"domain(full: app.example) -> proxy(mark:91)\ndomain(full: passport.example) -> proxy(mark:91)\ndomain(full: blocked.example) -> block",
		extension, func(context.Context, string, string) (net.Conn, error) {
			t.Error("unexpected fallback dial")
			return nil, net.ErrClosed
		})
	host, err := mitm.New(mitm.Options{Authority: authority, UpstreamTLSConfig: &tls.Config{RootCAs: roots}}, mitm.Instance{Plugin: extension})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	plane.mitmHost = host
	plane.soMarkFromDae = 37
	param.Dest = netip.MustParseAddrPort("192.0.2.20:443")
	param.routingResult.CaptureFlags = captureHTTP
	param.routingResult.Outbound = uint8(consts.OutboundDirect)
	param.routingResult.Mark, param.routingResult.Must = 37, 1
	originalIdentity := *param.routingResult
	attachDownloadTestDNS(t, plane, "test", "accept", func(message *dnsmessage.Msg) {
		t.Error("fronted authority triggered DNS resolution")
		message.Response = true
		if message.Question[0].Qtype == dnsmessage.TypeA {
			message.Answer = []dnsmessage.RR{&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{Name: message.Question[0].Name, Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
				A:   net.ParseIP("198.51.100.4"),
			}}
		}
	})
	var mu sync.Mutex
	dials := make(map[string]int)
	for index, name := range map[int]string{0: "direct", 2: "proxy"} {
		plane.outbounds[index] = downloadTestGroup(t, name, func(ctx context.Context, _, address string) (net.Conn, error) {
			want := "192.0.2.20:443"
			if name == "proxy" {
				want = "198.51.100.4:443"
			}
			if address != want {
				t.Errorf("%s dialed %s, want %s", name, address, want)
			}
			mu.Lock()
			dials[name]++
			mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, "tcp", backend.Listener.Addr().String())
		})
	}
	retained, _, release, err := plane.prepareHTTPRoute(t.Context(), param.Domain, param)
	if err != nil || retained == nil || release == nil {
		t.Fatalf("inspection route: %+v, %v", retained, err)
	}
	defer release()
	// Observe the same target selection used by the production planner, before
	// it turns options into a pool key and dial callback.
	planner := &httpRoutePlanner{plane: plane, network: "tcp", original: httpTarget{host: param.Domain, port: 443},
		source: param.Src, destination: param.Dest, identity: originalIdentity, retained: retained}
	var plans atomic.Int32
	plan := func(r *http.Request) (mitm.UpstreamPlan, error) {
		plans.Add(1)
		target, err := requestHTTPTarget(r)
		if err != nil {
			return mitm.UpstreamPlan{}, err
		}
		options, err := planner.routeOptions(r.Context(), target)
		if err != nil {
			return mitm.UpstreamPlan{}, err
		}
		for _, option := range options {
			switch target.host {
			case "original.example":
				if option != retained || option.Mark != 37 || option.Outbound.Name != "direct" {
					t.Errorf("lost original inspection route: %+v", option)
				}
			default:
				t.Errorf("fronted authority reached routing: %s", target.host)
			}
		}
		return planner.upstreamPlan(r.URL.Scheme, target, options)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	served := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			err = host.ServeConn(conn, param.Domain, 443, plan)
		}
		served <- err
	}()
	transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		_ = host.Close()
		select {
		case <-served:
		case <-time.After(time.Second):
			t.Error("MITM authority server did not stop")
		}
	})
	for _, name := range []string{"original.example", "app.example", "app.example", "passport.example", "blocked.example", "outside.example", "original.example"} {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+param.Domain+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = name
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.ProtoMajor != 2 {
			t.Fatalf("response protocol=%s read=%v", response.Proto, err)
		}
		// Domain routing applies to the fixed ingress, not its HTTP stream
		// authorities. Explicit URL rewrites are tested separately.
		want := 200
		if response.StatusCode != want || want == 200 && string(body) != name {
			t.Fatalf("%s: response %d %q, want %d", name, response.StatusCode, body, want)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if plans.Load() != 1 || dials["direct"] != 1 || dials["proxy"] != 0 || len(dials) != 1 {
		t.Fatalf("authority pools or routes mixed: %v", dials)
	}
	if *param.routingResult != originalIdentity || planner.identity != originalIdentity {
		t.Fatal("request routing changed the original mark/must/client identity")
	}
}
