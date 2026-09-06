package control

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
)

func TestMITMHTTPPolicyResetsClientAfterResourceRetires(t *testing.T) {
	accepted, client := relayTestTCPPair(t)
	remote, backend := net.Pipe()
	defer backend.Close()
	defer remote.Close()
	resource, policy := netproxy.NewLease(netproxy.NewResourceRef()), netproxy.NewLease(netproxy.NewResourceRef())
	defer resource.Invalidate(nil)
	defer policy.Invalidate(nil)
	data := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) {
		return &relayTestLeasedConn{Conn: remote, lease: resource}, nil
	})
	d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: data}), new(dialer.GlobalOption), &dialer.Property{Name: t.Name()}, false, "")
	defer d.Close()
	option := &DialOption{Dialer: d, PolicyLease: policy, Outbound: &outbound.DialerGroup{Name: "proxy"}, DialTarget: "192.0.2.1:80", NetworkType: *common.NetworkTCP4.NetworkType()}
	plane := new(ControlPlane)
	host, err := mitm.New(mitm.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	relay := &tcpRelay{lConn: sniffing.NewConnSniffer(accepted, time.Second), domain: "service.example", dst: netip.MustParseAddrPort("192.0.2.1:80"), mitmHost: host,
		mitmPlanner: func(*http.Request) (mitm.UpstreamPlan, error) {
			return mitm.UpstreamPlan{Key: "selected", Dial: func(ctx context.Context, _, _ string) (net.Conn, error) { return plane.dialHTTPUpstream(ctx, option) }}, nil
		},
	}
	done := make(chan error, 1)
	go func() {
		if _, err := relay.lConn.SniffTcp(); err != nil {
			done <- err
			return
		}
		done <- relay.run()
	}()
	served := make(chan error, 1)
	go func() {
		request, err := http.ReadRequest(bufio.NewReader(backend))
		if err == nil {
			_ = request.Body.Close()
			_, err = io.WriteString(backend, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}
		served <- err
	}()
	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: service.example\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(body) != "ok" {
		t.Fatalf("response: %q, %v", body, err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	resource.Invalidate(errors.New("graceful retirement"))
	policy.Abort(netproxy.WrapFailure(errors.New("group changed"), netproxy.Failure{Origin: netproxy.OriginLocalCleanup}))
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("client error=%v, want RST", err)
	}
	_ = waitTCPRelayTest(t, done)
	if resource.AbortCause() != nil {
		t.Fatal("group policy changed the resource owner's decision")
	}
}
