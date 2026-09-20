package control

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
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

// A request-transforming scope has no policy at TCP admission. Its first plan
// must still terminate the accepted connection if revoked before any dial
// succeeds, rather than keeping that connection alive with permanent 502s.
func TestMITMHTTPFailedDialPlanRevocationResetsClient(t *testing.T) {
	accepted, client := relayTestTCPPair(t)
	defer client.Close()
	policy := netproxy.NewLease(netproxy.NewResourceRef())
	defer policy.Invalidate(nil)
	var dials, plans atomic.Int32
	data := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("selected node unreachable")
	})
	d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: data}), new(dialer.GlobalOption), &dialer.Property{Name: t.Name()}, false, "")
	defer d.Close()
	option := &DialOption{Dialer: d, PolicyLease: policy, Outbound: &outbound.DialerGroup{Name: "proxy"}, DialTarget: "192.0.2.1:80", NetworkType: *common.NetworkTCP4.NetworkType()}
	planner := &httpRoutePlanner{plane: new(ControlPlane), original: httpTarget{host: "service.example", port: 80}}
	host, err := mitm.New(mitm.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	relay := &tcpRelay{lConn: sniffing.NewConnSniffer(accepted, time.Second), domain: "service.example", dst: netip.MustParseAddrPort(option.DialTarget), mitmHost: host,
		mitmPlanner: func(*http.Request) (mitm.UpstreamPlan, error) {
			plans.Add(1)
			return planner.upstreamPlan("http", planner.original, []*DialOption{option})
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
	reader := bufio.NewReader(client)
	request := "GET / HTTP/1.1\r\nHost: service.example\r\n\r\n"
	client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 502 || dials.Load() != 1 {
		t.Fatalf("failed first dial: status=%d dials=%d", response.StatusCode, dials.Load())
	}
	policy.Abort(errors.New("group selection changed"))
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	// HTTP may finish writing the error before the asynchronous reset arrives.
	// Either way the connection must close, rather than accept another stream.
	if response, err := http.ReadResponse(reader, nil); err == nil {
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if _, err := client.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, io.EOF) {
			t.Fatalf("revoked original plan left client open: %v", err)
		}
	} else if !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	_ = waitTCPRelayTest(t, done)
	if plans.Load() != 1 || dials.Load() != 1 {
		t.Fatalf("revocation reselected or dialed: plans=%d dials=%d", plans.Load(), dials.Load())
	}
}
