// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	"golang.org/x/sys/unix"
)

// Use the real duplicated UDP ingress and routing lookup, with private maps
// and loopback sockets. No BPF programs are attached to network interfaces.
func TestMITMQUICReloadKernelIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for isolated BPF map tests")
	}
	authority, roots := mitmQUICTestAuthority(t)
	for _, scenario := range []string{"idle", "active", "drain timeout", "reset upstream", "abort"} {
		t.Run(scenario, func(t *testing.T) {
			spec, err := loadBpf()
			if err != nil {
				t.Fatal(err)
			}
			// No redirector is attached: only FD publication is needed here.
			// An array also permits running on kernels without listener sockmap support.
			spec.Maps["listen_socket_map"].Type = ebpf.Array
			maps := make(map[string]*ebpf.Map)
			for _, name := range []string{"listen_socket_map", "routing_tuples_map"} {
				spec.Maps[name].Pinning = ebpf.PinNone
				m, err := ebpf.NewMap(spec.Maps[name])
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = m.Close() })
				maps[name] = m
			}
			plane := newLifecycleTestControlPlane(new(UdpEndpointPool))
			t.Cleanup(plane.udpEndpoints.closeAll)
			ifmgr, err := network.NewInterfaceManager()
			if err != nil {
				t.Fatal(err)
			}
			coreCtx, coreCancel := context.WithCancel(context.Background())
			plane.core = &controlPlaneCore{closed: coreCtx, close: coreCancel, ifmgr: ifmgr,
				bpf: &bpfState{bpfObjects: &bpfObjects{bpfMaps: bpfMaps{
					ListenSocketMap: maps["listen_socket_map"], RoutingTuplesMap: maps["routing_tuples_map"],
				}}},
			}
			t.Cleanup(func() { _ = plane.Close() })
			host, err := mitm.New(mitm.Options{
				Authority: authority, UpstreamTLSConfig: &tls.Config{RootCAs: roots}, DrainTimeout: time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			plane.mitmHost = host
			listenConfig := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
				var err error
				if e := raw.Control(func(fd uintptr) { err = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1) }); e != nil {
					return e
				}
				return err
			}}
			packets, err := listenConfig.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = packets.Close() })
			tcp, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = tcp.Close() })
			clientPackets, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = clientPackets.Close() })
			upstreamPackets, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = upstreamPackets.Close() })
			started, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			releaseRequest := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(releaseRequest)
			upstream := &http3.Server{TLSConfig: authority.TLSConfig("video.example"), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/active":
					close(started)
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
				case "/reset":
					panic(http.ErrAbortHandler)
				}
				_, _ = io.WriteString(w, "complete")
			})}
			upstreamDone := make(chan error, 1)
			go func() { upstreamDone <- upstream.Serve(upstreamPackets) }()
			t.Cleanup(func() { releaseRequest(); _ = upstream.Close(); <-upstreamDone })
			selected := new(mitmQUICDialer)
			d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: selected}), &dialer.GlobalOption{}, &dialer.Property{Name: t.Name()}, false, "")
			t.Cleanup(func() { _ = d.Close() })
			src, dst := addrPortOf(clientPackets.LocalAddr()), addrPortOf(packets.LocalAddr())
			retained, err := d.Retain()
			if err != nil {
				t.Fatal(err)
			}
			option := &DialOption{Dialer: d, DialTarget: upstreamPackets.LocalAddr().String(), Outbound: &outbound.DialerGroup{Name: "direct"}, NetworkType: *common.NetworkUDP4.NetworkType()}
			param := &RouteParam{Src: src, Dest: dst, Domain: "video.example", routingResult: &bpfRoutingResult{}}
			bridge := plane.newMITMQUIC(param, plane.mitmUpstreamPlanner("udp", param.Domain, src, dst, *param.routingResult, option), retained)
			key := udpEndpointKey{Source: src, Destination: dst, Interface: 7}
			endpoint := newUdpEndpoint(&UdpEndpointOptions{PacketConn: bridge, NatTimeout: time.Minute, Handler: func(data []byte, _ netip.AddrPort) error {
				_, err := packets.WriteTo(data, clientPackets.LocalAddr())
				return err
			}})
			endpoint.mitm = true
			endpoint.traffic = stats.DefaultStore.OpenConnection(d.StatsPath("direct", common.NetworkUDP4.NetworkType()), false)
			plane.udpEndpoints.add(key, endpoint)
			endpointDone := make(chan error, 1)
			go func() { endpointDone <- endpoint.run(plane.udpEndpoints, key, dst) }()
			t.Cleanup(func() { _ = endpoint.Close(); <-endpointDone })
			routeKey := bpfTuplesKey{Sport: common.Htons(src.Port()), Dport: common.Htons(dst.Port()), L4proto: unix.IPPROTO_UDP}
			routeKey.Sip.U6Addr8, routeKey.Dip.U6Addr8 = src.Addr().As16(), dst.Addr().As16()
			if err := maps["routing_tuples_map"].Update(routeKey, bpfRoutingResult{Ifindex: key.Interface, CaptureFlags: captureHTTP}, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			ready, served := make(chan bool, 1), make(chan error, 1)
			go func() { served <- plane.Serve(ready, &Listener{tcpListener: tcp, packetConn: packets}) }()
			if !<-ready {
				t.Fatalf("ingress failed: %v", <-served)
			}
			clientQUIC := &quic.Transport{Conn: clientPackets}
			t.Cleanup(func() { _ = clientQUIC.Close() })
			clientTransport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, Dial: func(ctx context.Context, _ string, cfg *tls.Config, qc *quic.Config) (*quic.Conn, error) {
				return clientQUIC.Dial(ctx, packets.LocalAddr(), cfg, qc)
			}}
			t.Cleanup(func() { _ = clientTransport.Close() })
			client := &http.Client{Transport: clientTransport, Timeout: 3 * time.Second}
			requestCtx, cancelRequests := context.WithCancel(t.Context())
			defer cancelRequests()
			request := func(path string) error {
				req, err := http.NewRequestWithContext(requestCtx, "GET", "https://"+net.JoinHostPort("video.example", strconv.Itoa(int(dst.Port())))+path, nil)
				if err != nil {
					return err
				}
				resp, err := client.Do(req)
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				if err == nil && path != "/reset" && (resp.StatusCode != http.StatusOK || string(body) != "complete") {
					return fmt.Errorf("unexpected response: %d %q", resp.StatusCode, body)
				}
				return err
			}
			if err := request("/ok"); err != nil {
				t.Fatal(err)
			}
			if scenario == "reset upstream" {
				if err := request("/reset"); err != nil {
					t.Fatal(err)
				}
			}
			responseDone := make(chan error, 1)
			if scenario == "active" || scenario == "drain timeout" {
				go func() { responseDone <- request("/active") }()
				select {
				case <-started:
				case <-time.After(3 * time.Second):
					t.Fatal("request never reached the upstream")
				}
			}
			if scenario == "abort" {
				if err := plane.StopAndAbortConnections(); err != nil {
					t.Fatal(err)
				}
			}
			closed := make(chan error, 1)
			go func() { closed <- plane.Close() }()
			if scenario == "active" {
				select {
				case err := <-closed:
					t.Fatalf("Close returned before the response completed: %v", err)
				case <-time.After(50 * time.Millisecond):
				}
				releaseRequest()
				if err := <-responseDone; err != nil {
					t.Fatalf("reload interrupted an active H3 response: %v", err)
				}
			}
			select {
			case err := <-closed:
				if err != nil {
					t.Fatalf("normal retirement must not fail reload: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("control plane did not close")
			}
			if !plane.closedDone.Load() {
				t.Fatal("retirement did not finish successfully")
			}
			if scenario == "drain timeout" {
				if _, err := bridge.WriteTo(nil, net.UDPAddrFromAddrPort(dst)); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("forced retirement left the association open: %v", err)
				}
				// Forced UDP closure cannot guarantee delivery of a final close
				// packet. Cancel the remote test client after checking local cleanup.
				cancelRequests()
				select {
				case err := <-responseDone:
					if err == nil {
						t.Fatal("unfinished request survived forced retirement")
					}
				case <-time.After(time.Second):
					t.Fatal("forced retirement left the client waiting")
				}
			}
			if err := <-served; err != nil {
				t.Fatal(err)
			}
		})
	}
}
