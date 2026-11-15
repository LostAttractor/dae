// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	quic "github.com/daeuniverse/quic-go"
)

type destinationUDPRecorder struct {
	downloadTestDialer
	targets []string
	quic    []bool
	opened  []*udpLifecyclePacket
}

func (d *destinationUDPRecorder) ListenPacket(ctx context.Context, target string) (net.PacketConn, error) {
	d.targets = append(d.targets, target)
	d.quic = append(d.quic, netproxy.IsQUIC(ctx))
	conn := &udpLifecyclePacket{testPacketConn: newTestPacketConn(false), lease: netproxy.NewLease(netproxy.NewResourceRef()), writes: make(chan netip.AddrPort, 8)}
	d.opened = append(d.opened, conn)
	return conn, nil
}

// Capture a real QUIC Initial without completing a handshake or serving TLS.
func destinationQUICInitial(t *testing.T) []byte {
	t.Helper()
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := quic.Dial(ctx, client, server.LocalAddr(), &tls.Config{
			ServerName: "127.0.0.1", NextProtos: []string{"probe"}, CurvePreferences: []tls.CurveID{tls.X25519},
		}, &quic.Config{InitialPacketSize: 1200})
		if conn != nil {
			_ = conn.CloseWithError(0, "done")
		}
	}()
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		cancel()
		<-done
		t.Fatal(err)
	}
	packet := make([]byte, 65535)
	n, _, err := server.ReadFrom(packet)
	cancel()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	return packet[:n]
}

func TestDestinationUDPKeepsSniffedQUICClassification(t *testing.T) {
	for _, isQUIC := range []bool{false, true} {
		t.Run(fmt.Sprint(isQUIC), func(t *testing.T) {
			bindings := newRoutingLayoutTestMap(t, "udp_bindings_map", uint32(unsafe.Sizeof(bpfUdpBinding{})))
			decisions := newRoutingLayoutTestMap(t, "udp_routing_cache_map", 8)
			var endpoints UdpEndpointPool
			defer endpoints.closeAll()
			source := netip.MustParseAddrPort("192.0.2.10:5000")
			first := netip.MustParseAddrPort("192.0.2.20:443")
			second := netip.MustParseAddrPort("192.0.2.21:443")
			matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t,
				"dip(192.0.2.20,192.0.2.21) -> dnat(198.51.100.20)", "dip(198.51.100.20) -> proxy"))
			unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("UDP association must use the selected packet dialer")
				return nil, net.ErrClosed
			})
			recorder := &destinationUDPRecorder{downloadTestDialer: unused}
			global := &dialer.GlobalOption{}
			d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: recorder}), global, &dialer.Property{Name: t.Name()}, false, "")
			group := outbound.NewDialerGroup(global, "proxy", outbound.GroupKindSingleAlwaysAlive, []*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{})
			defer group.Close()
			plane := &ControlPlane{udpEndpoints: &endpoints, routingMatcher: matcher, deviceRoutes: newTestDeviceRoutes(t),
				core:      &controlPlaneCore{bpf: &BPFState{bpfObjects: &bpfObjects{bpfMaps: bpfMaps{UdpBindingsMap: bindings, UdpRoutingCacheMap: decisions}}}},
				outbounds: []*outbound.DialerGroup{downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), group},
			}
			packet := []byte("payload")
			if isQUIC {
				packet = destinationQUICInitial(t)
			}
			result := &routingResult{Outbound: uint8(consts.OutboundControlPlaneRouting), CaptureFlags: captureDestination, Ifindex: 7, ProfileId: matcher.defaultProfileID, SourceOrigin: uint8(plugin.SourceLocal)}
			for i, dst := range []netip.AddrPort{first, second} {
				if err := plane.handlePkt(t.Context(), packet, source, dst, result); err != nil {
					t.Fatal(err)
				}
				if len(recorder.quic) != i+1 || recorder.quic[i] != isQUIC {
					t.Fatalf("destination %v lost classification %v: dials=%v targets=%v", dst, isQUIC, recorder.quic, recorder.targets)
				}
				// Only the first destination is sniffed; later payloads cannot
				// supply the association's retained classification themselves.
				packet = []byte("later packet")
			}
		})
	}
}

// Exercise real UDP association creation, replacement and private ownership maps.
// Packet conns record dials without sending traffic or attaching BPF programs.
func TestDestinationUDPReplacementKernelIntegration(t *testing.T) {
	for _, rewritten := range []bool{false, true} {
		t.Run(fmt.Sprint(rewritten), func(t *testing.T) {
			bindings := newRoutingLayoutTestMap(t, "udp_bindings_map", uint32(unsafe.Sizeof(bpfUdpBinding{})))
			decisions := newRoutingLayoutTestMap(t, "udp_routing_cache_map", 8)
			var endpoints UdpEndpointPool
			defer endpoints.closeAll()
			// Ordinary association traffic must not enter the DNS interception path.
			source, original := netip.MustParseAddrPort("192.0.2.10:5000"), netip.MustParseAddrPort("192.0.2.20:443")
			target, filter := original, "domain(full: declared.example)"
			if rewritten {
				target, filter = netip.MustParseAddrPort("198.51.100.20:443"), "dip(192.0.2.20)"
			}
			matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, filter+" -> dnat(198.51.100.20)", "dip(192.0.2.20,198.51.100.20) -> proxy(mark:37)"))
			matcher.profiles[42] = matcher.profiles[matcher.defaultProfileID]
			matcher.destinations[42] = matcher.destinations[matcher.defaultProfileID]
			matcher.defaultProfileID = 99
			profileID := uint32(42)
			unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("UDP association must use the selected packet dialer")
				return nil, net.ErrClosed
			})
			recorder := &destinationUDPRecorder{downloadTestDialer: unused}
			newGroup := func() *outbound.DialerGroup {
				global := &dialer.GlobalOption{}
				d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: recorder}), global, &dialer.Property{Name: t.Name()}, false, "")
				group := outbound.NewDialerGroup(global, "proxy", outbound.GroupKindSingleAlwaysAlive, []*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{})
				t.Cleanup(func() { _ = group.Close() })
				return group
			}
			plane := &ControlPlane{udpEndpoints: &endpoints, routingMatcher: matcher, deviceRoutes: newTestDeviceRoutes(t),
				core:      &controlPlaneCore{bpf: &BPFState{bpfObjects: &bpfObjects{bpfMaps: bpfMaps{UdpBindingsMap: bindings, UdpRoutingCacheMap: decisions}}}},
				outbounds: []*outbound.DialerGroup{downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), newGroup()},
			}
			send := func() {
				t.Helper()
				result := &routingResult{Outbound: uint8(consts.OutboundControlPlaneRouting), CaptureFlags: captureDestination, Ifindex: 7, ProfileId: profileID, SourceOrigin: uint8(plugin.SourceLocal)}
				if err := plane.handlePkt(t.Context(), []byte("payload"), source, original, result); err != nil {
					t.Fatal(err)
				}
			}
			setupDrops := dropSetupCapacity.Load()
			plane.udpSlowWork.Store(maxConcurrentUDPSlowWork)
			send()
			if _, ok := endpoints.Get(source); ok || len(recorder.targets) != 0 {
				t.Fatal("created an association beyond setup capacity")
			}
			plane.udpSlowWork.Store(0)
			send()
			if plane.udpSlowWork.Load() != 0 {
				t.Fatal("completed setup retained admission")
			}
			plane.udpSlowWork.Store(maxConcurrentUDPSlowWork)
			send()
			if dropSetupCapacity.Load()-setupDrops != 1 || len(recorder.targets) != 1 {
				t.Fatal("established association passed through setup admission")
			}
			plane.udpSlowWork.Store(0)
			endpoint, ok := endpoints.Get(source)
			if !ok || endpoint.destinations[original].target != target || endpoint.destinationParam.routingResult.Mark != 37 || endpoint.destinationParam.routingResult.ProfileId != 42 || len(recorder.targets) != 1 || recorder.targets[0] != target.String() {
				t.Fatalf("initial source lost its target or policy: endpoint=%+v dials=%v", endpoint, recorder.targets)
			}
			// A config/node replacement only affects new lifetimes. The original
			// target and mark survive even when the first destination rule missed.
			newTarget := netip.MustParseAddrPort("203.0.113.20:443")
			plane.routingMatcher, _ = routingMatcherForTest(t, prepareFlowRulesForTest(t, "dip(192.0.2.20) -> dnat(203.0.113.20)", "dip(203.0.113.20) -> proxy(mark:91)"))
			profileID = plane.routingMatcher.defaultProfileID
			if err := plane.outbounds[2].Close(); err != nil {
				t.Fatal(err)
			}
			plane.outbounds[2] = newGroup()
			send()
			if current, ok := endpoints.Get(source); !ok || current != endpoint || current.destinations[original].target != target || current.destinationParam.routingResult.Mark != 37 || current.destinationParam.routingResult.ProfileId != 42 || len(recorder.targets) != 1 {
				t.Fatal("config replacement changed an existing UDP lifetime")
			}
			recorder.opened[0].lease.Abort(errors.New("transport failed"))
			deadline := time.Now().Add(time.Second)
			for {
				if _, ok := endpoints.Get(source); !ok {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("failed source was not released")
				}
				time.Sleep(time.Millisecond)
			}
			send()
			fresh, ok := endpoints.Get(source)
			if !ok || fresh == endpoint || fresh.destinations[original].target != newTarget || fresh.destinationParam.routingResult.Mark != 91 || fresh.destinationParam.routingResult.ProfileId != profileID || len(recorder.targets) != 2 || recorder.targets[1] != newTarget.String() {
				t.Fatalf("new lifetime did not use current target/policy: endpoint=%+v dials=%v", fresh, recorder.targets)
			}
			var binding bpfUdpBinding
			if err := bindings.Lookup(udpSourceKey(source), &binding); err != nil {
				t.Fatalf("replacement source binding missing: %v", err)
			}
		})
	}
}
