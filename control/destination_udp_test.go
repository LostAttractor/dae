// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type destinationUDPRecorder struct {
	downloadTestDialer
	targets []string
	opened  []*udpLifecyclePacket
}

func (d *destinationUDPRecorder) ListenPacket(_ context.Context, target string) (net.PacketConn, error) {
	d.targets = append(d.targets, target)
	conn := &udpLifecyclePacket{testPacketConn: newTestPacketConn(false), lease: netproxy.NewLease(netproxy.NewResourceRef()), writes: make(chan netip.AddrPort, 8)}
	d.opened = append(d.opened, conn)
	return conn, nil
}

// Exercise real UDP association creation, replacement and private ownership maps.
// Packet conns record dials without sending traffic or attaching BPF programs.
func TestDestinationUDPReplacementKernelIntegration(t *testing.T) {
	for _, rewritten := range []bool{false, true} {
		t.Run(fmt.Sprint(rewritten), func(t *testing.T) {
			bindings := newRoutingLayoutTestMap(t, "udp_bindings_map", 8)
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
				group := outbound.NewDialerGroup(global, "proxy", outbound.GroupKindSingleAlwaysAlive, []*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, nil)
				t.Cleanup(func() { _ = group.Close() })
				return group
			}
			plane := &ControlPlane{udpEndpoints: &endpoints, routingMatcher: matcher, deviceRoutes: newTestDeviceRoutes(t),
				core:      &controlPlaneCore{bpf: &BPFState{bpfObjects: &bpfObjects{bpfMaps: bpfMaps{UdpBindingsMap: bindings, UdpRoutingCacheMap: decisions}}}},
				outbounds: []*outbound.DialerGroup{downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), newGroup()},
			}
			send := func() {
				t.Helper()
				result := &routingResult{Outbound: uint8(consts.OutboundControlPlaneRouting), CaptureFlags: captureDestination, Ifindex: 7, ProfileId: profileID}
				if err := plane.handlePkt(t.Context(), []byte("payload"), source, original, result); err != nil {
					t.Fatal(err)
				}
			}
			plane.udpSetups.Store(maxConcurrentUDPSetups)
			send()
			if _, ok := endpoints.Get(source); ok || len(recorder.targets) != 0 {
				t.Fatal("created an association beyond setup capacity")
			}
			plane.udpSetups.Store(0)
			send()
			if plane.udpSetups.Load() != 0 {
				t.Fatal("completed setup retained admission")
			}
			plane.udpSetups.Store(maxConcurrentUDPSetups)
			send()
			if plane.udpSetupDrops.total.Load() != 1 || len(recorder.targets) != 1 {
				t.Fatal("established association passed through setup admission")
			}
			plane.udpSetups.Store(0)
			endpoint, ok := endpoints.Get(source)
			if !ok || endpoint.destinations[original] != target || endpoint.destinationParam.routingResult.Mark != 37 || endpoint.destinationParam.routingResult.ProfileId != 42 || len(recorder.targets) != 1 || recorder.targets[0] != target.String() {
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
			if current, ok := endpoints.Get(source); !ok || current != endpoint || current.destinations[original] != target || current.destinationParam.routingResult.Mark != 37 || current.destinationParam.routingResult.ProfileId != 42 || len(recorder.targets) != 1 {
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
			if !ok || fresh == endpoint || fresh.destinations[original] != newTarget || fresh.destinationParam.routingResult.Mark != 91 || fresh.destinationParam.routingResult.ProfileId != profileID || len(recorder.targets) != 2 || recorder.targets[1] != newTarget.String() {
				t.Fatalf("new lifetime did not use current target/policy: endpoint=%+v dials=%v", fresh, recorder.targets)
			}
			var epoch uint64
			if err := bindings.Lookup(udpSourceKey(source), &epoch); err != nil {
				t.Fatalf("replacement source binding missing: %v", err)
			}
		})
	}
}
