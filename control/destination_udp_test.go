// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type destinationUDPRecorder struct {
	surgeDownloadTestDialer
	targets []string
}

func (d *destinationUDPRecorder) ListenPacket(_ context.Context, target string) (net.PacketConn, error) {
	d.targets = append(d.targets, target)
	return newTestPacketConn(false), nil
}

// Exercise real UDP association creation, replacement and private ownership maps.
// Packet conns record dials without sending traffic or attaching BPF programs.
func TestDestinationUDPReplacementKernelIntegration(t *testing.T) {
	for _, rewritten := range []bool{false, true} {
		t.Run(fmt.Sprint(rewritten), func(t *testing.T) {
			tuples := newRoutingLayoutTestMap(t, "routing_tuples_map", 8)
			owners := newRoutingLayoutTestMap(t, "destination_udp_map", 8)
			var endpoints UdpEndpointPool
			defer endpoints.closeAll()
			source, original := netip.MustParseAddrPort("192.0.2.10:5000"), netip.MustParseAddrPort("192.0.2.20:53")
			target, filter := original, "domain(full: declared.example)"
			if rewritten {
				target, filter = netip.MustParseAddrPort("198.51.100.20:53"), "dip(192.0.2.20)"
			}
			matcher, _ := surgeRoutingMatcher(t, prepareFlowRulesForTest(t, filter+" -> dnat(198.51.100.20)", "dip(192.0.2.20,198.51.100.20) -> proxy(mark:37)"))
			unused := surgeDownloadTestDialer(func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("UDP association must use the selected packet dialer")
				return nil, net.ErrClosed
			})
			recorder := &destinationUDPRecorder{surgeDownloadTestDialer: unused}
			newGroup := func() *outbound.DialerGroup {
				global := &dialer.GlobalOption{}
				d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: recorder}), global, &dialer.Property{Name: t.Name()}, false, "")
				group := outbound.NewDialerGroup(global, "proxy", outbound.GroupKindSingleAlwaysAlive, []*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, nil)
				t.Cleanup(func() { _ = group.Close() })
				return group
			}
			plane := &ControlPlane{udpEndpoints: &endpoints, routingMatcher: matcher,
				core:      &controlPlaneCore{bpf: &bpfState{bpfObjects: &bpfObjects{bpfMaps: bpfMaps{RoutingTuplesMap: tuples, DestinationUdpMap: owners}}}},
				outbounds: []*outbound.DialerGroup{surgeDownloadTestGroup(t, "direct", unused), surgeDownloadTestGroup(t, "block", unused), newGroup()},
			}
			result := bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting), CaptureFlags: captureDestination, Ifindex: 7}
			key := bpfTuplesKey{Sport: common.Htons(source.Port()), Dport: common.Htons(original.Port()), L4proto: 17}
			key.Sip.U6Addr8, key.Dip.U6Addr8 = source.Addr().As16(), original.Addr().As16()
			if err := tuples.Update(key, result, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			association := udpRoutingKey(source, original, &result)
			for generation, wantMark := range []uint32{37, 91} {
				if err := plane.handlePkt(t.Context(), []byte("payload"), source, original, true, "", false); err != nil {
					t.Fatal(err)
				}
				endpoint, ok := endpoints.Get(association)
				if !ok || endpoint.destination != target || len(recorder.targets) != generation+1 || recorder.targets[generation] != target.String() {
					t.Fatalf("generation %d changed the session target: endpoint=%+v dials=%v", generation, endpoint, recorder.targets)
				}
				var owner bpfDestinationUdpValue
				if err := owners.Lookup(bpfDestinationUdpKey{Tuples: key, Ifindex: 7}, &owner); err != nil || owner.Result.Mark != wantMark {
					t.Fatalf("generation %d lost current policy/ownership: %+v, %v", generation, owner, err)
				}
				if generation == 0 {
					// Replace both config and node. The old target must survive even
					// when the old rule missed, while mark comes from the new policy.
					plane.routingMatcher, _ = surgeRoutingMatcher(t, prepareFlowRulesForTest(t, "dip(192.0.2.20) -> dnat(203.0.113.20)", "dip(192.0.2.20,198.51.100.20) -> proxy(mark:91)\ndip(203.0.113.20) -> block"))
					if err := endpoint.dialer.Close(); err != nil {
						t.Fatal(err)
					}
					plane.outbounds[2] = newGroup()
				}
			}
		})
	}
}
