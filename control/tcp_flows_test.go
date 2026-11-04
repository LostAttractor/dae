// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
	"golang.org/x/sys/unix"
)

func TestTCPProxyTupleBecomesInbound(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, fragmented := range []bool{false, true} {
			t.Run(fmt.Sprintf("ipv6=%t/fragmented=%t", ipv6, fragmented), func(t *testing.T) {
				collection, state := routingKernelFixture(t, nil, 0, func(spec *ebpf.CollectionSpec) {
					full, err := loadBpf()
					if err != nil {
						t.Fatal(err)
					}
					spec.Programs["lan_egress_l2"] = full.Programs["lan_egress_l2"]
					spec.Programs["tproxy_wan_ingress_l2"] = full.Programs["tproxy_wan_ingress_l2"]
				})
				network, address := "tcp4", "127.0.0.1:0"
				dst := netip.MustParseAddrPort("198.51.100.1:50000")
				if ipv6 {
					network, address, dst = "tcp6", "[::1]:0", netip.MustParseAddrPort("[2001:db8::2]:50000")
				}
				listener, err := net.Listen(network, address)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				src := listener.Addr().(*net.TCPAddr).AddrPort()
				prepared := prepareFlowRulesForTest(t, "", "l4proto(tcp) -> direct(mark:17)")
				prepared.enableMITMPlan(plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: plugin.Scope{{Host: dst.Addr().String(), Ports: []uint16{dst.Port()}}}, PreserveRoute: true}}})
				builder, _ := routingMatcherForTest(t, prepared)
				builder.bpf = state
				if err := builder.BuildKernspace(); err != nil {
					t.Fatal(err)
				}
				run := func(name string, packet []byte, want uint32) {
					t.Helper()
					got, err := collection.Programs[name].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256)})
					if err != nil || got != want {
						t.Fatalf("%s: verdict=%d err=%v, want %d", name, got, err, want)
					}
				}
				key := tuplesKey(src, dst, unix.IPPROTO_TCP)
				for _, paths := range [][2]string{{"lan_ingress_l2", "lan_egress_l2"}, {"tproxy_wan_egress_l2", "tproxy_wan_ingress_l2"}} {
					syn, _ := routingKernelPacket(src, dst, consts.L4ProtoType_TCP)
					run(paths[0], syn, 7)
					reply := slices.Clone(syn)
					reply[len(reply)-7] = 0x12
					binary.BigEndian.PutUint32(reply[len(reply)-16:], 0x5678)
					binary.BigEndian.PutUint32(reply[len(reply)-12:], 0x1235)
					// A pending proxy handshake must not be cleared by a SYN-ACK from the other direction.
					run(paths[0], reply, 7)
					if _, err := retrieveRoutingResult(collection.Maps["routing_tuples_map"], src, dst, unix.IPPROTO_TCP); err != nil {
						t.Fatal(err)
					}
					inbound, _ := routingKernelPacket(dst, src, consts.L4ProtoType_TCP)
					binary.BigEndian.PutUint32(inbound[len(inbound)-16:], 0x1234)
					run(paths[1], inbound, ^uint32(0))
					var old bpfTcpFlowState
					if err := collection.Maps["tcp_flow_map"].Lookup(key, &old); !errors.Is(err, ebpf.ErrKeyNotExist) {
						t.Fatalf("inbound SYN created flow properties: %+v, %v", old, err)
					}
					if fragmented {
						// Four payload bytes align the TCP first fragment to eight bytes.
						reply = append(reply, 0, 0, 0, 0)
						if ipv6 {
							reply = slices.Insert(reply, 54, 6, 0, 0, 1, 0, 0, 0, 0)
							reply[20] = 44
							binary.BigEndian.PutUint16(reply[18:20], 32)
						} else {
							binary.BigEndian.PutUint16(reply[16:18], 44)
							binary.BigEndian.PutUint16(reply[20:22], 0x2000)
						}
					}
					// Once accept consumed the setup, the answer is native and
					// carries none of the outbound rule's properties.
					run(paths[0], reply, ^uint32(0))
					if err := collection.Maps["tcp_flow_map"].Lookup(key, &old); !errors.Is(err, ebpf.ErrKeyNotExist) {
						t.Fatalf("inbound answer acquired flow properties: %+v, %v", old, err)
					}
					syn[len(syn)-7] = 0x10
					run(paths[0], syn, ^uint32(0))
				}
			})
		}
	}
}

func TestTCPFlowSurvivesRealIngressRelayClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		spec, err := loadBpf()
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range spec.Maps {
			m.Pinning = ebpf.PinNone
		}
		objects := new(bpfObjects)
		if err := spec.LoadAndAssign(objects, nil); errors.Is(err, unix.EPERM) {
			t.Skip("BPF privileges required")
		} else if err != nil {
			t.Fatal(err)
		}
		defer objects.Close()
		r := NewRuntime()
		defer func() { clear(r.planes); _ = r.Close() }()
		if err := r.retainMaps(objects); err != nil {
			t.Fatal(err)
		}
		upstream, remote := net.Pipe()
		defer upstream.Close()
		defer remote.Close()
		plane, _, _ := newHTTPRequestRouteTest(t, "", new(controlTestPlugin), func(context.Context, string, string) (net.Conn, error) { return remote, nil })
		plane.ctx, plane.cancel = context.WithCancel(t.Context())
		defer plane.cancel()
		plane.planeTraffic = newPlaneTraffic(plane.ctx, &r.tcpConnections, r.udpEndpoints)
		plane.dnsRelay = newDNSRelay()
		defer plane.retireTraffic()
		plane.core.bpf = &BPFState{Runtime: r}
		plane.deviceRoutes = new(deviceRoutes)
		plane.routingGeneration = 1
		r.planes[1], r.current = plane, plane
		lc := tproxyListenConfig()
		tcp, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer tcp.Close()
		udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer udp.Close()
		client, err := net.Dial("tcp4", tcp.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		key := tuplesKey(client.LocalAddr().(*net.TCPAddr).AddrPort(), client.RemoteAddr().(*net.TCPAddr).AddrPort(), unix.IPPROTO_TCP)
		flow := bpfTcpFlowState{Mark: 37}
		if err := objects.TcpFlowMap.Update(key, flow, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		if err := objects.RoutingTuplesMap.Update(key, testRoutingHandoff(t, bpfRoutingResult{Generation: 1}), ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		ready, served := make(chan bool, 1), make(chan error, 1)
		go func() { served <- r.Serve(ready, &Listener{tcpListener: tcp, packetConn: udp}) }()
		if !<-ready {
			t.Fatal(<-served)
		}
		if _, err := client.Write([]byte("ok")); err != nil {
			t.Fatal(err)
		}
		var data [2]byte
		if _, err := io.ReadFull(upstream, data[:]); err != nil || string(data[:]) != "ok" {
			t.Fatalf("production relay did not deliver data: %q, %v", data, err)
		}
		_ = client.Close()
		_ = upstream.Close()
		_ = tcp.Close()
		_ = udp.Close()
		<-served
		r.ingress.Wait()
		synctest.Wait()
		// Ingress and relay have exited; advance past the former cleanup deadline.
		time.Sleep(61 * time.Second)
		synctest.Wait()
		var got bpfTcpFlowState
		if err := objects.TcpFlowMap.Lookup(key, &got); err != nil || got != flow {
			t.Fatalf("userspace relay closure deleted kernel flow state: %+v, %v", got, err)
		}
	})
}

func TestTCPFlowStateOwnedByKernel(t *testing.T) {
	for _, closeFirst := range []bool{true, false} {
		for _, next := range []struct {
			name    string
			capture bool
			mark    uint32
		}{
			{"proxy", true, 37},
			{"marked-direct", false, 37},
			{"unmarked-direct", false, 0},
		} {
			t.Run(fmt.Sprintf("%s/close-first=%t", next.name, closeFirst), func(t *testing.T) {
				collection, state := dnsKernelCollection(t)
				flowMap := collection.Maps["tcp_flow_map"]
				if flowMap.Type() != ebpf.LRUHash {
					t.Fatal("idle TCP state must be reclaimed by a bounded LRU")
				}
				accepted, client := relayTestTCPPair(t)
				raw, err := accepted.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				// Match production: ordinary TCP sockets linger in FIN_WAIT2 after Close.
				listenConfig := tproxyListenConfig()
				if err := listenConfig.Control("tcp4", "", raw); err != nil {
					t.Fatal(err)
				}
				src, dst := accepted.RemoteAddr().(*net.TCPAddr).AddrPort(), accepted.LocalAddr().(*net.TCPAddr).AddrPort()
				key := tuplesKey(src, dst, unix.IPPROTO_TCP)
				configure := func(state *BPFState, capture bool, mark uint32) {
					t.Helper()
					prepared := prepareFlowRulesForTest(t, "", fmt.Sprintf("l4proto(tcp) -> direct(mark:%d)", mark))
					if capture {
						prepared.enableMITMPlan(plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: plugin.Scope{{Host: dst.Addr().String(), Ports: []uint16{dst.Port()}}}, PreserveRoute: true}}})
					}
					builder, _ := routingMatcherForTest(t, prepared)
					builder.bpf = state
					if err := builder.BuildKernspace(); err != nil {
						t.Fatal(err)
					}
				}
				run := func(collection *ebpf.Collection, packet []byte, want uint32) {
					t.Helper()
					for _, name := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
						status, err := collection.Programs[name].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256)})
						if err != nil || status != want {
							t.Fatalf("%s: verdict=%d err=%v, want %d", name, status, err, want)
						}
					}
				}
				checkFlow := func(want *bpfTcpFlowState) {
					t.Helper()
					var flow bpfTcpFlowState
					err := flowMap.Lookup(&key, &flow)
					if want == nil {
						if !errors.Is(err, ebpf.ErrKeyNotExist) {
							t.Fatalf("proxy retained a native admission: %+v, %v", flow, err)
						}
					} else if err != nil || flow != *want {
						t.Fatalf("TCP state=%+v err=%v, want %+v", flow, err, *want)
					}
				}
				// Accept the old proxy flow without a native forwarding admission.
				configure(state, true, 17)
				syn, _ := routingKernelPacket(src, dst, consts.L4ProtoType_TCP)
				run(collection, syn, 7)
				if _, err := retrieveRoutingResult(collection.Maps["routing_tuples_map"], src, dst, unix.IPPROTO_TCP); err != nil {
					t.Fatal(err)
				}
				var oldFlow *bpfTcpFlowState
				checkFlow(oldFlow)
				closeRelay := func() {
					t.Helper()
					relay := tcpRelay{lConn: accepted, custom: func() error { return nil }}
					if err := relay.run(); err != nil {
						t.Fatal(err)
					}
					if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
						t.Fatalf("old relay did not close the client connection: %v", err)
					}
					// End the old kernel socket before replaying the reused tuple's ACK.
					if err := client.SetLinger(0); err != nil {
						t.Fatal(err)
					}
					if err := client.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if closeFirst {
					closeRelay()
					// The proxy lifetime ended with dae's socket: late packets are
					// native and never acquire properties.
					for _, flags := range []byte{0x10, 0x11, 0x14} {
						late := slices.Clone(syn)
						late[len(late)-7] = flags
						run(collection, late, ^uint32(0))
						checkFlow(oldFlow)
					}
				}
				replacement, nextState := dnsKernelGeneration(t, map[string]*ebpf.Map{"tcp_flow_map": flowMap, "routing_tuples_map": collection.Maps["routing_tuples_map"]}, 1)
				configure(nextState, next.capture, next.mark)
				fresh := slices.Clone(syn)
				fresh[len(fresh)-13]++
				verdict := ^uint32(0)
				want := new(bpfTcpFlowState{Mark: next.mark, SynSeq: binary.NativeEndian.Uint32(fresh[len(fresh)-16:])})
				if next.capture {
					verdict, want = 7, nil
				}
				run(replacement, fresh, verdict)
				checkFlow(want)
				if !closeFirst {
					closeRelay()
					checkFlow(want)
				}
				fresh[len(fresh)-7] = 0x10
				run(replacement, fresh, verdict)
				checkFlow(want)
			})
		}
	}
}
