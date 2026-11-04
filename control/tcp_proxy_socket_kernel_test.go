// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestTCPProxyTupleKeepsAcceptedSocket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("BPF privileges required")
	}
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, separate := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/separate-netns=%t", network, separate), func(t *testing.T) {
				proxyID := int32(-1)
				if separate && os.Getenv("DAE_TEST_ISOLATED") != "1" {
					t.Skip("requires an isolated network namespace")
				}
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				host, err := netns.Get()
				if err != nil {
					t.Fatal(err)
				}
				defer host.Close()
				defer netns.Set(host)
				var proxy netns.NsHandle
				if separate {
					proxy, err = netns.New()
					if err != nil {
						t.Fatal(err)
					}
					defer proxy.Close()
					lo, err := netlink.LinkByName("lo")
					if err != nil {
						t.Fatal(err)
					}
					if err := netlink.LinkSetUp(lo); err != nil {
						t.Fatal(err)
					}
				}
				address := "127.0.0.1:0"
				if network == "tcp6" {
					address = "[::1]:0"
				}
				lc := tproxyListenConfig()
				listener, err := lc.Listen(t.Context(), network, address)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				client, err := net.DialTimeout(network, listener.Addr().String(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				accepted, err := listener.(*net.TCPListener).AcceptTCP()
				if err != nil {
					t.Fatal(err)
				}
				defer accepted.Close()
				if err := accepted.SetLinger(0); err != nil {
					t.Fatal(err)
				}
				if err := netns.Set(host); err != nil {
					t.Fatal(err)
				}
				if separate {
					ns := &DaeNetns{daeNs: proxy}
					if err := ns.setupNetnsID(); err != nil {
						t.Fatal(err)
					}
					proxyID = ns.ID()
				}
				collection, state := routingKernelFixture(t, nil, 1, func(spec *ebpf.CollectionSpec) {
					if separate {
						variable, ok := spec.Variables["proxy_netns_id"]
						if !ok {
							t.Fatal("missing proxy network namespace constant")
						}
						if err := variable.Set(proxyID); err != nil {
							t.Fatal(err)
						}
					}
				})
				src, dst := accepted.RemoteAddr().(*net.TCPAddr).AddrPort(), accepted.LocalAddr().(*net.TCPAddr).AddrPort()
				prepared := prepareFlowRulesForTest(t, "", "")
				prepared.enableMITMPlan(plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: plugin.Scope{{Host: dst.Addr().String(), Ports: []uint16{dst.Port()}}}, PreserveRoute: true}}})
				builder, _ := routingMatcherForTest(t, prepared)
				builder.bpf = state
				if err := builder.BuildKernspace(); err != nil {
					t.Fatal(err)
				}
				run := func(packet []byte, want uint32) {
					t.Helper()
					for _, name := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
						got, err := collection.Programs[name].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256)})
						if err != nil || got != want {
							t.Fatalf("%s: verdict=%d err=%v, want %d", name, got, err, want)
						}
					}
				}
				syn, _ := routingKernelPacket(src, dst, consts.L4ProtoType_TCP)
				binary.BigEndian.PutUint32(syn[len(syn)-16:], 0x40000000)
				run(syn, 7)
				if _, err := retrieveRoutingResult(collection.Maps["routing_tuples_map"], src, dst, unix.IPPROTO_TCP); err != nil {
					t.Fatal(err)
				}
				late := slices.Clone(syn)
				late[len(late)-7] = 0x12
				binary.BigEndian.PutUint32(late[len(late)-16:], 0x100)
				binary.BigEndian.PutUint32(late[len(late)-12:], 0x200)
				run(late, 7)
				key := tuplesKey(src, dst, unix.IPPROTO_TCP)
				var flow bpfTcpFlowState
				if err := collection.Maps["tcp_flow_map"].Lookup(key, &flow); !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("proxy retained native admission after late SYN-ACK: %+v, %v", flow, err)
				}
				syn[len(syn)-7] = 0x10
				run(syn, 7)
				// dae's live socket owns every segment of its flow.
				for _, flags := range []byte{0x10, 0x11, 0x14, 0x12} {
					packet := slices.Clone(syn)
					packet[len(packet)-7] = flags
					run(packet, 7)
				}
				fragment := append(slices.Clone(syn), 0, 0, 0, 0)
				if network == "tcp6" {
					fragment = slices.Insert(fragment, 54, 6, 0, 0, 1, 0, 0, 0, 0)
					fragment[20] = 44
					binary.BigEndian.PutUint16(fragment[18:20], 32)
				} else {
					binary.BigEndian.PutUint16(fragment[16:18], 44)
					binary.BigEndian.PutUint16(fragment[20:22], 0x2000)
				}
				run(fragment, 2)
				if _, err := client.Write([]byte("ok")); err != nil {
					t.Fatal(err)
				}
				if err := accepted.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				var data [2]byte
				if _, err := io.ReadFull(accepted, data[:]); err != nil || string(data[:]) != "ok" {
					t.Fatalf("socket lookup disturbed the accepted connection: %q, %v", data, err)
				}
				// Once the socket is gone the tuple is unowned: native, without properties.
				_ = accepted.Close()
				_ = client.Close()
				run(late, ^uint32(0))
				if err := collection.Maps["tcp_flow_map"].Lookup(key, &flow); !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("unowned SYN-ACK created flow properties: %+v, %v", flow, err)
				}
			})
		}
	}
}
