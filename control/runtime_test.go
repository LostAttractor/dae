// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
)

func testRoutingHandoff(t testing.TB, result bpfRoutingResult) bpfRoutingHandoff {
	t.Helper()
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		t.Fatal(err)
	}
	return bpfRoutingHandoff{Result: result, Expires: uint32(now.Sec) + 30}
}

func TestRuntimeTCPHandoffAdmission(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	m, err := ebpf.NewMap(spec.Maps["routing_tuples_map"])
	if errors.Is(err, unix.EPERM) {
		t.Skip("BPF maps require privileges")
	}
	if err != nil {
		t.Fatal(err)
	}
	r := NewRuntime()
	r.shared["routing_tuples_map"] = m
	t.Cleanup(func() { clear(r.planes); _ = r.Close() })
	old, next := newLifecycleTestControlPlane(t, r.udpEndpoints), newLifecycleTestControlPlane(t, r.udpEndpoints)
	for i, plane := range []*ControlPlane{old, next} {
		plane.routingGeneration = uint32(i + 1)
		plane.tcpConnections.connections = &r.tcpConnections
		r.planes[plane.routingGeneration] = plane
		t.Cleanup(func() { _ = plane.retireTraffic() })
	}
	r.current = next
	for _, test := range []struct {
		name             string
		generation       uint32
		expired, retired bool
	}{
		{"queued old generation", 1, false, false}, {"new generation", 2, false, false},
		{"expired mailbox", 1, true, false}, {"unpublished candidate", 3, false, false},
		{"retired generation", 1, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			accepted, client := relayTestTCPPair(t)
			src, dst := accepted.RemoteAddr().(*net.TCPAddr).AddrPort(), accepted.LocalAddr().(*net.TCPAddr).AddrPort()
			key := bpfTuplesKey{Sport: common.Htons(src.Port()), Dport: common.Htons(dst.Port()), L4proto: unix.IPPROTO_TCP}
			key.Sip.U6Addr8, key.Dip.U6Addr8 = src.Addr().As16(), dst.Addr().As16()
			var now unix.Timespec
			if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
				t.Fatal(err)
			}
			handoff := bpfRoutingHandoff{Result: bpfRoutingResult{Generation: test.generation, Outbound: 2, Mark: 37}, Expires: uint32(now.Sec) + 30}
			if test.expired {
				handoff.Expires = uint32(now.Sec) - 1
			}
			if test.retired {
				old.tcpConnections.stopAccepting()
			}
			if err := m.Update(key, handoff, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			plane, result := r.admitTCP(accepted)
			if plane != nil {
				plane.tcpConnections.finishSetup()
				defer plane.tcpConnections.removeConnection(accepted)
			}
			if test.expired || test.retired || test.generation == 3 {
				if plane != nil {
					t.Fatal("admitted an invalid generation")
				}
				_ = client.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := client.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
					t.Fatalf("rejected setup: %v, want RST", err)
				}
			} else {
				if plane != r.planes[test.generation] || result.Outbound != 2 || result.Mark != 37 {
					t.Fatalf("wrong generation or route: %p, %+v", plane, result)
				}
				if _, err := accepted.Write([]byte("ok")); err != nil {
					t.Fatal(err)
				}
				var data [2]byte
				if _, err := io.ReadFull(client, data[:]); err != nil {
					t.Fatal(err)
				}
			}
			if err := m.Lookup(key, &handoff); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("handoff was not consumed: %v", err)
			}
		})
	}
}

// Userspace re-evaluation of a kernel decision sees the local process name.
func TestRoutingHandoffProcessNameReachesUserspaceRules(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: uint32(unsafe.Sizeof(bpfTuplesKey{})), ValueSize: uint32(unsafe.Sizeof(bpfRoutingHandoff{})), MaxEntries: 1})
	if errors.Is(err, unix.EPERM) {
		t.Skip("BPF maps require privileges")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	src, dst := netip.MustParseAddrPort("192.0.2.10:5000"), netip.MustParseAddrPort("198.51.100.1:443")
	key := bpfTuplesKey{Sport: common.Htons(src.Port()), Dport: common.Htons(dst.Port()), L4proto: unix.IPPROTO_TCP}
	key.Sip.U6Addr8, key.Dip.U6Addr8 = src.Addr().As16(), dst.Addr().As16()
	handoff := testRoutingHandoff(t, bpfRoutingResult{Outbound: 2})
	copy(handoff.Pname[:], "curl")
	if err := m.Update(key, handoff, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	result, err := retrieveRoutingResult(m, src, dst, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "pname(curl) -> proxy"))
	outbound, _, _, err := matcher.match(result.routingInput(src, dst, "verified.example", consts.L4ProtoType_TCP))
	if err != nil || outbound != consts.OutboundUserDefinedMin {
		t.Fatalf("re-evaluated outbound = %d, %v; want the pname() route", outbound, err)
	}
}
