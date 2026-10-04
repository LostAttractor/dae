// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
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
	old, next := newLifecycleTestControlPlane(r.udpEndpoints), newLifecycleTestControlPlane(r.udpEndpoints)
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
