// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/settings"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// Prepare a real private projection, including many static tries and one
// client membership which can change while a candidate is being prepared.
func runtimeRefreshFixture(t testing.TB) (*ControlPlane, *ebpf.Collection) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("BPF privileges required")
	}
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	for name := range spec.Programs {
		if name != "lan_ingress_l2" {
			delete(spec.Programs, name)
		}
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(collection.Close)
	var maps bpfMaps
	var variables bpfVariables
	if err := collection.Assign(&maps); err != nil {
		t.Fatal(err)
	}
	if err := collection.Assign(&variables); err != nil {
		t.Fatal(err)
	}
	state := &BPFState{bpfObjects: &bpfObjects{bpfMaps: maps, bpfVariables: variables}}
	var rules strings.Builder
	for i := range 64 {
		fmt.Fprintf(&rules, "dip(10.%d.0.0/16) -> direct(mark: %d)\n", i, i+1)
	}
	rules.WriteString("client(gaming) -> block\n")
	matcher, builder := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", rules.String()))
	builder.bpf = state
	store, err := settings.Open(filepath.Join(t.TempDir(), "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := &ControlPlane{core: &controlPlaneCore{bpf: state, closed: t.Context()}, settings: store, routingMatcher: matcher, routingMatcherBuilder: builder, routingState: builder.routingState}
	if err := c.PrepareKernel(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(state.clearRoutingRegistrations)
	return c, collection
}

func TestPreparedGenerationRefreshesLatestKernelMembership(t *testing.T) {
	c, collection := runtimeRefreshFixture(t)
	packet, _ := routingKernelPacket(netip.MustParseAddrPort("192.0.2.1:42000"), netip.MustParseAddrPort("198.51.100.1:443"), consts.L4ProtoType_TCP)
	mac := [6]byte{2, 0, 0, 0, 0, 10}
	copy(packet[6:12], mac[:])
	run := func(want uint32) {
		status, err := collection.Programs["lan_ingress_l2"].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256)})
		if err != nil || status != want {
			t.Fatalf("kernel verdict=%d, %v; want %d", status, err, want)
		}
	}
	run(^uint32(0))
	if err := c.settings.SetMembers("gaming", [][6]byte{mac}); err != nil {
		t.Fatal(err)
	}
	run(^uint32(0)) // the running API changed preferences, not candidate maps
	if err := c.restoreRuntimeSettings(true); err != nil {
		t.Fatal(err)
	}
	run(2)
}

func BenchmarkRuntimeKernelRefresh(b *testing.B) {
	level := log.GetLevel()
	log.SetLevel(log.ErrorLevel)
	b.Cleanup(func() { log.SetLevel(level) })
	for _, changed := range []bool{false, true} {
		b.Run(fmt.Sprintf("changed=%t", changed), func(b *testing.B) {
			c, _ := runtimeRefreshFixture(b)
			mac := [6]byte{2, 0, 0, 0, 0, 10}
			b.ReportAllocs()
			for b.Loop() {
				if changed {
					b.StopTimer()
					mac[5] ^= 1
					if err := c.settings.SetMembers("gaming", [][6]byte{mac}); err != nil {
						b.Fatal(err)
					}
					b.StartTimer()
				}
				if err := c.restoreRuntimeSettings(true); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkRuntimeIngress(b *testing.B) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.SockMap, KeySize: 4, ValueSize: 8, MaxEntries: 2})
	if errors.Is(err, unix.EPERM) {
		b.Skip("BPF privileges required")
	}
	if err != nil {
		b.Fatal(err)
	}
	defer m.Close()
	var extraFDs int
	lc := net.ListenConfig{}
	lc.SetMultipathTCP(false)
	b.ReportAllocs()
	for b.Loop() {
		r := NewRuntime()
		r.shared["listen_socket_map"], err = m.Clone()
		if err != nil {
			b.Fatal(err)
		}
		tcp, err := lc.Listen(b.Context(), "tcp4", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		// Count only descriptors added by Serve. The existing listener sockets
		// and retained map descriptor are required in every compared variant.
		before, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		ready, done := make(chan bool, 1), make(chan error, 1)
		go func() { done <- r.Serve(ready, &Listener{tcpListener: tcp, packetConn: udp}) }()
		if !<-ready {
			b.Fatal(<-done)
		}
		b.StopTimer()
		after, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			b.Fatal(err)
		}
		extraFDs = len(after) - len(before)
		b.StartTimer()
		if err := r.Close(); err != nil {
			b.Fatal(err)
		}
		if err := <-done; err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(extraFDs), "extra-fds")
}
