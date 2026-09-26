//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
)

// Measure the uninstrumented LAN classifier, not test_bridge_ingress (which
// reads metadata a second time to observe it). TEST_RUN cannot create bridge
// extensions, so live packets and per-program kernel runtime counters are used.
// bpf-ns/pkt excludes send syscalls and bridge/netfilter work outside BPF; Go's
// ns/op includes that work and represents a batch, not one packet.
func BenchmarkBridgePhysinif(b *testing.B) {
	for _, scenario := range []struct {
		name      string
		netfilter bool
		proto     uint8
		flags     uint8
	}{
		{"SYN/no-metadata", false, unix.IPPROTO_TCP, 2},
		{"SYN/metadata", true, unix.IPPROTO_TCP, 2},
		{"TCP/established", true, unix.IPPROTO_TCP, 16},
		{"UDP/cache-hit", true, unix.IPPROTO_UDP, 0},
	} {
		b.Run(scenario.name, func(b *testing.B) {
			withTestBridge(b, func(f *bridgeFixture) {
				// Suppress unrelated IPv6 address-discovery packets during timing.
				if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/disable_ipv6", []byte("1"), 0); err != nil {
					b.Fatal(err)
				}
				setBridgeNetfilter(b, scenario.netfilter)
				obj, err := loadTestObjects(b)
				if err != nil {
					b.Fatal(err)
				}
				installRoutingFlow(b, obj, []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback)}})
				program := obj.LanIngressL2
				attached, err := link.AttachTCX(link.TCXOptions{Interface: f.bridge.Index, Program: program, Attach: ebpf.AttachTCXIngress})
				if err != nil {
					b.Fatal(err)
				}
				defer attached.Close()
				stats, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
				if err != nil {
					b.Fatal(err)
				}
				defer stats.Close()
				packet := bridgePacket(netip.MustParseAddrPort("192.0.2.2:40000"), netip.MustParseAddrPort("192.0.2.1:443"), scenario.proto, f.bridge.HardwareAddr, scenario.flags)
				destination := &unix.SockaddrLinklayer{Ifindex: f.peers[0].Attrs().Index, Protocol: nativeUint16(unix.ETH_P_ALL)}
				const batch = 1024
				send := func() {
					for range batch {
						if err := unix.Sendto(f.fd, packet, 0, destination); err != nil {
							b.Fatal(err)
						}
					}
				}
				send() // Warm instruction/data caches and the UDP source decision.
				var elapsed time.Duration
				var packets uint64
				for b.Loop() {
					before, err := program.Stats()
					if err != nil {
						b.Fatal(err)
					}
					send()
					after, err := program.Stats()
					if err != nil {
						b.Fatal(err)
					}
					if count := after.RunCount - before.RunCount; count != batch {
						b.Fatalf("received %d classifier runs, want %d; timing contaminated or packets still queued", count, batch)
					}
					elapsed += after.Runtime - before.Runtime
					packets += batch
				}
				b.ReportMetric(float64(elapsed.Nanoseconds())/float64(packets), "bpf-ns/pkt")
			})
		})
	}
}
