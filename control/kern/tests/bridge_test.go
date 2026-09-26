//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type bridgeFixture struct {
	bridge       *netlink.Bridge
	ports, peers []netlink.Link
	fd           int
}

// Run on one locked thread: subtests must create their own fixture rather than
// inherit a namespace from their parent's goroutine. Cleanup restores the
// namespace before the thread can return to the scheduler.
func withTestBridge(t testing.TB, run func(*bridgeFixture)) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root is required for the isolated bridge test")
	}
	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	defer original.Close()
	defer func() {
		if err := netns.Set(original); err != nil {
			t.Fatalf("restore namespace: %v", err)
		}
		runtime.UnlockOSThread()
	}()
	isolated, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer isolated.Close()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	setBridgeNetfilter(t, true)
	bridge := &netlink.Bridge{Name: "br-test", HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}}
	must(netlink.LinkAdd(bridge))
	must(netlink.LinkSetUp(bridge))
	var ports, peers []netlink.Link
	for i, name := range []string{"lan", "direct"} {
		port := &netlink.Veth{Name: name, PeerName: fmt.Sprintf("peer%d", i)}
		must(netlink.LinkAdd(port))
		must(netlink.LinkSetMaster(port, bridge))
		must(netlink.LinkSetUp(port))
		peer, err := netlink.LinkByName(port.PeerName)
		must(err)
		must(netlink.LinkSetUp(peer))
		ports, peers = append(ports, port), append(peers, peer)
	}
	for _, cidr := range []string{"192.0.2.1/24", "2001:db8::1/64"} {
		addr, err := netlink.ParseAddr(cidr)
		must(err)
		addr.Flags = unix.IFA_F_NODAD
		must(netlink.AddrAdd(bridge, addr))
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(nativeUint16(unix.ETH_P_ALL)))
	must(err)
	defer unix.Close(fd)
	run(&bridgeFixture{bridge: bridge, ports: ports, peers: peers, fd: fd})
}

func setBridgeNetfilter(t testing.TB, enabled bool) {
	t.Helper()
	value := []byte("0")
	if enabled {
		value = []byte("1")
	}
	for _, name := range []string{"bridge-nf-call-iptables", "bridge-nf-call-ip6tables"} {
		err := os.WriteFile("/proc/sys/net/bridge/"+name, value, 0)
		if errors.Is(err, os.ErrNotExist) {
			t.Skip("load br_netfilter to exercise live bridge member metadata")
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// A real bridge is necessary: BPF_PROG_TEST_RUN cannot supply skb extensions.
// All links and sysctl changes are confined to this test's network namespace.
func TestBridgePhysinif(t *testing.T) {
	withTestBridge(t, func(f *bridgeFixture) {
		bridge, ports, peers, fd := f.bridge, f.ports, f.peers, f.fd
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		obj, err := loadTestObjects(t)
		must(err)
		attached, err := link.AttachTCX(link.TCXOptions{Interface: bridge.Index, Program: obj.TestBridgeIngress, Attach: ebpf.AttachTCXIngress})
		must(err)
		defer attached.Close()
		const mark = uint32(37)
		sport := uint16(40000)
		for _, ipv6 := range []bool{false, true} {
			for _, proto := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
				for _, tc := range []struct {
					name, match               string
					member                    int
					negate, disabled, capture bool
					port                      uint16
					want                      bool
				}{
					{name: "member", port: 443, want: true},
					{name: "other member", member: 1, port: 443},
					{name: "bridge", member: 1, match: "br-test", port: 443, want: true},
					{name: "SSH", port: 22},
					{name: "negated member", negate: true, port: 443},
					{name: "negated other member", member: 1, negate: true, port: 443, want: true},
					{name: "unresolved interface", match: "missing", port: 443},
					{name: "unresolved without metadata", match: "missing", disabled: true, port: 443},
					{name: "metadata absent", disabled: true, port: 443},
					{name: "bridge without metadata", disabled: true, match: "br-test", port: 443, want: true},
					{name: "target capture", capture: true, port: 443, want: true},
					{name: "unrelated HTTPS", capture: true, member: 1, port: 443},
					{name: "capture wrong port", capture: true, port: 22},
				} {
					// Keep sends on the locked namespace thread, rather than t.Run's goroutine.
					name := fmt.Sprintf("%s/ipv6=%v/proto=%d", tc.name, ipv6, proto)
					t.Log(name)
					setBridgeNetfilter(t, !tc.disabled)
					sport++
					index := uint32(ports[0].Attrs().Index)
					switch tc.match {
					case "br-test":
						index = uint32(bridge.Index)
					case "missing":
						index = 0
					}
					intf := bpftestMatchSet{Type: uint8(consts.MatchType_IfIndex), Action: uint8(consts.MatchActionAnd)}
					binary.LittleEndian.PutUint32(intf.Value[:], index)
					if tc.negate {
						intf.Flags = 1 // MATCH_FLAG_NOT
					}
					portRule := routingPortRule(443, consts.MatchActionRoute, consts.OutboundDirect)
					portRule.Mark, portRule.Flags = mark, 2 // MATCH_FLAG_MUST
					if tc.capture {
						portRule.Action, portRule.Flags, portRule.Mark = uint8(consts.MatchActionCapture), 2<<3, 0
					}
					installRoutingFlow(t, obj, []bpftestMatchSet{intf, portRule, {Type: uint8(consts.MatchType_Fallback)}})
					source, destination := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.2"), sport), netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), tc.port)
					if ipv6 {
						source, destination = netip.AddrPortFrom(netip.MustParseAddr("2001:db8::2"), sport), netip.AddrPortFrom(netip.MustParseAddr("2001:db8::1"), tc.port)
					}
					packet := bridgePacket(source, destination, proto, bridge.HardwareAddr, 2)
					must(unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: peers[tc.member].Attrs().Index, Protocol: nativeUint16(unix.ETH_P_ALL)}))
					var observed bpftestBridgeTestResult
					deadline := time.Now().Add(time.Second)
					for {
						err = obj.BridgeTestResults.Lookup(uint32(sport), &observed)
						if err == nil || !errors.Is(err, ebpf.ErrKeyNotExist) || time.Now().After(deadline) {
							break
						}
						time.Sleep(time.Millisecond)
					}
					must(err)
					member := uint32(ports[tc.member].Attrs().Index)
					if tc.disabled {
						member = 0
					}
					verdict, wantMark := ^uint32(0), uint32(0)
					if tc.want {
						wantMark = mark
						if tc.capture {
							verdict, wantMark = 7, 0
						}
					}
					if observed.Ifindex != uint32(bridge.Index) || observed.Physinif != member || observed.Verdict != verdict || observed.Mark != wantMark {
						t.Fatalf("%s: got %+v, want bridge=%d member=%d verdict=%d mark=%d", name, observed, bridge.Index, member, verdict, wantMark)
					}
					key := bpftestTuplesKey{Sport: nativeUint16(sport), Dport: nativeUint16(tc.port), L4proto: proto}
					key.Sip.U6Addr8, key.Dip.U6Addr8 = source.Addr().As16(), destination.Addr().As16()
					if tc.want {
						var result bpftestRoutingResult
						if proto == unix.IPPROTO_UDP && !tc.capture {
							var cached bpftestUdpRoutingCacheValue
							must(obj.UdpRoutingCacheMap.Lookup(bpftestUdpRoutingCacheKey{Sip: key.Sip, Sport: key.Sport}, &cached))
							if cached.Result.Physinif != member || cached.Result.Ifindex != uint32(bridge.Index) || cached.Result.Must != 1 || cached.Result.Mark != mark || cached.Result.Outbound != 0 || cached.Result.CaptureFlags != 0 {
								t.Fatalf("%s: lost cached identity: %+v", name, cached.Result)
							}
						} else {
							must(obj.RoutingTuplesMap.Lookup(key, &result))
							wantOutbound, wantMust, wantCapture := uint8(consts.OutboundDirect), uint8(1), uint8(0)
							if tc.capture {
								wantOutbound, wantMust, wantCapture = uint8(consts.OutboundControlPlaneRouting), 0, 2
							}
							if result.Physinif != member || result.Ifindex != uint32(bridge.Index) || result.Mark != wantMark || result.Outbound != wantOutbound || result.Must != wantMust || result.CaptureFlags != wantCapture {
								t.Fatalf("%s: lost handoff identity: %+v", name, result)
							}
						}
					}
					if proto == unix.IPPROTO_UDP && tc.want && tc.capture {
						// The next packet arrives on the other member without metadata.
						// Its source lifetime must retain the first member and decision.
						setBridgeNetfilter(t, false)
						must(obj.RoutingTuplesMap.Delete(key))
						ctx := make([]byte, 256)
						binary.NativeEndian.PutUint32(ctx[40:44], uint32(ports[1].Attrs().Index))
						status, _, _, err := runBpfProgram(obj.LanIngressL2, packet, ctx)
						must(err)
						var result bpftestRoutingResult
						must(obj.RoutingTuplesMap.Lookup(key, &result))
						if status != 7 || result.Physinif != member || result.Ifindex != uint32(bridge.Index) || result.CaptureFlags != 2 {
							t.Fatalf("%s: cache hit changed identity/decision: status=%d result=%+v", name, status, result)
						}
					}
				}
			}
		}
	})
}

func bridgePacket(source, destination netip.AddrPort, proto uint8, mac net.HardwareAddr, tcpFlags uint8) []byte {
	ipLen, transportLen := 20, 20
	if source.Addr().Is6() {
		ipLen = 40
	}
	if proto == unix.IPPROTO_UDP {
		transportLen = 8
	}
	packet := make([]byte, 14+ipLen+transportLen)
	copy(packet[:6], mac)
	copy(packet[6:12], []byte{2, 0, 0, 0, 0, 2})
	ip, transport := packet[14:], packet[14+ipLen:]
	var pseudo []byte
	if ipLen == 20 {
		binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IP)
		ip[0], ip[8], ip[9] = 0x45, 64, proto
		binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
		copy(ip[12:16], source.Addr().AsSlice())
		copy(ip[16:20], destination.Addr().AsSlice())
		binary.BigEndian.PutUint16(ip[10:12], bridgeChecksum(ip[:20]))
		pseudo = append(pseudo, ip[12:20]...)
		pseudo = append(pseudo, 0, proto, 0, byte(transportLen))
	} else {
		binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IPV6)
		ip[0], ip[6], ip[7] = 0x60, proto, 64
		binary.BigEndian.PutUint16(ip[4:6], uint16(transportLen))
		copy(ip[8:24], source.Addr().AsSlice())
		copy(ip[24:40], destination.Addr().AsSlice())
		pseudo = append(pseudo, ip[8:40]...)
		pseudo = append(pseudo, 0, 0, 0, byte(transportLen), 0, 0, 0, proto)
	}
	binary.BigEndian.PutUint16(transport[:2], source.Port())
	binary.BigEndian.PutUint16(transport[2:4], destination.Port())
	checksumOffset := 16
	if proto == unix.IPPROTO_TCP {
		transport[12], transport[13] = 5<<4, tcpFlags
	} else {
		binary.BigEndian.PutUint16(transport[4:6], uint16(transportLen))
		checksumOffset = 6
	}
	checksum := bridgeChecksum(append(pseudo, transport...))
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(transport[checksumOffset:], checksum)
	return packet
}

func bridgeChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
