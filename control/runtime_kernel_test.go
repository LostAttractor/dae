// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/vishvananda/netlink"
)

func TestRuntimeKernelGenerationIsolationAndLinkUpdate(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("isolated network namespace and BPF privileges required")
	}
	r := NewRuntime()
	t.Cleanup(func() { _ = r.Close() })
	var generation uint32
	load := func() *bpfObjects {
		spec, err := loadBpf()
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range spec.Maps {
			m.Pinning = ebpf.PinNone
		}
		obj := new(bpfObjects)
		if err := spec.LoadAndAssign(obj, &ebpf.CollectionOptions{MapReplacements: r.shared}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = obj.Close() })
		generation++
		if err := obj.RoutingGeneration.Set(generation); err != nil {
			t.Fatal(err)
		}
		if err := obj.RoutingMap.Update(uint32(0), bpfMatchSet{Type: uint8(consts.MatchType_Fallback)}, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		if err := obj.RoutingProfileMap.Update(uint32(0), bpfRoutingProfile{Length: 1}, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		return obj
	}
	old := load()
	if err := r.retainMaps(old); err != nil {
		t.Fatal(err)
	}
	device := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: fmt.Sprintf("dae-rt-%d", os.Getpid()%100000)}}
	if err := netlink.LinkAdd(device); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(device) })
	attached, err := link.AttachTCX(link.TCXOptions{Interface: device.Index, Program: old.LanIngressL2, Attach: ebpf.AttachTCXIngress})
	if err != nil {
		t.Fatal(err)
	}
	r.kernelLinks.ownHostTCXLink(hostTCXLink{linkIndex: device.Index, role: hostTCXLanIngress, program: old.LanIngressL2, link: attached, close: attached.Close})
	initial, err := attached.Info()
	if err != nil {
		t.Fatal(err)
	}
	mapID := func(m *ebpf.Map) ebpf.MapID {
		info, err := m.Info()
		if err != nil {
			t.Fatal(err)
		}
		id, ok := info.ID()
		if !ok {
			t.Fatal("map ID unavailable")
		}
		return id
	}
	captureDNS := func(obj *bpfObjects) (uint64, bpfDnsHandoff) {
		t.Helper()
		packet, _ := routingKernelPacket(netip.MustParseAddrPort("192.0.2.1:45001"), netip.MustParseAddrPort("192.0.2.53:53"), consts.L4ProtoType_UDP)
		out := make([]byte, 256)
		verdict, err := obj.LanIngressL2.Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256), ContextOut: out, Repeat: 1})
		if err != nil || verdict != 7 {
			t.Fatalf("capture DNS: verdict=%d err=%v", verdict, err)
		}
		cookie := uint64(binary.NativeEndian.Uint32(out[52:56])) | uint64(binary.NativeEndian.Uint32(out[56:60]))<<32
		var handoff bpfDnsHandoff
		if err := obj.DnsHandoffMap.Lookup(cookie, &handoff); err != nil {
			t.Fatal(err)
		}
		if err := obj.DnsReplyMap.Update(cookie, handoff.Reply, ebpf.UpdateNoExist); err != nil {
			t.Fatal(err)
		}
		return cookie, handoff
	}
	cookie, snapshot := captureDNS(old)
	for range 3 {
		next := load()
		plane := &ControlPlane{core: &controlPlaneCore{bpf: &BPFState{bpfObjects: old, Runtime: r}}}
		source := netip.MustParseAddrPort("192.0.2.1:45000")
		unbind, err := plane.bindUDPSource(source, &routingResult{})
		if err != nil {
			t.Fatal(err)
		}
		for _, pair := range [][2]*ebpf.Map{{old.TcpFlowMap, next.TcpFlowMap}, {old.TcpProxySocketMap, next.TcpProxySocketMap}, {old.RoutingTuplesMap, next.RoutingTuplesMap}, {old.UdpBindingsMap, next.UdpBindingsMap}, {old.ListenSocketMap, next.ListenSocketMap}, {old.DnsCookieMap, next.DnsCookieMap}, {old.DnsHandoffMap, next.DnsHandoffMap}, {old.DnsReplyMap, next.DnsReplyMap}} {
			if mapID(pair[0]) != mapID(pair[1]) {
				t.Fatal("generation lost Runtime connection state")
			}
		}
		for _, pair := range [][2]*ebpf.Map{{old.RoutingMap, next.RoutingMap}, {old.DomainRoutingMap, next.DomainRoutingMap}, {old.LpmArrayMap, next.LpmArrayMap}, {old.RoutingProfileMap, next.RoutingProfileMap}, {old.RoutingInterfaceMap, next.RoutingInterfaceMap}, {old.OutboundConnectivityMap, next.OutboundConnectivityMap}, {old.ApiClientMap, next.ApiClientMap}} {
			if mapID(pair[0]) == mapID(pair[1]) {
				t.Fatal("candidate reused a configuration map")
			}
		}
		if err := r.kernelLinks.updatePrograms(old, next); err != nil {
			t.Fatal(err)
		}
		info, err := attached.Info()
		if err != nil {
			t.Fatal(err)
		}
		program, err := next.LanIngressL2.Info()
		if err != nil {
			t.Fatal(err)
		}
		programID, _ := program.ID()
		if info.ID != initial.ID || info.Program != programID {
			t.Fatalf("link was replaced or retained old program: %+v", info)
		}
		if err := old.Close(); err != nil {
			t.Fatal(err)
		}
		unbind()
		var binding bpfUdpBinding
		if err := r.shared["udp_bindings_map"].Lookup(udpSourceKey(source), &binding); !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("retired generation could not release its UDP binding: %v", err)
		}
		var retained bpfDnsHandoff
		var reply bpfDnsReply
		if err := next.DnsHandoffMap.LookupAndDelete(cookie, &retained); err != nil || retained != snapshot {
			t.Fatalf("reload lost queued DNS snapshot: %+v err=%v", retained, err)
		}
		if err := next.DnsReplyMap.Lookup(cookie, &reply); err != nil || reply != snapshot.Reply {
			t.Fatalf("reload lost delayed DNS reply: %+v err=%v", reply, err)
		}
		nextCookie, nextSnapshot := captureDNS(next)
		if nextCookie != cookie+1 || nextSnapshot.Result.Generation != generation {
			t.Fatalf("reload reset counter or retained old route: cookie=%d previous=%d snapshot=%+v", nextCookie, cookie, nextSnapshot)
		}
		cookie, snapshot = nextCookie, nextSnapshot
		old = next
	}
}
