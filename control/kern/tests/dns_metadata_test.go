//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/internal/routingabi"
	"golang.org/x/sys/unix"
)

func dnsContextCookie(ctx []byte) uint64 {
	return uint64(binary.NativeEndian.Uint32(ctx[52:56])) | uint64(binary.NativeEndian.Uint32(ctx[56:60]))<<32
}

func dnsTestContext(t *testing.T) []byte {
	t.Helper()
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	ctx := make([]byte, 256)
	binary.NativeEndian.PutUint32(ctx[40:44], uint32(loopback.Index))
	return ctx
}

func TestDNSImmutableMetadata(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("IPv6=%v", ipv6), func(t *testing.T) {
			obj, err := loadTestObjects(t, "TproxyWanEgressL2", "LanIngressL2", "TproxyDae0Ingress", "TproxyDae0peerIngress", "TproxyDae0peerEgress")
			if err != nil {
				t.Fatal(err)
			}
			installRoutingFlow(t, obj, []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback)}})
			source, dest := netip.MustParseAddrPort("192.0.2.2:52001"), netip.MustParseAddrPort("198.51.100.1:53")
			if ipv6 {
				source, dest = netip.MustParseAddrPort("[2001:db8:1::2]:52001"), netip.MustParseAddrPort("[2001:db8:2::1]:53")
			}
			ctx := dnsTestContext(t)
			packet := bridgePacket(source, dest, unix.IPPROTO_UDP, []byte{2, 0, 0, 0, 0, 9}, 0)
			var cookies [2]uint64
			var snapshots [2]bpftestDnsHandoff
			for i, program := range []*ebpf.Program{obj.TproxyWanEgressL2, obj.LanIngressL2} {
				packet[11] = byte(i + 1)
				if i != 0 {
					copy(ctx[36:40], ctx[40:44])
				}
				status, _, out, err := runBpfProgram(program, packet, ctx)
				if err != nil || status != 7 {
					t.Fatalf("capture %d: status=%d err=%v", i, status, err)
				}
				cookies[i] = dnsContextCookie(out)
				if cookies[i] == 0 || binary.NativeEndian.Uint32(out[48:52]) != routingabi.DNS_METADATA_MARK {
					t.Fatalf("missing packet metadata: %x", out[48:60])
				}
				if err := obj.DnsHandoffMap.Lookup(cookies[i], &snapshots[i]); err != nil {
					t.Fatal(err)
				}
				if snapshots[i].Result.SourceOrigin != uint8(i+1) || snapshots[i].Reply.Path.Smac[5] != byte(i+1) || snapshots[i].Reply.Path.FromWan != uint8(1-i) {
					t.Fatalf("incorrect immutable source: %+v", snapshots[i])
				}
				var legacy bpftestRoutingHandoff
				if err := obj.RoutingTuplesMap.Lookup(snapshots[i].Reply.Tuple, &legacy); !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("DNS wrote legacy handoff: %v", err)
				}
				peerStatus, _, peerCtx, err := runBpfProgram(obj.TproxyDae0peerIngress, packet, out)
				if err != nil || peerStatus != 0 || binary.NativeEndian.Uint32(peerCtx[8:12]) != routingabi.DNS_METADATA_MARK {
					t.Fatalf("peer receive: status=%d err=%v", peerStatus, err)
				}
			}
			if cookies[0] == cookies[1] {
				t.Fatal("reused a DNS cookie")
			}
			var redirectKey bpftestRedirectTuple
			var redirect bpftestRedirectEntry
			if obj.RedirectTrack.Iterate().Next(&redirectKey, &redirect) {
				t.Fatal("ordinary DNS wrote redirect_track")
			}
			// Reply in reverse order, after both identical tuples have been queued.
			for _, i := range []int{1, 0} {
				var saved bpftestDnsHandoff
				if err := obj.DnsHandoffMap.LookupAndDelete(cookies[i], &saved); err != nil || saved != snapshots[i] {
					t.Fatalf("queued snapshot changed: %+v, %v", saved, err)
				}
				if err := obj.DnsReplyMap.Update(cookies[i], saved.Reply, ebpf.UpdateNoExist); err != nil {
					t.Fatal(err)
				}
				if err := obj.DnsReplyMap.Update(cookies[i], saved.Reply, ebpf.UpdateNoExist); !errors.Is(err, ebpf.ErrKeyExist) {
					t.Fatalf("reply was mutable: %v", err)
				}
				replyCtx := dnsTestContext(t)
				binary.NativeEndian.PutUint32(replyCtx[48:52], routingabi.DNS_REPLY_MARK)
				binary.NativeEndian.PutUint32(replyCtx[52:56], uint32(cookies[i]))
				binary.NativeEndian.PutUint32(replyCtx[56:60], uint32(cookies[i]>>32))
				replyPacket := bridgePacket(dest, source, unix.IPPROTO_UDP, nil, 0)
				status, output, outCtx, err := runBpfProgram(obj.TproxyDae0Ingress, replyPacket, replyCtx)
				if err != nil || status != 7 || !bytes.Equal(output[:6], saved.Reply.Path.Smac[:]) || !bytes.Equal(output[6:12], saved.Reply.Path.Dmac[:]) || dnsContextCookie(outCtx) != 0 {
					t.Fatalf("reply %d: status=%d MACs=%x err=%v", i, status, output[:12], err)
				}
				for _, bad := range []struct {
					name     string
					from, to netip.AddrPort
					proto    uint8
				}{
					{"source port", netip.AddrPortFrom(dest.Addr(), 54), source, unix.IPPROTO_UDP},
					{"destination port", dest, netip.AddrPortFrom(source.Addr(), 52002), unix.IPPROTO_UDP},
					{"address", source, dest, unix.IPPROTO_UDP},
					{"protocol", dest, source, unix.IPPROTO_TCP},
				} {
					status, _, _, err := runBpfProgram(obj.TproxyDae0Ingress, bridgePacket(bad.from, bad.to, bad.proto, nil, 2), replyCtx)
					if err != nil || status != 2 {
						t.Fatalf("accepted wrong %s: status=%d err=%v", bad.name, status, err)
					}
				}
				for _, fragment := range dnsReplyFragments(replyPacket, ipv6) {
					status, _, _, err := runBpfProgram(obj.TproxyDae0Ingress, fragment, replyCtx)
					if err != nil || status != 7 {
						t.Fatalf("valid reply fragment: status=%d err=%v", status, err)
					}
					wrongAddress := append([]byte(nil), fragment...)
					wrongAddress[30]++
					status, _, _, err = runBpfProgram(obj.TproxyDae0Ingress, wrongAddress, replyCtx)
					if err != nil || status != 2 {
						t.Fatalf("fragment accepted wrong address: status=%d err=%v", status, err)
					}
					if ipv6 {
						fragment[54] = unix.IPPROTO_TCP
					} else {
						fragment[23] = unix.IPPROTO_TCP
					}
					status, _, _, err = runBpfProgram(obj.TproxyDae0Ingress, fragment, replyCtx)
					if err != nil || status != 2 {
						t.Fatalf("fragment accepted wrong protocol: status=%d err=%v", status, err)
					}
				}
				missing := append([]byte(nil), replyCtx...)
				clear(missing[48:60])
				status, _, _, err = runBpfProgram(obj.TproxyDae0Ingress, replyPacket, missing)
				if err != nil || status != 2 {
					t.Fatalf("missing cb accepted reply: status=%d err=%v", status, err)
				}
				if err := obj.DnsReplyMap.Delete(cookies[i]); err != nil {
					t.Fatal(err)
				}
				status, _, _, err = runBpfProgram(obj.TproxyDae0Ingress, replyPacket, replyCtx)
				if err != nil || status != 2 {
					t.Fatalf("missing reply fell back: status=%d err=%v", status, err)
				}
			}
			// Saturation never wraps into a previous request's identity.
			if err := obj.DnsCookieMap.Update(uint32(0), bpftestDnsCookie{Value: math.MaxInt64 - 1}, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			status, _, last, err := runBpfProgram(obj.LanIngressL2, packet, ctx)
			if err != nil || status != 7 || dnsContextCookie(last) != math.MaxInt64 {
				t.Fatalf("last cookie: status=%d cookie=%d err=%v", status, dnsContextCookie(last), err)
			}
			status, _, _, err = runBpfProgram(obj.LanIngressL2, packet, ctx)
			if err != nil || status != 2 {
				t.Fatalf("saturated counter accepted packet: status=%d err=%v", status, err)
			}
			var counter bpftestDnsCookie
			if err := obj.DnsCookieMap.Lookup(uint32(0), &counter); err != nil || counter.Value != math.MaxInt64 {
				t.Fatalf("counter wrapped: %+v err=%v", counter, err)
			}
		})
	}
}

func dnsReplyFragments(packet []byte, ipv6 bool) [][]byte {
	first := append([]byte(nil), packet...)
	if ipv6 {
		first = append(append(first[:54:54], make([]byte, 8)...), packet[54:]...)
		first[20], first[54] = unix.IPPROTO_FRAGMENT, unix.IPPROTO_UDP
		binary.BigEndian.PutUint16(first[18:20], 16)
		binary.BigEndian.PutUint16(first[56:58], 1)
		binary.BigEndian.PutUint16(first[66:68], 16)
		last := append([]byte(nil), first...)
		binary.BigEndian.PutUint16(last[56:58], 8)
		clear(last[62:])
		atomic := append([]byte(nil), first...)
		binary.BigEndian.PutUint16(atomic[56:58], 0)
		binary.BigEndian.PutUint16(atomic[66:68], 8)
		return [][]byte{first, last, atomic}
	}
	binary.BigEndian.PutUint16(first[20:22], 0x2000)
	binary.BigEndian.PutUint16(first[38:40], 16)
	last := append([]byte(nil), first...)
	binary.BigEndian.PutUint16(last[20:22], 1)
	clear(last[34:])
	return [][]byte{first, last}
}

func TestDNSReplyEgressMetadata(t *testing.T) {
	obj, err := loadTestObjects(t, "TestDnsReplyEgress", "TproxyDae0peerEgress")
	if err != nil {
		t.Fatal(err)
	}
	packet := bridgePacket(netip.MustParseAddrPort("192.0.2.53:53"), netip.MustParseAddrPort("192.0.2.1:52001"), unix.IPPROTO_UDP, nil, 0)
	for _, cookie := range []uint64{1, 0x123456789abcdef, math.MaxInt64, 0, math.MaxInt64 + 1} {
		ctx := dnsTestContext(t)
		binary.NativeEndian.PutUint32(ctx[8:12], routingabi.DNS_REPLY_MARK)
		binary.NativeEndian.PutUint32(ctx[52:56], uint32(cookie))
		binary.NativeEndian.PutUint32(ctx[56:60], uint32(cookie>>32))
		status, _, _, err := runBpfProgram(obj.TestDnsReplyEgress, packet, ctx)
		want := uint32(0)
		if cookie == 0 || cookie > math.MaxInt64 {
			want = 2
		}
		if err != nil || status != want {
			t.Fatalf("cookie=%x: status=%d want=%d err=%v", cookie, status, want, err)
		}
		status, _, _, err = runBpfProgram(obj.TproxyDae0peerEgress, packet, ctx)
		if err != nil || status != 2 {
			t.Fatalf("missing delivery timestamp accepted: status=%d err=%v", status, err)
		}
	}
}

func TestDNSMustBindingWithoutRouteCache(t *testing.T) {
	for _, test := range []struct {
		name                          string
		bound, incoming               plugin.SourceOrigin
		otherMAC, staleEpoch, allowed bool
	}{
		{"local_to_lan", plugin.SourceLocal, plugin.SourceLAN, false, false, false},
		{"lan_to_local", plugin.SourceLAN, plugin.SourceLocal, false, false, false},
		{"lan_other_mac", plugin.SourceLAN, plugin.SourceLAN, true, false, false},
		{"lan_same_source", plugin.SourceLAN, plugin.SourceLAN, false, false, true},
		{"local_other_mac", plugin.SourceLocal, plugin.SourceLocal, true, false, true},
		{"stale_epoch", plugin.SourceLAN, plugin.SourceLAN, false, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			obj, err := loadTestObjects(t, "TproxyWanEgressL2", "LanIngressL2")
			if err != nil {
				t.Fatal(err)
			}
			installRoutingFlow(t, obj, []bpftestMatchSet{
				{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionMust)},
				{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionFlowEnd)},
				{Type: uint8(consts.MatchType_Fallback), Outbound: uint8(consts.OutboundControlPlaneRouting)},
			})
			source, dest := netip.MustParseAddrPort("192.0.2.2:52001"), netip.MustParseAddrPort("198.51.100.1:53")
			key := bpftestUdpRoutingCacheKey{Sport: nativeUint16(source.Port())}
			key.Sip.U6Addr8 = source.Addr().As16()
			binding := bpftestUdpBinding{SourceOrigin: uint8(test.bound), Mac: [6]uint8{2, 0, 0, 0, 0, 2}}
			if test.staleEpoch {
				binding.RouteEpoch = 1
			}
			if err := obj.UdpBindingsMap.Update(key, binding, ebpf.UpdateNoExist); err != nil {
				t.Fatal(err)
			}
			packet, ctx := bridgePacket(source, dest, unix.IPPROTO_UDP, nil, 0), dnsTestContext(t)
			if test.otherMAC {
				packet[11]++
			}
			program := obj.TproxyWanEgressL2
			if test.incoming == plugin.SourceLAN {
				program = obj.LanIngressL2
				copy(ctx[36:40], ctx[40:44])
			}
			status, _, out, err := runBpfProgram(program, packet, ctx)
			want := uint32(2)
			if test.allowed {
				want = 7
			}
			if err != nil || status != want {
				t.Fatalf("must: status=%d want=%d err=%v", status, want, err)
			}
			var route bpftestUdpRoutingCacheValue
			err = obj.UdpRoutingCacheMap.Lookup(key, &route)
			if test.allowed {
				var handoff bpftestDnsHandoff
				if err != nil || obj.DnsHandoffMap.Lookup(dnsContextCookie(out), &handoff) != nil || handoff.Result.Must != 1 {
					t.Fatalf("valid must lost association/handoff: %+v err=%v", handoff, err)
				}
			} else {
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("rejected must wrote route: %+v err=%v", route, err)
				}
				var cookie uint64
				var handoff bpftestDnsHandoff
				var tuple bpftestRedirectTuple
				var path bpftestRedirectEntry
				if obj.DnsHandoffMap.Iterate().Next(&cookie, &handoff) || obj.RedirectTrack.Iterate().Next(&tuple, &path) {
					t.Fatal("rejected must changed handoff or return ownership")
				}
			}
		})
	}
}
