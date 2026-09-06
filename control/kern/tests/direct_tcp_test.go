//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestDirectTCPSynReplacesPreviousRoute(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	status, syn, ctx, err := runBpfProgram(obj.TestpktgenMacMatch, make([]byte, 4096-256-320), make([]byte, 256))
	if err != nil || status != 0 {
		t.Fatalf("generate SYN: status %d, error %v", status, err)
	}
	key := bpftestTuplesKey{Sport: nativeUint16(19233), Dport: nativeUint16(79), L4proto: unix.IPPROTO_TCP}
	key.Sip.U6Addr8 = netip.MustParseAddr("192.168.0.1").As16()
	key.Dip.U6Addr8 = netip.MustParseAddr("1.1.1.1").As16()
	ack := append([]byte(nil), syn...)
	// The fixture has Ethernet + IPv4 without options + TCP headers.
	ack[14+20+13] = 0x10
	const (
		direct       = 0
		proxy        = 2
		fallbackType = 11
		next         = math.MaxUint32 // TCX_NEXT
		redirect     = 7              // TC_ACT_REDIRECT
	)
	for _, test := range []struct {
		name        string
		previous    bpftestRoutingResult
		mark        uint32
		unavailable bool
	}{
		{name: "proxy to plain direct", previous: bpftestRoutingResult{Outbound: proxy}},
		{name: "marked to plain direct", previous: bpftestRoutingResult{Outbound: direct, Mark: 42}},
		{name: "proxy to marked direct", previous: bpftestRoutingResult{Outbound: proxy}, mark: 73},
		{name: "proxy to unavailable selector direct fallback", previous: bpftestRoutingResult{Outbound: proxy}, unavailable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := obj.RoutingTuplesMap.Update(key, test.previous, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			fallback := bpftestMatchSet{Type: fallbackType, Outbound: direct, Mark: test.mark}
			if test.unavailable {
				fallback.Outbound = proxy
				query := bpftestOutboundConnectivityQuery{Outbound: proxy, L4proto: unix.IPPROTO_TCP, Ipversion: 4}
				const noAliveDirect uint32 = 1
				if err := obj.OutboundConnectivityMap.Update(query, noAliveDirect, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			}
			if err := obj.RoutingMap.Update(uint32(0), fallback, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			// Changing rules alone must preserve an already established flow.
			want := uint32(next)
			if test.previous.Outbound == proxy {
				want = redirect
			}
			if status, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, ack, ctx); err != nil || status != want {
				t.Fatalf("existing ACK: status %d, error %v; want %d", status, err, want)
			}
			want = uint32(next)
			if test.unavailable {
				want = redirect
			}
			for _, packet := range [][]byte{syn, ack} {
				status, _, ctxOut, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx)
				if err != nil || status != want {
					t.Fatalf("new direct flow: status %d, error %v", status, err)
				}
				// __sk_buff.mark is its third uint32 field.
				if mark := binary.NativeEndian.Uint32(ctxOut[8:12]); mark != test.mark {
					t.Fatalf("packet mark = %d, want %d", mark, test.mark)
				}
			}
			var result bpftestRoutingResult
			err := obj.RoutingTuplesMap.Lookup(key, &result)
			if test.unavailable {
				if err != nil || result.Outbound != proxy || result.NoSniff != 1 {
					t.Fatalf("fallback lost group ownership: %+v, %v", result, err)
				}
			} else if test.mark == 0 {
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("plain direct retained previous routing tuple: %+v, %v", result, err)
				}
			} else if err != nil || result.Outbound != direct || result.Mark != test.mark {
				t.Fatalf("marked direct tuple = %+v, %v", result, err)
			}
		})
	}
}
