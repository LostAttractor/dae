// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"github.com/daeuniverse/dae/internal/routingabi"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/clientmatch"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/settings"
)

func TestMITMSelectionUsesPublishedHTTPPolicy(t *testing.T) {
	clients, err := clientmatch.Parse([]string{"all"})
	if err != nil {
		t.Fatal(err)
	}
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	ip := netip.MustParseAddr("192.0.2.1")
	plane := &ControlPlane{mitmClients: clients}
	for _, enabled := range []bool{false, true} {
		plane.httpClients.policy = clients.Compile(map[[6]byte]bool{mac: enabled})
		got, override := plane.mitmSelection(ip, mac)
		if got != enabled || override == nil || *override != enabled || plane.httpClientAllowed(ip, mac) != got {
			t.Fatalf("published policy differs between MITM and routing: got %v, override %v, want %v", got, override, enabled)
		}
	}
}

func TestHTTPClientAdmissionSkipsScopesAndSharesResult(t *testing.T) {
	prepared := prepareFlowRulesForTest(t, "dport(8443) -> dnat('198.51.100.20:9443')\ndport(53) -> must\ndport(9443) -> bump", "dport(443) -> direct(mark:37)")
	prepared.bypass = planRulesForTest(t, "dport(9000) -> direct")
	prepared.enableMITMPlan(plugin.Plan{Scopes: []plugin.HTTPScope{
		{Scope: plugin.Scope{{Host: "198.51.100.9"}}},
		{Scope: plugin.Scope{{Host: "198.51.100.8"}}, PreserveRoute: true},
	}})
	m, _ := routingMatcherForTest(t, prepared)
	for _, tc := range []struct {
		name        string
		allowed     bool
		destination string
		queries     int
		want        routingEvaluation
	}{
		{"denied skips both blocks", false, "198.51.100.8:443", 1, routingEvaluation{outbound: consts.OutboundDirect, mark: 37}},
		{"allowed shares admission", true, "198.51.100.8:443", 1, routingEvaluation{outbound: consts.OutboundDirect, mark: 37, captureFlags: captureHTTP}},
		{"request capture precedes routing", true, "198.51.100.9:443", 1, routingEvaluation{outbound: consts.OutboundControlPlaneRouting, captureFlags: captureHTTP | captureHTTPRequest}},
		{"denied preserves must", false, "198.51.100.8:53", 1, routingEvaluation{outbound: consts.OutboundDirect, must: true}},
		{"denied preserves bump", false, "198.51.100.8:9443", 1, routingEvaluation{outbound: consts.OutboundControlPlaneRouting}},
		{"DNAT needs no HTTP admission", false, "198.51.100.8:8443", 0, routingEvaluation{outbound: consts.OutboundControlPlaneRouting, captureFlags: captureDestination}},
		{"API bypass needs no HTTP admission", false, "198.51.100.8:9000", 0, routingEvaluation{outbound: consts.OutboundDirect}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			queries := 0
			m.httpClientAllowed = func(netip.Addr, [6]byte) bool {
				queries++
				return tc.allowed
			}
			trace := newRoutingExecution()
			spans := m.profiles[m.defaultProfileID]
			got, err := m.evaluateSpans(spans, routingInput{
				src: netip.MustParseAddrPort("192.0.2.1:41000"), dst: netip.MustParseAddrPort(tc.destination),
				l4proto: consts.L4ProtoType_TCP, kernel: true, trace: trace,
			})
			if err != nil || got != tc.want || queries != tc.queries {
				t.Fatalf("got %+v, %v, %d admission queries; want %+v, %d queries", got, err, queries, tc.want, tc.queries)
			}
			if !tc.allowed {
				for spanIndex, span := range spans {
					for i := span.Start; i < span.End; i++ {
						jump := m.matches[i]
						if jump.Action != uint8(consts.MatchActionConditionalJump) {
							continue
						}
						for j := i + 1; j < i+jump.Mark; j++ {
							if trace.visited[routingTracePosition{spanIndex, j}] {
								t.Fatalf("denied client visited HTTP scope instruction %d", j)
							}
						}
					}
				}
			}
		})
	}
}

func TestHTTPClientAdmissionKernelParity(t *testing.T) {
	collection, state := dnsKernelCollection(t)
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	sourcePort := uint16(41000)
	for _, preserve := range []bool{false, true} {
		prepared := prepareFlowRulesForTest(t, "dport(8443) -> dnat('198.51.100.20:9443')", "dport(8888) -> proxy")
		prepared.enableMITMPlan(plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: plugin.Scope{
			{Host: "198.51.100.8", Ports: []uint16{80, 443, 53, 8443, 8888}},
			{Host: "2001:db8::8", Ports: []uint16{80, 443, 53, 8443, 8888}},
		}, PreserveRoute: preserve}}})
		matcher, _ := routingMatcherForTest(t, prepared)
		matcher.bpf = state
		if err := matcher.BuildKernspace(); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name       string
			rules      []string
			override   *bool
			unknownMAC bool
		}{
			{name: "default deny"},
			{name: "all", rules: []string{"all"}},
			{name: "IP before MAC deny", rules: []string{"192.0.2.0/24", "-02:00:00:00:00:01", "all"}},
			{name: "MAC deny before IP", rules: []string{"-02:00:00:00:00:01", "192.0.2.0/24", "all"}},
			{name: "narrow deny before broad allow", rules: []string{"-192.0.2.0/24", "0.0.0.0/0", "::/0"}},
			{name: "broad deny before narrow allow", rules: []string{"-0.0.0.0/0", "192.0.2.1", "2001:db8::/32"}},
			{name: "IPv6 does not select IPv4", rules: []string{"::/0"}},
			{name: "IPv4 does not select IPv6", rules: []string{"0.0.0.0/0"}},
			{name: "override disable", rules: []string{"all"}, override: new(false)},
			{name: "override enable", rules: []string{"-all"}, override: new(true)},
			{name: "unknown MAC cannot match", rules: []string{"00:00:00:00:00:00"}, unknownMAC: true},
			{name: "unknown MAC retains IP selection", rules: []string{"-02:00:00:00:00:01", "192.0.2.0/24", "2001:db8::/32"}, unknownMAC: true},
		} {
			clients, err := clientmatch.Parse(tc.rules)
			if err != nil {
				t.Fatal(err)
			}
			overrides := map[[6]byte]bool{}
			if tc.override != nil {
				overrides[mac] = *tc.override
			}
			policy := clients.Compile(overrides)
			table, err := httpClientMap(policy)
			if err != nil {
				t.Fatal(err)
			}
			if err := state.HttpClientsMap.Update(uint32(0), table, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			table.Close()
			matcher.httpClientAllowed = func(ip netip.Addr, mac [6]byte) bool { enabled, _ := policy.Match(ip, mac); return enabled }
			observedMAC := mac
			if tc.unknownMAC {
				observedMAC = [6]byte{}
			}
			for _, family := range []uint8{4, 6} {
				srcIP, dstIP := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.8")
				if family == 6 {
					srcIP, dstIP = netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::8")
				}
				for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
					protocol := uint8(6)
					if proto == consts.L4ProtoType_UDP {
						protocol = 17
					}
					if err := collection.Maps["outbound_connectivity_map"].Update(bpfOutboundConnectivityQuery{Outbound: uint8(consts.OutboundUserDefinedMin), Ipversion: family, L4proto: protocol}, uint32(1), ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
					for _, port := range []uint16{22, 80, 443, 53, 8443, 8888} {
						for _, program := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
							sourcePort++
							src, dst := netip.AddrPortFrom(srcIP, sourcePort), netip.AddrPortFrom(dstIP, port)
							packet, _ := routingKernelPacket(src, dst, proto)
							copy(packet[6:12], observedMAC[:])
							evaluation, err := matcher.evaluateSpans(matcher.profiles[matcher.defaultProfileID], routingInput{src: src, dst: dst, mac: observedMAC, l4proto: proto, kernel: true})
							if err != nil {
								t.Fatal(err)
							}
							allowed, _ := policy.Match(srcIP, observedMAC)
							if !allowed && evaluation.captureFlags&(captureHTTP|captureHTTPRequest) != 0 {
								t.Fatalf("denied client entered HTTP capture: %s %+v", tc.name, evaluation)
							}
							want := ^uint32(0)
							if evaluation.outbound != consts.OutboundDirect || evaluation.captureFlags != 0 {
								want = 7
							}
							if !allowed && (port == 53 || port == 8443 || port == 8888) && want != 7 {
								t.Fatalf("HTTP exclusion removed DNS, DNAT or proxy admission: port=%d", port)
							}
							verdict, err := collection.Programs[program].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256)})
							if err != nil || verdict != want {
								t.Fatalf("%s preserve=%v IPv%d proto=%d port=%d %s: verdict=%d want=%d error=%v", tc.name, preserve, family, proto, port, program, verdict, want, err)
							}
							if want == 7 {
								key := bpfTuplesKey{Sport: common.Htons(src.Port()), Dport: common.Htons(dst.Port()), L4proto: protocol}
								key.Sip.U6Addr8, key.Dip.U6Addr8 = srcIP.As16(), dstIP.As16()
								var got bpfRoutingResult
								if err := lookupKernelHandoff(collection.Maps["routing_tuples_map"], key, &got); err != nil || got.CaptureFlags != evaluation.captureFlags || got.Outbound != uint8(evaluation.outbound) {
									t.Fatalf("%s: kernel/userspace diverged: %+v %+v %v", tc.name, got, evaluation, err)
								}
							}
						}
					}
				}
			}
		}
	}
}

func TestHTTPClientPublicationRollsBackWithSettings(t *testing.T) {
	_, state := dnsKernelCollection(t)
	store, err := settings.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	clients, _ := clientmatch.Parse([]string{"all"})
	plane := &ControlPlane{settings: store, mitmClients: clients, core: &controlPlaneCore{bpf: state}, kernelReady: true}
	if err := plane.restoreHTTPClients(); err != nil {
		t.Fatal(err)
	}
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	failed := errors.New("final route commit failed")
	err = store.Update(func(next *settings.Snapshot) error { next.MITM["02:00:00:00:00:01"] = false; return nil }, func(previous, next settings.Snapshot, persist func() error) error {
		return plane.changeHTTPClients(previous, next, persist, func() error { return failed })
	})
	if !errors.Is(err, failed) {
		t.Fatal(err)
	}
	if enabled, override := plane.mitmSelection(netip.MustParseAddr("192.0.2.1"), mac); !enabled || override != nil {
		t.Fatal("failed update changed userspace admission")
	}
	if _, exists := store.MITM(mac); exists {
		t.Fatal("failed update retained settings preference")
	}
	var current *ebpf.Map
	if err := state.HttpClientsMap.Lookup(uint32(0), &current); err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	key := bpfHttpClientKey{Prefixlen: routingabi.HTTP_CLIENT_KEY_BITS, Kind: routingabi.HTTP_CLIENT_MAC_OVERRIDE}
	copy(key.Address[:], mac[:])
	var decision bpfHttpClientDecision
	if err := current.Lookup(key, &decision); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("kernel retained failed override: %+v %v", decision, err)
	}
	if _, err := plane.UpdateManagedMITM(mac, new(false)); err != nil {
		t.Fatal(err)
	}
	var published *ebpf.Map
	if err := state.HttpClientsMap.Lookup(uint32(0), &published); err != nil {
		t.Fatal(err)
	}
	defer published.Close()
	if err := published.Lookup(key, &decision); err != nil || decision.Allow != 0 {
		t.Fatalf("managed update did not publish kernel exclusion: %+v %v", decision, err)
	}

	if enabled, override := plane.mitmSelection(netip.MustParseAddr("192.0.2.1"), mac); enabled || override == nil || *override {
		t.Fatal("successful update did not publish userspace admission")
	}
}
