// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/mitm/plugin"
)

func TestMITMCaptureKeepsUnrelatedDirectInKernel(t *testing.T) {
	prepared := preparedRules{}
	prepared.enableMITMPlan(plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: plugin.Scope{
		{Host: "api.bilibili.com", Ports: []uint16{443, 80, 443}},
		{Host: "service.example", Ports: []uint16{8443}},
		{Host: "192.0.2.10", Ports: []uint16{8443}},
		{Host: "2001:db8::10", Ports: []uint16{443}},
	}}}})
	matcher, builder := routingMatcherForTest(t, prepared)
	exposeCapturePredicates(t, builder)
	for _, test := range []struct {
		name, destination string
		dns               []string
		capture           bool
	}{
		{"router SSH", "10.0.0.1:22", nil, false},
		{"router HTTPS", "10.0.0.1:443", nil, false},
		{"unrelated HTTPS", "192.0.2.1:443", []string{"outside.example"}, false},
		{"missing DNS", "192.0.2.1:443", nil, false},
		{"known plugin domain", "192.0.2.1:443", []string{"api.bilibili.com"}, true},
		{"known domain wrong port", "192.0.2.1:22", []string{"api.bilibili.com"}, false},
		{"port sets must not cross", "192.0.2.1:8443", []string{"api.bilibili.com"}, false},
		{"shared IP needs exact host", "192.0.2.1:443", []string{"api.bilibili.com", "outside.example"}, true},
		{"shared IP wrong port", "192.0.2.1:22", []string{"api.bilibili.com", "outside.example"}, false},
		{"custom port", "192.0.2.1:8443", []string{"service.example"}, true},
		{"custom host wrong port", "192.0.2.1:443", []string{"service.example"}, false},
		{"literal IPv4 needs no DNS", "192.0.2.10:8443", nil, true},
		{"literal IPv4 wrong port", "192.0.2.10:22", nil, false},
		{"literal IPv6 needs no DNS", "[2001:db8::10]:443", nil, true},
		{"unrelated IPv6", "[2001:db8::11]:443", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			destination := netip.MustParseAddrPort(test.destination)
			address := destination.Addr().As16()
			routing, bump := make([]uint32, consts.MaxMatchSetLen/32), make([]uint32, consts.MaxMatchSetLen/32)
			for i, host := range test.dns {
				bitmap := matcher.domainMatcher.MatchDomainBitmap(host)
				for word, bits := range bitmap {
					bump[word] |= bits
					if i == 0 {
						routing[word] = bits
					} else {
						routing[word] &= bits
					}
				}
			}
			// Supply the kernel's DNS bitmaps explicitly. Even a later TLS or
			// QUIC SNI cannot manufacture evidence at the initial packet.
			for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
				got, _, _, err := matcher.Match(address[:], address[:], 12345, destination.Port(), consts.IpVersionFromAddr(destination.Addr()), proto, "api.bilibili.com", [16]uint8{}, 0, 0, make([]byte, 16), routing, bump)
				if err != nil || (got != consts.OutboundDirect) != test.capture {
					t.Fatalf("protocol=%v kernel capture = %v, err=%v, want %v", proto, got, err, test.capture)
				}
			}
		})
	}
}

func TestMITMEmptyAndExcludedScopesDoNotCapture(t *testing.T) {
	for _, scope := range []plugin.Scope{
		nil,
		{{Host: "*.example", Exclude: true}},
		{{Host: ""}},
		{{Host: "*.example", Ports: []uint16{0}}},
	} {
		prepared := preparedRules{}
		prepared.enableMITMPlan(plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: scope}}})
		_, builder := routingMatcherForTest(t, prepared)
		for _, rule := range builder.rules {
			if rule.CaptureFlags != 0 {
				t.Fatalf("nonmatching scope caused capture: %+v", scope)
			}
		}
	}
}

func TestDestinationDomainCaptureRetainsDNSPredicate(t *testing.T) {
	matcher, builder := destinationTestMatcher(t, "domain(full: service.example) && dport(443) -> dnat(198.51.100.1)")
	exposeCapturePredicates(t, builder)
	for _, host := range []string{"", "outside.example", "service.example"} {
		for _, port := range []uint16{22, 443} {
			address := make([]byte, 16)
			got, _, _, err := matcher.Match(address, address, 12345, port, consts.IpVersion_4, consts.L4ProtoType_TCP, host, [16]uint8{}, 0, 0, address)
			want := host == "service.example" && port == 443
			if err != nil || (got != consts.OutboundDirect) != want {
				t.Fatalf("DNAT capture %q:%d = %v, %v, want %v", host, port, got, err, want)
			}
		}
	}
}
