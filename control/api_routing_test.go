// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"golang.org/x/sys/unix"
)

func TestAPIRoutingAddressChanges(t *testing.T) {
	prepare := func(port uint16, addresses ...string) preparedRules {
		t.Helper()
		var addrs []net.Addr
		for _, address := range addresses {
			ip, subnet, err := net.ParseCIDR(address)
			if err != nil {
				t.Fatal(err)
			}
			subnet.IP = ip
			addrs = append(addrs, subnet)
		}
		var rules preparedRules
		rules.bypassAPI(port, addrs)
		return rules
	}
	old := prepare(8081, "192.0.2.1/24", "2001:db8::1/64")
	plane := &ControlPlane{apiListen: "8081", apiBypass: append(old.apiBypass, old.apiBypass...)}
	for _, test := range []struct {
		name      string
		port      uint16
		addresses []string
		current   bool
	}{
		{"same", 8081, []string{"192.0.2.1/24", "2001:db8::1/64"}, true},
		{"reordered and duplicated", 8081, []string{"2001:db8::1/64", "192.0.2.1/24", "192.0.2.1/32"}, true},
		{"subnet changed", 8081, []string{"192.0.2.1/32", "2001:db8::1/128"}, true},
		{"IPv4 replaced", 8081, []string{"192.0.2.2/24", "2001:db8::1/64"}, false},
		{"IPv6 replaced", 8081, []string{"192.0.2.1/24", "2001:db8::2/64"}, false},
		{"added", 8081, []string{"192.0.2.1/24", "2001:db8::1/64", "198.51.100.1/24"}, false},
		{"removed", 8081, []string{"192.0.2.1/24"}, false},
		{"empty", 8081, nil, false},
		{"port changed", 8082, []string{"192.0.2.1/24", "2001:db8::1/64"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := prepare(test.port, test.addresses...)
			if got := plane.matchesAPIBypass(current.apiBypass); got != test.current {
				t.Fatalf("API routing current=%v, want %v", got, test.current)
			}
		})
	}
	if current, err := new(ControlPlane).APIRoutingCurrent(); !current || err != nil {
		t.Fatalf("disabled TCP API required a routing refresh: %v, %v", current, err)
	}
}

func TestAPIRoutingExplicitEndpoint(t *testing.T) {
	for _, listen := range []string{"192.0.2.1:8081", "[2001:db8::1]:8081", "[::ffff:192.0.2.1]:8081", "[fe80::1%dae-test]:8081"} {
		t.Run(listen, func(t *testing.T) {
			api := config.API{Listen: listen}
			rules := preparedRules{routing: testRoutingConfig(nil, &config_parser.Function{Name: "proxy"})}
			if err := rules.bypassLocalAPI(api.Listen); err != nil {
				t.Fatal(err)
			}
			ip := netip.MustParseAddrPort(listen).Addr().Unmap().WithZone("")
			key := netip.AddrPortFrom(ip, 8081)
			if len(rules.apiBypass) != 1 || rules.apiBypass[0] != key {
				t.Fatalf("explicit API bypass = %+v; want only %+v", rules.apiBypass, key)
			}
			plane := &ControlPlane{apiListen: api.Listen, apiBypass: rules.apiBypass}
			if current, err := plane.APIRoutingCurrent(); !current || err != nil {
				t.Fatalf("explicit API routing is not current: %v, %v", current, err)
			}
			plane.apiBypass = nil
			if current, err := plane.APIRoutingCurrent(); current || err != nil {
				t.Fatalf("missing explicit API exemption was considered current: %v, %v", current, err)
			}
			matcher, _ := routingMatcherForTest(t, rules)
			for _, destination := range []netip.Addr{ip, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::2")} {
				for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
					for _, port := range []uint16{8081, 8082} {
						got, _, _, err := matcher.match(routingInput{
							src:     netip.MustParseAddrPort("198.51.100.2:12345"),
							dst:     netip.AddrPortFrom(destination, port),
							l4proto: proto,
						})
						want := consts.OutboundUserDefinedMin
						if destination == ip && port == 8081 && proto == consts.L4ProtoType_TCP {
							want = consts.OutboundDirect
						}
						if err != nil || got != want {
							t.Fatalf("route(%s:%d/%v) = %v, %v; want %v", destination, port, proto, got, err, want)
						}
					}
				}
			}
		})
	}
}

func TestAPIRoutingWildcardSocketFamilies(t *testing.T) {
	for _, host := range []string{"", "0.0.0.0", "::"} {
		t.Run(host, func(t *testing.T) {
			listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
			if err != nil {
				t.Skipf("wildcard TCP listener unavailable: %v", err)
			}
			defer listener.Close()
			ipv6 := listener.Addr().(*net.TCPAddr).IP.To4() == nil
			ipv4 := !ipv6
			if ipv6 {
				raw, err := listener.(*net.TCPListener).SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var optionErr error
				if err := raw.Control(func(fd uintptr) {
					var only int
					only, optionErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
					ipv4 = only == 0
				}); err != nil || optionErr != nil {
					t.Fatalf("read actual wildcard socket families: %v, %v", err, optionErr)
				}
			}
			listen := "8081"
			if host != "" {
				listen = net.JoinHostPort(host, "8081")
			}
			api := config.API{Listen: listen}
			var rules preparedRules
			if err := rules.bypassLocalAPI(api.Listen); err != nil {
				t.Fatal(err)
			}
			addresses, err := net.InterfaceAddrs()
			if err != nil {
				t.Fatal(err)
			}
			var expected []net.Addr
			for _, address := range addresses {
				prefix, err := netip.ParsePrefix(address.String())
				if err == nil && (prefix.Addr().Unmap().Is4() && ipv4 || prefix.Addr().Unmap().Is6() && ipv6) {
					expected = append(expected, address)
				}
			}
			var want preparedRules
			want.bypassAPI(8081, expected)
			plane := &ControlPlane{apiListen: api.Listen, apiBypass: rules.apiBypass}
			if !plane.matchesAPIBypass(want.apiBypass) {
				t.Fatalf("wildcard bypass differs from actual socket (IPv4=%v, IPv6=%v): %+v, want %+v", ipv4, ipv6, rules.apiBypass, want.apiBypass)
			}
			if current, err := plane.APIRoutingCurrent(); !current || err != nil {
				t.Fatalf("wildcard API routing is not current: %v, %v", current, err)
			}
		})
	}
}
