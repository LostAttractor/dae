package common

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestResolveUDPAddrContextLiterals(t *testing.T) {
	resolver := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		t.Error("IP literals must not trigger DNS transport")
		return nil, errors.New("unexpected DNS query")
	}}
	for _, test := range []struct {
		address, ip, zone string
		family            string
	}{
		{"[fe80::1234%eth0]:443", "fe80::1234", "eth0", "ip6"},
		{"[fe80::1234%7]:443", "fe80::1234", "7", "ip6"},
		{"[2001:db8::1]:443", "2001:db8::1", "", "ip6"},
		{"192.0.2.1:443", "192.0.2.1", "", "ip4"},
		{"[::ffff:192.0.2.1]:443", "192.0.2.1", "", "ip4"},
	} {
		t.Run(test.address, func(t *testing.T) {
			for _, network := range []string{"ip", "ip4", "ip6"} {
				addr, err := ResolveUDPAddrContext(t.Context(), resolver, network, test.address)
				if network != "ip" && network != test.family {
					if err == nil {
						t.Fatalf("%s accepted the wrong family: address=%v error=%v", network, addr, err)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if !addr.IP.Equal(net.ParseIP(test.ip)) || addr.Zone != test.zone || addr.Port != 443 {
					t.Errorf("%s resolved to %s, want IP=%s zone=%q port=443", network, addr, test.ip, test.zone)
				}
			}
			legacy, err := ResolveUDPAddrWithResolver(resolver, test.address)
			if err != nil || legacy.Zone != test.zone {
				t.Errorf("legacy resolver lost zone %q: address=%v error=%v", test.zone, legacy, err)
			}
		})
	}
}
