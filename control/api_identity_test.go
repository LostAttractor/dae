// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"testing"
)

func TestAPIClientKeyIdentifiesConnection(t *testing.T) {
	source := netip.MustParseAddrPort("192.0.2.2:12345")
	destination := netip.MustParseAddrPort("192.0.2.1:9080")
	key := apiClientKey(source, destination)
	if got := apiClientKey(netip.MustParseAddrPort("[::ffff:192.0.2.2]:12345"), destination); got != key {
		t.Fatal("IPv4 mapped connection key differs")
	}
	for _, pair := range [][2]netip.AddrPort{
		{netip.MustParseAddrPort("192.0.2.2:12346"), destination},
		{source, netip.MustParseAddrPort("192.0.2.1:9081")},
		{source, netip.MustParseAddrPort("192.0.2.3:9080")},
		{destination, source},
	} {
		if got := apiClientKey(pair[0], pair[1]); got == key {
			t.Fatalf("connection %v reused another connection's key", pair)
		}
	}
}
