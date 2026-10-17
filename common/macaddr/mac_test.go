// SPDX-License-Identifier: AGPL-3.0-only

package macaddr

import (
	"net"
	"testing"
)

func TestEthernetAndClientAddresses(t *testing.T) {
	for _, text := range []string{"02:ab:cd:ef:00:01", "02-AB-CD-EF-00-01", "02ab.cdef.0001"} {
		mac, err := ParseClient(text)
		if err != nil || net.HardwareAddr(mac[:]).String() != "02:ab:cd:ef:00:01" {
			t.Fatalf("%q: %x, %v", text, mac, err)
		}
	}
	for _, text := range []string{"00:00:00:00:00:00", "01:00:5e:00:00:01", "ff:ff:ff:ff:ff:ff"} {
		if _, err := Parse(text); err != nil {
			t.Fatalf("Ethernet selector %q: %v", text, err)
		}
		if _, err := ParseClient(text); err == nil {
			t.Fatalf("accepted client identity %q", text)
		}
	}
	for _, text := range []string{"", "invalid", "02:00:00:00:00", "02:00:00:00:00:00:00:01", "02:00:00:00:00:gg"} {
		if _, err := Parse(text); err == nil {
			t.Fatalf("accepted invalid Ethernet address %q", text)
		}
	}
}
