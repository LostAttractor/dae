//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"net"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRedirectTrackKeepsUnchangedEntry(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	packet := bridgePacket(netip.MustParseAddrPort("192.168.1.2:40000"), netip.MustParseAddrPort("203.0.113.1:443"), unix.IPPROTO_TCP, net.HardwareAddr{2, 0, 0, 0, 0, 2}, 0x10)
	if status, _, _, err := runBpfProgram(obj.TestRedirectTrackUnchanged, packet, make([]byte, 256)); err != nil || status != 0 {
		t.Fatalf("redirect_track failed at step %d: %v", status, err)
	}
}
