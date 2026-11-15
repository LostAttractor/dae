// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
)

func TestQueuedDNSMustChecksEndpointSource(t *testing.T) {
	macA, macB := [6]byte{2, 0, 0, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 2}
	local := bpfUdpBinding{SourceOrigin: uint8(plugin.SourceLocal), RouteEpoch: 3, Mac: macA}
	lan := bpfUdpBinding{SourceOrigin: uint8(plugin.SourceLAN), RouteEpoch: 3, Mac: macA}
	for _, test := range []struct {
		name    string
		binding bpfUdpBinding
		origin  plugin.SourceOrigin
		mac     [6]byte
		epoch   uint64
		must    uint8
		writes  int
	}{
		{"LAN into local", local, plugin.SourceLAN, macA, 3, 1, 0},
		{"local into LAN", lan, plugin.SourceLocal, macA, 3, 1, 0},
		{"different LAN MAC", lan, plugin.SourceLAN, macB, 3, 1, 0},
		{"old epoch", lan, plugin.SourceLAN, macA, 2, 1, 0},
		{"unknown", bpfUdpBinding{}, plugin.SourceUnknown, [6]byte{}, 0, 1, 0},
		{"same LAN", lan, plugin.SourceLAN, macA, 3, 1, 1},
		{"local changed interface MAC", local, plugin.SourceLocal, macB, 3, 1, 1},
		{"ordinary DNS is independent", local, plugin.SourceLAN, macA, 3, 0, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			src, dst := netip.MustParseAddrPort("192.0.2.1:12345"), netip.MustParseAddrPort("192.0.2.53:53")
			p := new(UdpEndpointPool)
			defer p.closeAll()
			c := &ControlPlane{ctx: t.Context(), udpEndpoints: p, udpTaskPool: &udpTaskPool{ctx: t.Context()}}
			identity := &routingResult{SourceOrigin: uint8(test.origin), Mac: test.mac, RouteEpoch: test.epoch, Must: test.must}
			work := udpPacketWork{plane: c, src: src, dst: dst, routingResult: identity, deadline: time.Now().Add(time.Second)}
			// Another source creates the endpoint after queueing; execution must recheck its identity.
			conn := &udpLifecyclePacket{testPacketConn: newTestPacketConn(false), writes: make(chan netip.AddrPort, 1)}
			ue := &UdpEndpoint{conn: conn, binding: test.binding, firstDst: dst, NatTimeout: time.Hour}
			if !p.addLocked(src, ue) {
				t.Fatal("publish endpoint")
			}
			work.executeData(nil, []byte("queued DNS"))
			if len(conn.writes) != test.writes {
				t.Fatalf("upstream writes=%d, want %d", len(conn.writes), test.writes)
			}
		})
	}
}

func TestDNSMustOwnerTransferKeepsIdentity(t *testing.T) {
	src, dst := netip.MustParseAddrPort("192.0.2.1:12345"), netip.MustParseAddrPort("192.0.2.53:53")
	identity := &routingResult{SourceOrigin: uint8(plugin.SourceLAN), Mac: [6]byte{2, 0, 0, 0, 0, 1}, Must: 1}
	transferred := make(chan *routingResult, 1)
	owner := &ControlPlane{udpTaskPool: newUdpTaskPool(func(work udpPacketWork, _ *udpWriteSlot, _ []byte) {
		transferred <- work.routingResult
	})}
	defer owner.udpTaskPool.close()
	p := new(UdpEndpointPool)
	defer p.closeAll()
	ue := &UdpEndpoint{binding: bpfUdpBinding{SourceOrigin: identity.SourceOrigin, Mac: identity.Mac}, NatTimeout: time.Hour}
	ue.setupOwner.Store(owner)
	if !p.addLocked(src, ue) {
		t.Fatal("publish pending endpoint")
	}
	c := &ControlPlane{udpEndpoints: p}
	if err := c.handlePkt(t.Context(), []byte("DNS must"), src, dst, identity); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-transferred:
		if got != identity {
			t.Fatalf("owner transfer lost source identity: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("packet was not transferred to setup owner")
	}
}
