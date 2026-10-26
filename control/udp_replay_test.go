// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
)

func TestUDPGenerationHandoffKeepsDeadline(t *testing.T) {
	deadline := time.Now().Add(time.Second)
	forwarded := make(chan udpPacketWork, 1)
	tasks := newUdpTaskPool(func(work udpPacketWork, _ *udpWriteSlot, _ []byte) { forwarded <- work })
	t.Cleanup(tasks.close)
	owner := &ControlPlane{udpTaskPool: tasks}
	endpoints := new(UdpEndpointPool)
	t.Cleanup(endpoints.closeAll)
	src, dst := netip.MustParseAddrPort("192.0.2.1:5000"), netip.MustParseAddrPort("198.51.100.1:443")
	endpoint := &UdpEndpoint{NatTimeout: time.Minute}
	endpoint.setupOwner.Store(owner)
	endpoints.add(src, endpoint)
	current := &ControlPlane{udpEndpoints: endpoints}
	if err := current.handlePktUntil(t.Context(), deadline, nil, []byte("packet"), src, dst, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case work := <-forwarded:
		if work.plane != owner || !work.deadline.Equal(deadline) {
			t.Fatalf("handoff = %+v, want original deadline %v", work, deadline)
		}
	case <-time.After(time.Second):
		t.Fatal("packet was not handed to its setup owner")
	}
}

type replayPacketConn struct {
	*deadlineRecordingPacketConn
	packets []string
}

func (c *replayPacketConn) WriteTo(data []byte, _ net.Addr) (int, error) {
	c.packets = append(c.packets, string(data))
	return len(data), nil
}

func TestUDPReplayKeepsEachDeadline(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "expiry", true: "cancellation"}[canceled], func(t *testing.T) {
			conn := &replayPacketConn{deadlineRecordingPacketConn: &deadlineRecordingPacketConn{testPacketConn: newTestPacketConn(false)}}
			t.Cleanup(func() { _ = conn.Close() })
			pending := &udpSetup{sniffer: sniffing.NewPacketSniffer(nil)}
			t.Cleanup(pending.close)
			deadlines := []time.Time{time.Now().Add(-time.Second), time.Now().Add(time.Second), time.Now().Add(2 * time.Second)}
			for i, packet := range []string{"expired", "first", "second"} {
				if !pending.appendPacket(&udpPacket{data: []byte(packet), deadline: deadlines[i]}) {
					t.Fatal("packet budget exhausted")
				}
			}
			endpoint := &UdpEndpoint{conn: conn, firstDst: netip.MustParseAddrPort("198.51.100.1:443")}
			plane := &ControlPlane{udpEndpoints: new(UdpEndpointPool)}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if canceled {
				cancel()
			}
			before := dropExpired.Load()
			err := plane.replayUDP(ctx, nil, endpoint, netip.MustParseAddrPort("192.0.2.1:5000"), pending)
			if canceled {
				if !errors.Is(err, context.Canceled) || len(conn.packets) != 0 || dropExpired.Load() != before {
					t.Fatalf("canceled replay: err=%v packets=%v drops=%d", err, conn.packets, dropExpired.Load()-before)
				}
				return
			}
			if err != nil || !slices.Equal(conn.packets, []string{"first", "second"}) {
				t.Fatalf("replay: err=%v packets=%v", err, conn.packets)
			}
			if want := []time.Time{deadlines[1], {}, deadlines[2], {}}; !slices.Equal(conn.deadlines, want) {
				t.Fatalf("deadlines = %v, want %v", conn.deadlines, want)
			}
			if got := dropExpired.Load() - before; got != 1 {
				t.Fatalf("expired drops = %d, want 1", got)
			}
		})
	}
}
