// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy/fq"
)

func TestUDPOwnershipHandoffAtMemoryLimit(t *testing.T) {
	budget := membuffer.NewBudget(8)
	packet, ok := copyUDPPacket([]byte("packet"), budget)
	if !ok {
		t.Fatal("packet allocation failed")
	}
	defer packet.release()
	packet.deadline = time.Now().Add(time.Minute)
	deadline, address := packet.deadline, &packet.data[0]
	forwarded := make(chan bool, 1)
	tasks := newUdpTaskPool(func(work udpPacketWork, _ *udpWriteSlot, data []byte) {
		forwarded <- work.packet.owned && &data[0] == address && work.deadline.Equal(deadline)
	})
	tasks.memory = budget
	t.Cleanup(tasks.close)
	owner := &ControlPlane{udpTaskPool: tasks}
	endpoints := new(UdpEndpointPool)
	t.Cleanup(endpoints.closeAll)
	src, dst := netip.MustParseAddrPort("192.0.2.1:5000"), netip.MustParseAddrPort("198.51.100.1:443")
	endpoint := &UdpEndpoint{NatTimeout: time.Minute}
	endpoint.setupOwner.Store(owner)
	endpoints.add(src, endpoint)
	current := &ControlPlane{udpEndpoints: endpoints}
	if err := current.handleUDPPacket(t.Context(), new(udpWriteSlot), &packet, src, dst, nil); err != nil {
		t.Fatal(err)
	}
	if packet.data != nil || packet.owned {
		t.Fatal("old generation retained packet ownership")
	}
	select {
	case correct := <-forwarded:
		if !correct {
			t.Fatal("handoff copied the packet or lost its deadline")
		}
	case <-time.After(time.Second):
		t.Fatal("handoff tried to allocate a second packet at the memory limit")
	}
	tasks.close()
	if state := budget.Status(); state.Used != 0 || state.Peak != 8 || state.Denied != 0 {
		t.Fatalf("handoff budget: %+v", state)
	}
}

func TestUDPSetupBorrowsOwnedPacket(t *testing.T) {
	budget := membuffer.NewBudget(8)
	packet, ok := copyUDPPacket([]byte("packet"), budget)
	if !ok {
		t.Fatal("packet allocation failed")
	}
	defer packet.release()
	packet.deadline = time.Now().Add(time.Minute)
	address, deadline := &packet.data[0], packet.deadline
	pending := &udpSetup{sniffer: sniffing.NewPacketSniffer(nil)}
	endpoint := &UdpEndpoint{pending: pending}
	t.Cleanup(func() { _ = endpoint.Close() })
	if !pending.appendPacket(&packet) {
		t.Fatal("setup rejected owned packet")
	}
	if packet.data != nil || &pending.packets[0].data[0] != address || &pending.sniffer.Data()[1][0] != address || !pending.packets[0].deadline.Equal(deadline) {
		t.Fatal("sniffing did not borrow the original packet")
	}
	_, _, _ = pending.sniffer.SniffUdp()
	if err := endpoint.Close(); err != nil {
		t.Fatal(err)
	}
	if state := budget.Status(); state.Used != 0 || state.Peak != 8 {
		t.Fatalf("setup budget: %+v", state)
	}
}

func TestUDPWorkerTransfersPacketToMITM(t *testing.T) {
	budget := membuffer.NewBudget(8)
	src, dst := netip.MustParseAddrPort("192.0.2.1:5000"), netip.MustParseAddrPort("198.51.100.1:443")
	ingress, server := newMITMPacketPair(src, dst, nil)
	ingress.(*mitmPacketConn).pair.memory = budget
	t.Cleanup(func() { _ = ingress.Close() })
	resources := netproxy.NewPacketBudget(1)
	wrapped, err := resources.Open(t.Context(), "", func(_ context.Context, _ string) (net.PacketConn, error) { return ingress, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })
	endpoint := &UdpEndpoint{conn: wrapped, mitm: true, firstDst: dst}
	plane := &ControlPlane{udpEndpoints: new(UdpEndpointPool)}
	result := make(chan error, 1)
	deadline := time.Now().Add(time.Minute)
	tasks := newUdpTaskPool(func(work udpPacketWork, slot *udpWriteSlot, data []byte) {
		address := &data[0]
		err := plane.writeUDPPacket(t.Context(), slot, endpoint, src, dst, work.packet)
		queued := &server.(*mitmPacketConn).packets[0]
		if err == nil && (work.packet.data != nil || len(queued.data) == 0 || &queued.data[0] != address || !queued.deadline.Equal(deadline)) {
			err = errors.New("bridge copied the packet or lost ownership metadata")
		}
		result <- err
	})
	tasks.memory = budget
	t.Cleanup(tasks.close)
	if !tasks.emit([]byte("packet"), udpPacketWork{src: src, deadline: deadline}) {
		t.Fatal("ingress packet rejected")
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	tasks.close()
	if state := budget.Status(); state.Used != 8 || state.Peak != 8 || state.Denied != 0 {
		t.Fatalf("bridge budget: %+v", state)
	}
	buf := make([]byte, 3)
	if n, _, err := server.ReadFrom(buf); err != nil || string(buf[:n]) != "pac" {
		t.Fatalf("truncated read: %q, %v", buf[:n], err)
	}
	if got := budget.Status().Used; got != 0 {
		t.Fatalf("read retained %d bytes", got)
	}
}

func TestMITMBridgeDropsExpiredOwnedPackets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src, dst := netip.MustParseAddrPort("192.0.2.1:5000"), netip.MustParseAddrPort("198.51.100.1:443")
		ingress, server := newMITMPacketPair(src, dst, nil)
		defer ingress.Close()
		budget := membuffer.NewBudget(16)
		ingress.(*mitmPacketConn).pair.memory = budget
		for i, data := range []string{"expired", "fresh"} {
			packet := udpPacket{data: []byte(data), deadline: time.Now().Add(time.Duration(1+i*10) * time.Second)}
			if _, err := ingress.(*mitmPacketConn).writePacket(&packet, server.LocalAddr()); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(2 * time.Second)
		before := dropExpired.Load()
		buf := make([]byte, 16)
		n, _, err := server.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "fresh" || dropExpired.Load()-before != 1 {
			t.Fatalf("bridge expiry: %q, %v, drops=%d", buf[:n], err, dropExpired.Load()-before)
		}
		if got := budget.Status().Used; got != 0 {
			t.Fatalf("bridge retained %d bytes", got)
		}
	})
}

func TestUDPOwnedPacketRejectionKeepsOwner(t *testing.T) {
	budget := membuffer.NewBudget(8)
	packet, ok := copyUDPPacket([]byte("packet"), budget)
	if !ok {
		t.Fatal("packet allocation failed")
	}
	defer packet.release()
	address := &packet.data[0]
	tasks := newUdpTaskPool(func(udpPacketWork, *udpWriteSlot, []byte) { t.Error("closed pool executed a packet") })
	tasks.close()
	if tasks.emitPacket(&packet, udpPacketWork{src: testUdpKey(1)}) || !packet.owned || &packet.data[0] != address {
		t.Fatal("rejected handoff consumed the packet")
	}
	src, dst := netip.MustParseAddrPort("192.0.2.1:5000"), netip.MustParseAddrPort("198.51.100.1:443")
	ingress, server := newMITMPacketPair(src, dst, nil)
	_ = ingress.Close()
	if _, err := ingress.(*mitmPacketConn).writePacket(&packet, server.LocalAddr()); !errors.Is(err, net.ErrClosed) || !packet.owned || &packet.data[0] != address {
		t.Fatalf("closed bridge consumed packet: %v", err)
	}
	packet.release()
	if got := budget.Status().Used; got != 0 {
		t.Fatalf("rejected packet retained %d bytes", got)
	}
}

func TestUDPReplayDeadlineCountsRemainingPackets(t *testing.T) {
	pending := &udpSetup{sniffer: sniffing.NewPacketSniffer(nil)}
	defer pending.close()
	for range 3 {
		if !pending.appendPacket(&udpPacket{data: []byte("packet"), deadline: time.Now().Add(time.Minute)}) {
			t.Fatal("packet budget exhausted")
		}
	}
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	before := dropExpired.Load()
	plane := new(ControlPlane)
	if err := plane.replayUDP(ctx, nil, new(UdpEndpoint), netip.AddrPort{}, pending); err != nil {
		t.Fatal(err)
	}
	if got := dropExpired.Load() - before; got != 3 {
		t.Fatalf("expired replay counted %d packets, want 3", got)
	}
}

func TestUDPIngressAndCarrierShareMemoryBudget(t *testing.T) {
	if udpPacketMemory != netproxy.DatagramMemory {
		t.Fatal("ingress and carrier use different budgets")
	}
	limit := udpPacketMemory.UseLimit(2048)
	defer limit.Close()
	packet, ok := copyUDPPacket(make([]byte, 1024), udpPacketMemory)
	if !ok {
		t.Fatal("ingress allocation failed")
	}
	defer packet.release()
	s := new(fq.Scheduler)
	defer s.Clear()
	if !s.Force(new(fq.Flow), time.Now(), make([]byte, 1024)) {
		t.Fatal("carrier admission failed")
	}
	if s.Force(new(fq.Flow), time.Now(), make([]byte, 1)) {
		t.Fatal("carrier ignored ingress allocation")
	}
	packet.release()
	if !s.Offer(new(fq.Flow), time.Now(), make([]byte, 1024)) {
		t.Fatal("ingress release did not return carrier capacity")
	}
	s.Clear()
	if used := udpPacketMemory.Status().Used; used != 0 {
		t.Fatalf("shared budget retained %d bytes", used)
	}
}
